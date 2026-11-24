//! Redis request admission and server emissions share one ordered RESP writer.
use std::sync::Mutex;

use anyhow::Context;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::{
        mpsc::{self, error::TryRecvError},
        oneshot,
    },
};
use traffic_protocol::connection::{
    ConnectionIo, MessageBatchFramer, NativeFuture, OutputIo, RequestHost, ResponseDelivery,
    ResponseFramer,
};

use super::{
    subscription::{Confirmation, Subscriptions},
    *,
};
use crate::{RedisCommand, pubsub::frame};

pub(super) struct Server {
    pub limit: usize,
}

#[derive(Clone)]
struct Metadata {
    version: u8,
    database: i64,
    username: Option<String>,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            version: 2,
            database: 0,
            username: None,
        }
    }
}

#[derive(Default)]
struct Session {
    metadata: Metadata,
    subscriptions: Subscriptions<ProtocolRef>,
}

enum Reply {
    Local(Bytes, Metadata),
    Recorded(Box<dyn ResponseDelivery>),
}

struct Pending {
    command: RedisCommand,
    reply: Reply,
    written: oneshot::Sender<()>,
}

struct Emission {
    delivery: Box<dyn ResponseDelivery>,
    anchors: Vec<ProtocolRef>,
    after: Option<ProtocolRef>,
}

impl ServerSession for Server {
    fn run(
        self: Box<Self>,
        io: Box<dyn ConnectionIo>,
        host: Arc<dyn RequestHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            let session = Mutex::new(Session::default());
            let (reader, mut writer) = tokio::io::split(io);
            let (tx, rx) = mpsc::channel(1);
            tokio::try_join!(
                admit(
                    crate::BufferedReader::new(reader, self.limit),
                    &*host,
                    &session,
                    tx
                ),
                deliver(&mut writer, &*host, &session, rx),
            )?;
            Ok(())
        })
    }
}

async fn admit(
    mut reader: crate::BufferedReader<impl AsyncRead + Unpin>,
    host: &dyn RequestHost,
    session: &Mutex<Session>,
    tx: mpsc::Sender<Pending>,
) -> Result<()> {
    loop {
        // Idle listeners have no input reservation. Once bytes arrive, retain
        // ownership through parsing and delivery of this request.
        if reader.buffer.is_empty() {
            let mut first = [0];
            if reader.inner.read(&mut first).await? == 0 {
                return Ok(());
            }
            reader.buffer.extend_from_slice(&first);
        }
        let _input = host.begin_input().await?;
        let frame = crate::read_frame(&mut reader)
            .await?
            .context("Redis input closed during a frame")?;
        let command = crate::redis_command(&frame.raw)?;
        ensure!(
            !crate::builtins::redis_is_unsupported(&command),
            "Redis command mode is unavailable in native serving"
        );
        let (mut metadata, anchor) = {
            let session = session.lock().expect("Redis session");
            (
                session.metadata.clone(),
                session.subscriptions.anchors().into_iter().next(),
            )
        };
        ensure!(
            metadata.version == 2,
            "Redis native serving currently requires RESP2"
        );
        let local = if anchor.is_none() || command.name == "QUIT" {
            crate::builtins::redis_builtin(
                &command,
                &mut metadata.version,
                &mut metadata.database,
                &mut metadata.username,
            )
        } else {
            None
        };
        let reply = if let Some(response) = local {
            Reply::Local(response.into(), metadata)
        } else {
            let request = Arc::new(RequestMessage {
                command: command.name.clone(),
                args: command.args.iter().cloned().map(Bytes::from).collect(),
                resp_version: metadata.version,
                database: metadata.database,
                username: metadata.username,
            });
            let delivery = if anchor.is_some() || crate::is_pubsub_command(&command.name) {
                host.execute_bound(request, anchor).await?
            } else {
                host.execute(request).await?
            };
            Reply::Recorded(delivery)
        };
        let quit = command.name == "QUIT";
        let (written, delivered) = oneshot::channel();
        tx.send(Pending {
            command,
            reply,
            written,
        })
        .await
        .map_err(|_| anyhow::anyhow!("Redis writer closed"))?;
        delivered
            .await
            .context("Redis writer stopped before completing a reply")?;
        if quit {
            return Ok(());
        }
    }
}

async fn deliver(
    writer: &mut dyn OutputIo,
    host: &dyn RequestHost,
    session: &Mutex<Session>,
    mut rx: mpsc::Receiver<Pending>,
) -> Result<()> {
    let mut reply: Option<Pending> = None;
    let mut emission: Option<Emission> = None;
    loop {
        let anchors = session
            .lock()
            .expect("Redis session")
            .subscriptions
            .anchors();
        if reply.is_none()
            && emission.is_none()
            && !anchors.is_empty()
            && host.event_session()
            && writer.is_write_vectored()
        {
            // Retain the normal writer's priority for a queued command.
            match rx.try_recv() {
                Ok(next) => reply = Some(next),
                Err(TryRecvError::Disconnected) => return Ok(()),
                Err(TryRecvError::Empty) => {
                    if host
                        .try_write_message_batch(&anchors, writer, &mut BatchPushFramer(session))
                        .await?
                    {
                        continue;
                    }
                }
            }
        }
        tokio::select! {
            biased;
            next = rx.recv(), if reply.is_none() => {
                let Some(next) = next else { return Ok(()); };
                reply = Some(next);
            }
            ready = async { emission.as_mut().expect("queued emission").delivery.ready().await }, if emission.is_some() => {
                ready?;
                let Emission { delivery, anchors, after } = emission.take().expect("ready emission");
                delivery.write(writer, &mut PushFramer { session, anchors: &anchors, after: after.as_ref() }).await?;
            }
            delivery = host.next_message(anchors.clone()), if emission.is_none() && !anchors.is_empty() => {
                let delivery = delivery?;
                let after = delivery.reference().as_ref().map(super::notification::anchor).transpose()?.flatten();
                emission = Some(Emission { delivery, anchors, after });
            }
            ready = async {
                match &mut reply.as_mut().expect("queued reply").reply {
                    Reply::Recorded(delivery) => delivery.ready().await,
                    Reply::Local(..) => Ok(()),
                }
            }, if reply.is_some() => {
                ready?;
                let Pending { command, reply: output, written } = reply.take().expect("ready reply");
                let quit = command.name == "QUIT";
                match output {
                    Reply::Local(bytes, metadata) => {
                        writer.write_all(&bytes).await?;
                        writer.flush().await?;
                        session.lock().expect("Redis session").metadata = metadata;
                    }
                    Reply::Recorded(delivery) => write_reply(writer, host, session, command, delivery).await?,
                }
                if emission.as_ref().is_some_and(|message| {
                    let session = session.lock().expect("Redis session");
                    !session.subscriptions.anchors().iter().any(|anchor| {
                        message.after.as_ref().map_or_else(|| message.anchors.contains(anchor), |after| after == anchor)
                    })
                }) {
                    emission = None;
                }
                let _ = written.send(());
                if quit {
                    return Ok(());
                }
            }
        }
    }
}

async fn write_reply(
    writer: &mut dyn OutputIo,
    host: &dyn RequestHost,
    session: &Mutex<Session>,
    command: RedisCommand,
    mut delivery: Box<dyn ResponseDelivery>,
) -> Result<()> {
    let offer_anchor = matches!(
        command.name.as_str(),
        "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE"
    );
    let reference = if offer_anchor {
        delivery.retain_as_anchor();
        Some(
            delivery
                .reference()
                .context("Redis subscription reply has no Source reference")?,
        )
    } else {
        None
    };
    let mut framer = ReplyFramer {
        session,
        command,
        confirmation: None,
        reset: false,
    };
    delivery.write(writer, &mut framer).await?;

    let mut session = session.lock().expect("Redis session");
    let previous = session.subscriptions.anchors();
    if let Some(confirmation) = framer.confirmation {
        session
            .subscriptions
            .apply(confirmation, reference.clone())?;
    }
    if framer.reset {
        *session = Session::default();
    }
    let active = session.subscriptions.anchors();
    for anchor in previous.iter().chain(reference.as_ref()) {
        if !active.contains(anchor) {
            host.forget_anchor(anchor);
        }
    }
    if active.is_empty() {
        host.release_session();
    }
    Ok(())
}

struct ReplyFramer<'a> {
    session: &'a Mutex<Session>,
    command: RedisCommand,
    confirmation: Option<Confirmation>,
    reset: bool,
}

impl ResponseFramer for ReplyFramer<'_> {
    fn frame(&mut self, bytes: Bytes) -> Result<Bytes> {
        self.reset = self.command.name == "RESET" && bytes == b"+RESET\r\n".as_slice();
        self.confirmation = self
            .session
            .lock()
            .expect("Redis session")
            .subscriptions
            .confirmation(&self.command, &bytes, true)?;
        Ok(self
            .confirmation
            .as_ref()
            .map_or(bytes, |confirmation| confirmation.output.clone()))
    }
}

struct PushFramer<'a> {
    session: &'a Mutex<Session>,
    anchors: &'a [ProtocolRef],
    after: Option<&'a ProtocolRef>,
}

impl ResponseFramer for PushFramer<'_> {
    fn frame(&mut self, bytes: Bytes) -> Result<Bytes> {
        frame_push(self.session, bytes, |anchor| {
            self.after
                .map_or_else(|| self.anchors.contains(anchor), |after| after == anchor)
        })
    }
}

struct BatchPushFramer<'a>(&'a Mutex<Session>);

impl MessageBatchFramer for BatchPushFramer<'_> {
    fn frame_message(&mut self, anchor: &ProtocolRef, bytes: Bytes) -> Result<Bytes> {
        frame_push(self.0, bytes, |active| anchor == active)
    }
}

fn frame_push(
    session: &Mutex<Session>,
    bytes: Bytes,
    accepts_anchor: impl FnOnce(&ProtocolRef) -> bool,
) -> Result<Bytes> {
    let push = frame::decode(&bytes)?.context("Redis delivery has no notification frame")?;
    let session = session.lock().expect("Redis session");
    let subscription = session
        .subscriptions
        .get(push.kind, &push.subject)
        .context("Redis notification subject has no active subscription")?;
    ensure!(
        accepts_anchor(&subscription.anchor),
        "Redis notification subscription generation changed"
    );
    if subscription.target.as_slice() == push.subject.as_ref() {
        return Ok(bytes);
    }
    crate::subject::translate_frame(&push, &subscription.target).map(Bytes::from)
}
