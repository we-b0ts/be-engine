use super::*;
use crate::interaction::replay::timing::{Advance, InputTiming};
use futures_util::future::BoxFuture;
use std::sync::Arc;
use tokio::sync::watch;

struct CloseInput {
    prefix: watch::Receiver<bool>,
    peer_closed: watch::Receiver<bool>,
}

impl InputTiming for CloseInput {
    fn wait(&self, sequence: u64, completed: Vec<u64>) -> BoxFuture<'_, Result<Advance>> {
        Box::pin(async move {
            assert_eq!(sequence, 1);
            assert!(completed.is_empty());
            let mut prefix = self.prefix.clone();
            prefix.wait_for(|ready| *ready).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(Advance::default())
        })
    }
    fn closed(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            // This only completes when the genuine peer observes cancellation.
            // Calling feedback before resetting the primary socket deadlocks.
            let mut observed = self.peer_closed.clone();
            observed.wait_for(|closed| *closed).await.unwrap();
            Ok(())
        })
    }
}

#[tokio::test]
async fn shared_input_close_resets_real_primary_transport_before_acknowledgement() {
    tokio::time::timeout(Duration::from_secs(2),async {
        let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address=listener.local_addr().unwrap();
        let (prefix,ready)=watch::channel(false);
        let (closed,observed)=watch::channel(false);
        let server=tokio::spawn(async move {
            let (mut socket,_)=listener.accept().await.unwrap();read_request_head(&mut socket).await;
            let message="data: before\n\n";
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{message}\r\n",message.len()).as_bytes()).await.unwrap();
            prefix.send_replace(true);
            let mut b=[0];match socket.read(&mut b).await {
                Ok(0)|Err(_)=>{closed.send_replace(true);},
                result=>panic!("expected primary client cancellation, got {result:?}"),
            }
        });
        let mut input=InputTranscript::new(Protocol::Sse,InteractionPolicy {
            request_timeout_ms:900000,max_duration_ms:900000,stream_terminal:None,..policy()
        });
        input.actions.push(close_action(100424));
        let request=Request::builder().uri(format!("http://{address}/events"))
            .body(Full::new(Bytes::new())).unwrap();
        let client=Client::builder(TokioExecutor::new()).build_http();
        let started=Instant::now();
        let response=execute_with_feedback(&client,request,&input,Duration::from_secs(1),100000,
            crate::interaction::replay::Feedback {input_timing:Some(Arc::new(CloseInput {prefix:ready,peer_closed:observed})),..Default::default()})
            .await.unwrap();
        assert!(started.elapsed()<Duration::from_secs(1));
        assert_eq!(response.observation.end.reason,EndReason::ClientClose);
        assert!(response.observation.end.clean);
        assert!(response.body.starts_with(b"data: before"));
        server.await.unwrap();
    }).await.unwrap();
}
