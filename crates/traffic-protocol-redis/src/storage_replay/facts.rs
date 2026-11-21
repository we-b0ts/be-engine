//! Redis storage locations and effects projected from native messages.
use bytes::Bytes;
use traffic_protocol::{
    connection::Endpoint,
    message::{ProjectedMessage, ProtocolMessage},
};

use super::{Mutation, Position, ScopeHistory, Stamp};
use crate::message::RequestMessage;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Location {
    Endpoint,
    Database(i64),
    Key(i64, Bytes),
    String(i64, Bytes),
    Hash(i64, Bytes),
    Field(i64, Bytes, Bytes),
}

impl Location {
    pub fn value(database: i64, position: Position<'_>) -> Self {
        match position.field {
            Some(field) => Self::Field(database, position.key.clone(), field.clone()),
            None => Self::String(database, position.key.clone()),
        }
    }

    pub(super) fn related(&self) -> impl Iterator<Item = Self> {
        let (db, key, hash) = match self {
            Self::String(db, key) => (*db, key, None),
            Self::Field(db, key, _) => (*db, key, Some(Self::Hash(*db, key.clone()))),
            _ => unreachable!("related locations require a Redis value slot"),
        };
        [
            Some(self.clone()),
            hash,
            Some(Self::Key(db, key.clone())),
            Some(Self::Database(db)),
            Some(Self::Endpoint),
        ]
        .into_iter()
        .flatten()
    }
}

pub fn request(message: &dyn ProtocolMessage) -> Option<&RequestMessage> {
    message.as_any()?.downcast_ref()
}

pub struct WriteEffect {
    pub location: Location,
    pub argument: Option<usize>,
    pub value: Option<Bytes>,
}

pub struct SourceFacts {
    pub effects: Vec<WriteEffect>,
    pub read_has_values: bool,
}

pub fn source_facts(request: &RequestMessage, response: &ProjectedMessage) -> SourceFacts {
    let read = request.storage_read();
    let mutation = if read {
        request.storage_absence(response)
    } else {
        request.storage_mutation(response)
    };
    SourceFacts {
        effects: effects(request.database, mutation),
        read_has_values: read && !response.values.is_empty(),
    }
}

pub fn delivered_writes(
    source: &RequestMessage,
    target: &RequestMessage,
    response: &ProjectedMessage,
    retain_values: bool,
) -> Vec<WriteEffect> {
    let mut writes = effects(target.database, target.storage_mutation(response));
    if retain_values {
        for effect in &mut writes {
            if let Some(argument) = effect.argument
                && source.args.get(argument) != target.args.get(argument)
            {
                effect.value = target.args.get(argument).cloned();
            }
        }
    }
    writes
}

fn effects(db: i64, mutation: Mutation<'_>) -> Vec<WriteEffect> {
    let mut effects = Vec::new();
    let mut push = |location, argument| {
        effects.push(WriteEffect {
            location,
            argument,
            value: None,
        })
    };
    match mutation {
        Mutation::None => (),
        Mutation::Write(slots) => {
            if let Some(first) = slots.first().filter(|slot| slot.position.field.is_some()) {
                push(Location::String(db, first.position.key.clone()), None);
            }
            for slot in slots {
                let position = slot.position;
                if position.field.is_none() {
                    push(Location::Hash(db, position.key.clone()), None);
                }
                push(Location::value(db, position), Some(slot.argument));
            }
        }
        Mutation::Slots(slots) => {
            for slot in slots {
                push(Location::value(db, slot), None);
            }
        }
        Mutation::Keys(keys) => {
            for key in keys {
                push(Location::Key(db, key.clone()), None);
            }
        }
        Mutation::Database => push(Location::Database(db), None),
        Mutation::Endpoint => push(Location::Endpoint, None),
    }
    effects
}

pub struct ReadLink {
    pub path: String,
    pub writer: usize,
    pub argument: usize,
    pub target: Location,
}

pub struct ReadQuery<'a> {
    pub endpoint: &'a Endpoint,
    pub stamp: Stamp,
    pub source: &'a RequestMessage,
    pub target: &'a RequestMessage,
    pub response: &'a ProjectedMessage,
}

impl ScopeHistory {
    pub fn read_links<'a>(
        &self,
        run: &Self,
        query: ReadQuery<'_>,
        mut source_write: impl FnMut(usize) -> Option<&'a RequestMessage>,
    ) -> Vec<ReadLink> {
        let ReadQuery {
            endpoint,
            stamp,
            source,
            target,
            response,
        } = query;
        let target_slots =
            (source.args != target.args).then(|| target.storage_read_slots(response));
        source
            .storage_read_slots(response)
            .into_iter()
            .enumerate()
            .filter_map(|(slot_index, slot)| {
                let bytes = slot.value?;
                let location = Location::value(source.database, slot.position);
                let writer = self.writer(run, endpoint, stamp, &location)?;
                let argument = writer.argument?;
                let writer_index = writer.stamp.index;
                let write = source_write(writer_index)?;
                if write.username != source.username || write.args.get(argument)? != bytes {
                    return None;
                }
                let target = match &target_slots {
                    Some(slots) => {
                        Location::value(target.database, slots.get(slot_index)?.position)
                    }
                    None => location,
                };
                Some(ReadLink {
                    path: slot.path,
                    writer: writer_index,
                    argument,
                    target,
                })
            })
            .collect()
    }
}
