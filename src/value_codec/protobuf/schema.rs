//! Bounded reuse of pure, validated wire bindings. No decoded payload or
//! comparison decision belongs in this cache.
use std::{cell::RefCell, collections::VecDeque, sync::Arc};

use anyhow::Result;
use serde_json::Value;

use super::{Binding, Budget, Document, bindings, decode_message};
use crate::policy::ProtobufCodec;

const MAX_SCHEMAS: usize = 32;

#[derive(Debug)]
pub(in crate::value_codec) struct Schema {
    binding: Binding,
}

// Decode is synchronous. Each runtime thread reuses its own small immutable
// schema set without contending with other active protocol clients.
thread_local! {
    static SCHEMAS: RefCell<VecDeque<(ProtobufCodec, Arc<Schema>)>> = const {
        RefCell::new(VecDeque::new())
    };
}

pub(in crate::value_codec) fn schema(codec: &ProtobufCodec) -> Result<Arc<Schema>> {
    if let Some(schema) = SCHEMAS.with(|schemas| {
        schemas
            .borrow()
            .iter()
            .find(|(key, _)| key == codec)
            .map(|(_, schema)| schema.clone())
    }) {
        return Ok(schema);
    }
    let schema = Arc::new(Schema {
        binding: bindings(codec)?,
    });
    SCHEMAS.with(|schemas| {
        let mut schemas = schemas.borrow_mut();
        if schemas.len() == MAX_SCHEMAS {
            schemas.pop_front();
        }
        schemas.push_back((codec.clone(), schema.clone()));
    });
    Ok(schema)
}

impl Schema {
    pub(in crate::value_codec) fn decode(&self, bytes: &[u8]) -> Result<(Document, Value)> {
        let (message, logical) = decode_message(
            bytes,
            &self.binding,
            &[],
            &[],
            None,
            &mut Budget::default(),
            0,
        )?;
        Ok((Document { message }, logical))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ProtobufField, ProtobufType};
    use std::collections::BTreeMap;

    fn codec(alias: &str, kind: ProtobufType) -> ProtobufCodec {
        ProtobufCodec {
            fields: BTreeMap::from([(
                alias.into(),
                ProtobufField {
                    field_path: vec![1],
                    field_type: kind,
                    repeated: false,
                },
            )]),
        }
    }

    #[test]
    fn schema_reuse_is_bounded_and_keys_include_every_typed_binding() {
        SCHEMAS.with(|schemas| schemas.borrow_mut().clear());
        let original = codec("/value", ProtobufType::Uint64);
        let first = schema(&original).unwrap();
        assert!(Arc::ptr_eq(&first, &schema(&original).unwrap()));
        let boolean = schema(&codec("/value", ProtobufType::Bool)).unwrap();
        assert!(!Arc::ptr_eq(&first, &boolean));
        assert!(first.decode(&[8, 2]).is_ok());
        assert!(boolean.decode(&[8, 2]).is_err());
        let mut repeated = original.clone();
        repeated.fields.get_mut("/value").unwrap().repeated = true;
        let repeated = schema(&repeated).unwrap();
        assert!(repeated.decode(&[8, 1, 8, 2]).is_ok());
        assert!(first.decode(&[8, 1, 8, 2]).is_err());
        for index in 0..MAX_SCHEMAS + 1 {
            let _ = schema(&codec(&format!("/value{index}"), ProtobufType::Uint64)).unwrap();
        }
        assert_eq!(SCHEMAS.with(|schemas| schemas.borrow().len()), MAX_SCHEMAS);
        // Eviction cannot invalidate a retained immutable plan.
        assert_eq!(first.decode(&[8, 3]).unwrap().1["value"], 3);
        let mut invalid = original;
        invalid.fields.get_mut("/value").unwrap().field_path.clear();
        assert!(schema(&invalid).is_err());
        assert_eq!(SCHEMAS.with(|schemas| schemas.borrow().len()), MAX_SCHEMAS);
    }

    #[test]
    #[ignore = "manual fixture comparing repeated PB binding compilation with immutable schema reuse"]
    fn protobuf_schema_preparation_benchmark() {
        use std::{hint::black_box, time::Instant};
        let codec = ProtobufCodec {
            fields: (1..=128)
                .map(|number| {
                    (
                        format!("/field{number}"),
                        ProtobufField {
                            field_path: vec![number],
                            field_type: ProtobufType::Uint64,
                            repeated: false,
                        },
                    )
                })
                .collect(),
        };
        let iterations = 1000;
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(bindings(&codec).unwrap());
        }
        let compiled = start.elapsed();
        let first = schema(&codec).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            let next = schema(&codec).unwrap();
            assert!(Arc::ptr_eq(&first, &next));
            black_box(next);
        }
        let reused = start.elapsed();
        eprintln!(
            "PB schema preparation: fields={} iterations={iterations} compiled_ms={:.3} reused_ms={:.3}",
            codec.fields.len(),
            compiled.as_secs_f64() * 1000.0,
            reused.as_secs_f64() * 1000.0,
        );
    }
}
