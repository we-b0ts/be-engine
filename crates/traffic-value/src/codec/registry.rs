use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result, ensure};

use super::{CodecDescriptor, CodecProvider, Recognition, ValueCodec, ValueDocument};
use crate::Value;

#[derive(Clone, Default)]
pub struct CodecRegistry {
    providers: BTreeMap<String, Arc<dyn CodecProvider>>,
}

#[derive(Debug, Clone)]
pub struct CodecProbe {
    pub descriptor: CodecDescriptor,
    pub recognition: Recognition,
}

impl CodecRegistry {
    pub fn field_schema(
        &self,
        id: &str,
        configuration: &Value,
        path: &str,
    ) -> Result<super::FieldSchema> {
        self.providers
            .get(id)
            .with_context(|| format!("codec {id:?} is not installed"))?
            .field_schema(configuration, path)
    }

    pub fn register(&mut self, provider: Arc<dyn CodecProvider>) -> Result<()> {
        let descriptor = provider.descriptor();
        ensure!(!descriptor.id.is_empty(), "codec identity is empty");
        ensure!(descriptor.version > 0, "codec version is zero");
        ensure!(
            !self.providers.contains_key(descriptor.id),
            "duplicate codec registration {:?}",
            descriptor.id
        );
        self.providers.insert(descriptor.id.into(), provider);
        Ok(())
    }

    pub fn descriptors(&self) -> impl Iterator<Item = CodecDescriptor> + '_ {
        self.providers
            .values()
            .map(|provider| provider.descriptor())
    }

    pub fn prepare(&self, id: &str, configuration: &Value) -> Result<PreparedCodec> {
        let provider = self
            .providers
            .get(id)
            .with_context(|| format!("codec {id:?} is not installed"))?;
        Ok(PreparedCodec {
            descriptor: provider.descriptor(),
            configuration: configuration.clone(),
            codec: provider.prepare(configuration)?,
        })
    }
    pub fn merge(&self, id: &str, configurations: &[&Value]) -> Result<Value> {
        self.providers
            .get(id)
            .with_context(|| format!("codec {id:?} is not installed"))?
            .merge(configurations)
    }

    pub fn fields_overlap(
        &self,
        id: &str,
        left_configuration: &Value,
        left_path: &str,
        right_configuration: &Value,
        right_path: &str,
    ) -> Result<bool> {
        self.providers
            .get(id)
            .with_context(|| format!("codec {id:?} is not installed"))?
            .fields_overlap(
                left_configuration,
                left_path,
                right_configuration,
                right_path,
            )
    }

    pub fn recognize(&self, source: &[u8], metadata: &Value) -> Result<PreparedCodec> {
        self.try_recognize(source, metadata)?
            .context("no installed codec recognizes the Source value")
    }

    pub fn try_recognize(&self, source: &[u8], metadata: &Value) -> Result<Option<PreparedCodec>> {
        let mut recognized = Vec::new();
        for probe in self.inspect(source, metadata)? {
            if let Recognition::Recognized {
                confidence,
                configuration,
            } = probe.recognition
            {
                recognized.push((confidence, probe.descriptor.id, configuration));
            }
        }
        recognized.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
        let Some((confidence, id, configuration)) = recognized.first() else {
            return Ok(None);
        };
        ensure!(
            recognized.get(1).is_none_or(|other| other.0 != *confidence),
            "Source value has ambiguous codec recognition"
        );
        self.prepare(id, configuration).map(Some)
    }

    pub fn inspect(&self, source: &[u8], metadata: &Value) -> Result<Vec<CodecProbe>> {
        ensure!(
            source.len() <= crate::MAX_VALUE_BYTES,
            "payload exceeds the 64 MiB codec limit"
        );
        self.providers
            .values()
            .map(|provider| {
                Ok(CodecProbe {
                    descriptor: provider.descriptor(),
                    recognition: provider.recognize(source, metadata)?,
                })
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct PreparedCodec {
    descriptor: CodecDescriptor,
    configuration: Value,
    codec: Arc<dyn ValueCodec>,
}

impl std::fmt::Debug for PreparedCodec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedCodec")
            .field("id", &self.descriptor.id)
            .field("version", &self.descriptor.version)
            .finish()
    }
}

impl PreparedCodec {
    pub fn descriptor(&self) -> &CodecDescriptor {
        &self.descriptor
    }

    pub fn configuration(&self) -> &Value {
        &self.configuration
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        ensure!(
            bytes.len() <= crate::MAX_VALUE_BYTES,
            "payload exceeds the 64 MiB codec limit"
        );
        self.codec.decode(bytes)
    }
}
