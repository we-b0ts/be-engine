//! Borrowed native operation identity; no whole-message JSON or implicit case folding.
use super::ResourceProvider;
use anyhow::{Result, ensure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeOperation<'a> {
    HttpMethod(&'a str),
    RedisCommand(&'a str),
    MysqlCommand(&'a str),
    MemcachedCommand(&'a str),
    MotanMethod(&'a str),
    KafkaApi(&'a str),
}

impl<'a> NativeOperation<'a> {
    pub(crate) fn symbol(self) -> &'a str {
        match self {
            Self::HttpMethod(value)
            | Self::RedisCommand(value)
            | Self::MysqlCommand(value)
            | Self::MemcachedCommand(value)
            | Self::MotanMethod(value)
            | Self::KafkaApi(value) => value,
        }
    }

    pub(crate) fn sql_template(self) -> bool {
        matches!(self, Self::MysqlCommand("COM_QUERY" | "COM_STMT_EXECUTE"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationSelector<'a> {
    Any,
    Exact(NativeOperation<'a>),
}

impl<'a> OperationSelector<'a> {
    pub(crate) fn symbol(self) -> Option<&'a str> {
        match self {
            Self::Any => None,
            Self::Exact(operation) => Some(operation.symbol()),
        }
    }
}

pub(super) fn prepare<'a>(
    provider: ResourceProvider,
    operation: Option<&'a str>,
) -> Result<OperationSelector<'a>> {
    let Some(operation) = operation else {
        return Ok(OperationSelector::Any);
    };
    ensure!(
        !operation.is_empty()
            && operation.len() <= 4096
            && !operation.chars().any(char::is_control),
        "native resource operation must be a bounded nonempty symbol"
    );
    let native = match provider {
        ResourceProvider::Http => {
            hyper::Method::from_bytes(operation.as_bytes())?;
            NativeOperation::HttpMethod(operation)
        }
        ResourceProvider::Redis => NativeOperation::RedisCommand(operation),
        ResourceProvider::Mysql => NativeOperation::MysqlCommand(operation),
        ResourceProvider::Memcached => {
            ensure!(
                ![
                    "mg",
                    "ms",
                    "md",
                    "ma",
                    "me",
                    "mn",
                    "sasl_list_mechs",
                    "sasl_auth",
                    "sasl_step",
                    "unknown"
                ]
                .iter()
                .any(|unsupported| operation.eq_ignore_ascii_case(unsupported)),
                "Memcached operation mode has no supported native replay/value adapter"
            );
            NativeOperation::MemcachedCommand(operation)
        }
        ResourceProvider::Motan => NativeOperation::MotanMethod(operation),
        ResourceProvider::Kafka => NativeOperation::KafkaApi(operation),
    };
    Ok(OperationSelector::Exact(native))
}
