//! Preserve unknown native records for their registered evidence owner.
use super::*;

#[derive(Debug)]
pub(crate) enum DependencyRecord {
    ConnectFailure,
    MysqlConnection(Box<RecordedMysqlConnection>),
    MysqlExchange(Box<RecordedMysqlExchange>),
    HttpExchange(Box<http::RecordedHttpExchange>),
    TcpGatewayConnection(Box<http::RecordedTcpGatewayConnection>),
    RedisConnection(Box<redis::RecordedConnection>),
    RedisExchange(Box<redis::RecordedExchange>),
    RedisPubSubPush(Box<redis::pubsub::RecordedPush>),

    ProxyError(Box<RecordedProxyError>),
    Native(Box<Value>),
}

impl<'de> Deserialize<'de> for DependencyRecord {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let kind = value
            .get("event_type")
            .and_then(Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("dependency record has no event_type"))?;
        let parsed = match kind {
            "dependency_connect_failure" => {
                serde_json::from_value::<replay::connect_failure::RecordedFailure>(value)
                    .and_then(|failure| failure.validate().map_err(serde::de::Error::custom))
                    .map(|()| Self::ConnectFailure)
            }
            "mysql_connection" => serde_json::from_value(value).map(Self::MysqlConnection),
            "mysql_exchange" => serde_json::from_value(value).map(Self::MysqlExchange),
            "http_exchange" => serde_json::from_value(value).map(Self::HttpExchange),
            "tcp_gateway_connection" => {
                serde_json::from_value(value).map(Self::TcpGatewayConnection)
            }
            "redis_connection" => serde_json::from_value(value).map(Self::RedisConnection),
            "redis_exchange" => serde_json::from_value(value).map(Self::RedisExchange),
            "redis_pub_sub_push" => serde_json::from_value(value).map(Self::RedisPubSubPush),

            "proxy_error" => serde_json::from_value(value).map(Self::ProxyError),
            _ => Ok(Self::Native(Box::new(value))),
        };
        parsed.map_err(serde::de::Error::custom)
    }
}
