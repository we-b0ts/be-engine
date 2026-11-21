pub use traffic_protocol_redis::key_slots;
pub use traffic_protocol_redis::socketio_rpc;
mod wire;

pub use traffic_protocol_redis::client_info::is_client_library_info;

pub use wire::{
    RedisCommand, RedisPubSubPush, RedisSubscriptionKind, frame_kind, parse_pubsub_push,
    validate_subscription_confirmation,
};

#[cfg(any(test, feature = "test-support"))]
pub use wire::{BufferedReader, encode_array, read_frame, redis_command};
