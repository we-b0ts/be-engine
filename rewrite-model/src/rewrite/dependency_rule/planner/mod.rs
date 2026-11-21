use traffic_engine_config::{
    BackgroundDependencyPlan, BreezeMemcachedBackgroundDependencyPlan,
    MysqlBackgroundDependencyPlan, RedisBackgroundDependencyPlan,
};
use traffic_engine_verification::MemcachedTimestampRulePlan;
pub enum DependencyRulePlan {
    RedisApiTriggered(crate::ApiTriggeredRedisPlan),
    MysqlApiTriggered(crate::ApiTriggeredMysqlPlan),
    RedisCrossCase(crate::RedisCrossCasePlan),
    HttpCrossCase(crate::HttpCrossCasePlan),
    MysqlTime(crate::MysqlTimeRulePlan),
    Mysql(MysqlBackgroundDependencyPlan),
    Http(BackgroundDependencyPlan),
    Memcached(BreezeMemcachedBackgroundDependencyPlan),
    MemcachedTimestamp(MemcachedTimestampRulePlan),
    #[cfg(any())]
    Motan(MotanBackgroundDependencyPlan),
    Redis(RedisBackgroundDependencyPlan),
}
