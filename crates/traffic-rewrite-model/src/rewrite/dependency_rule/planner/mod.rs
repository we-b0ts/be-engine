use crate::rewrite::*;
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
    Motan(MotanBackgroundDependencyPlan),
    Redis(RedisBackgroundDependencyPlan),
}
