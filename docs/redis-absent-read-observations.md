# Redis transient nil observations

Declare Source-proven polling with `redis.keys.<bounded-pattern>.state.get:
{transient: [nil]}`. Nil GET observations may occur zero or more times; real
mutations and non-nil terminal observations retain their obligations.

See [Redis state contracts](redis-state-contracts.md) for configuration,
conditional loop bodies, Source proof, separate omission audits and the normal
plan/apply/fresh fast Replay workflow. Value correspondence remains separate in
[read-back](redis-read-back.md); [read commutation](redis-read-commutation.md)
keeps finite counts while permitting independent read ordering.
