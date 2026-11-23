//! Default application composition for traffic execution and rewrite coordination.
pub use traffic_engine::*;
pub use traffic_replay_runtime::ReplayTimerConfig;
pub use traffic_rewrite::*;

pub fn initialize_application() {
    traffic_rewrite::initialize();
}

pub fn prepare_e2e_run(options: E2eRunPrepareOptions) -> anyhow::Result<E2eRunPrepareResult> {
    initialize_application();
    traffic_engine::prepare_e2e_run(options)
}

pub async fn run_e2e_api(context: E2eRunContext, api: &str) -> anyhow::Result<E2eApiRunResult> {
    initialize_application();
    traffic_engine::run_e2e_api(context, api).await
}

pub async fn run_e2e_round(context: E2eRunContext) -> anyhow::Result<E2eRunResult> {
    initialize_application();
    traffic_engine::run_e2e_round(context).await
}

pub fn upgrade_source_snapshot(
    options: SourceUpgradeOptions,
) -> anyhow::Result<SourceUpgradeResult> {
    initialize_application();
    traffic_engine::upgrade_source_snapshot(options)
}

pub async fn run_replay(config: ReplayConfig) -> anyhow::Result<()> {
    initialize_application();
    traffic_replay_runtime::run_replay(config).await
}

pub async fn run_replay_with_lifecycle(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
) -> anyhow::Result<()> {
    initialize_application();
    traffic_replay_runtime::run_replay_with_lifecycle(config, lifecycle).await
}

pub async fn run_replay_with_counters(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
    counters: Option<ReplayEgressCounterReader>,
) -> anyhow::Result<()> {
    initialize_application();
    traffic_replay_runtime::run_replay_with_counters(config, lifecycle, counters).await
}

pub async fn run_replay_with_providers(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
    counters: Option<ReplayEgressCounterReader>,
    providers: std::sync::Arc<protocols::DependencyProviders>,
) -> anyhow::Result<()> {
    initialize_application();
    traffic_replay_runtime::run_replay_with_providers(config, lifecycle, counters, providers).await
}

pub async fn run_replay_with_timer_config(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
    counters: Option<ReplayEgressCounterReader>,
    timers: Option<ReplayTimerConfig>,
) -> anyhow::Result<()> {
    initialize_application();
    traffic_replay_runtime::run_replay_with_timer_config(config, lifecycle, counters, timers).await
}

pub async fn run_mysql_replay(config: MysqlReplayConfig) -> anyhow::Result<()> {
    run_replay(config).await
}
