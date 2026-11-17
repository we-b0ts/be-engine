use super::*;

const STAGES: &[&str] = &[
    "prepare", "spawn", "ready", "start", "cases", "stop", "finalize", "finish",
];

#[derive(Default)]
struct Driver {
    calls: Vec<&'static str>,
    failure: Option<&'static str>,
}

impl Driver {
    fn step(&mut self, name: &'static str) -> Result<()> {
        self.calls.push(name);
        anyhow::ensure!(self.failure != Some(name), "failed at {name}");
        Ok(())
    }
}

impl ExecutionDriver for Driver {
    fn prepare(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async { self.step("prepare") })
    }
    fn spawn_replay(&mut self) -> Result<()> {
        self.step("spawn")
    }
    fn wait_ready(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async { self.step("ready") })
    }
    fn start_target(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async { self.step("start") })
    }
    fn execute_cases(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async { self.step("cases") })
    }
    fn stop_target(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async { self.step("stop") })
    }
    fn finalize(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async { self.step("finalize") })
    }
    fn finish(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async { self.step("finish") })
    }
    fn interrupt(&mut self) -> CleanupFuture<'_> {
        Box::pin(async { self.calls.push("interrupt") })
    }
}

#[tokio::test]
async fn host_ports_run_in_order() {
    let mut driver = Driver::default();
    execute(&mut driver).await.unwrap();
    assert_eq!(driver.calls, STAGES);
}

#[tokio::test]
async fn each_session_failure_interrupts_once_and_preserves_original_error() {
    for (index, &stage) in STAGES.iter().enumerate() {
        let mut driver = Driver {
            failure: Some(stage),
            ..Default::default()
        };
        let error = execute(&mut driver).await.unwrap_err();
        assert_eq!(error.to_string(), format!("failed at {stage}"));
        let mut expected = STAGES[..=index].to_vec();
        if index >= 2 {
            expected.push("interrupt");
        }
        assert_eq!(driver.calls, expected);
    }
}
