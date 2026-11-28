//! Execution lifecycle over application-supplied process, input and evidence ports.
use std::{future::Future, pin::Pin};

use anyhow::Result;

pub type ExecutionFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
pub type CleanupFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// The composing application supplies installed protocol, codec and policy
/// capabilities together with process and authenticated storage adapters.
pub trait ExecutionDriver {
    fn prepare(&mut self) -> ExecutionFuture<'_, ()>;
    fn spawn_replay(&mut self) -> Result<()>;
    fn wait_ready(&mut self) -> ExecutionFuture<'_, ()>;
    fn start_target(&mut self) -> ExecutionFuture<'_, ()>;
    fn execute_cases(&mut self) -> ExecutionFuture<'_, ()>;
    fn stop_target(&mut self) -> ExecutionFuture<'_, ()>;
    fn finalize(&mut self) -> ExecutionFuture<'_, ()>;
    fn finish(&mut self) -> ExecutionFuture<'_, ()>;
    fn interrupt(&mut self) -> CleanupFuture<'_>;
}

pub async fn execute(driver: &mut impl ExecutionDriver) -> Result<()> {
    driver.prepare().await?;
    driver.spawn_replay()?;
    let outcome = run_session(driver).await;
    if outcome.is_err() {
        driver.interrupt().await;
    }
    outcome
}

async fn run_session(driver: &mut impl ExecutionDriver) -> Result<()> {
    driver.wait_ready().await?;
    driver.start_target().await?;
    driver.execute_cases().await?;
    driver.stop_target().await?;
    driver.finalize().await?;
    driver.finish().await
}

#[cfg(test)]
mod tests;
