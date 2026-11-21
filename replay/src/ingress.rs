//! Bounded read-ahead admissions. Delivery remains ordered by the connection owner.
use std::collections::VecDeque;
use std::future::Future;

use anyhow::{Context, Result};
use tokio::task::JoinHandle;

use crate::{PendingRequest, SequenceClaim};

pub struct AdmissionQueue<T> {
    tasks: VecDeque<Task<T>>,
}

struct Task<T> {
    handle: JoinHandle<T>,
    _budget: PendingRequest,
}

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl<T> Default for AdmissionQueue<T> {
    fn default() -> Self {
        Self {
            tasks: VecDeque::new(),
        }
    }
}

impl<T: Send + 'static> AdmissionQueue<T> {
    pub fn push(
        &mut self,
        claim: &SequenceClaim,
        bytes: usize,
        admission: impl Future<Output = T> + Send + 'static,
    ) -> Result<()> {
        let budget = claim.pending(bytes)?;
        self.tasks.push_back(Task {
            handle: tokio::spawn(admission),
            _budget: budget,
        });
        Ok(())
    }

    pub async fn pop(&mut self) -> Result<Option<T>> {
        let Some(mut task) = self.tasks.pop_front() else {
            return Ok(None);
        };
        (&mut task.handle)
            .await
            .context("pipelined dependency admission failed")
            .map(Some)
    }
}
