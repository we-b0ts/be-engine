//! The small synchronous epoch lock linearizes parsed headers with Case close.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU8};

#[derive(Debug)]
pub(super) struct Observation {
    pub id: uuid::Uuid,
    pub observed_case_id: Option<String>,
    pub started_at: chrono::DateTime<Utc>,
    pub startup_open: bool,
    pub process_head_unique: AtomicBool,
    pub head_sha256: std::sync::OnceLock<String>,
    pub status: AtomicU8,
}

#[derive(Debug)]
pub(super) struct Registry {
    case: Option<(String, Arc<AtomicUsize>)>,
    pub startup_open: bool,
    pub observations: Vec<Arc<Observation>>,
    pub omitted: usize,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            case: None,
            startup_open: true,
            observations: vec![],
            omitted: 0,
        }
    }
}
impl Registry {
    pub(super) fn activate(&mut self, case: Option<&str>, count: Arc<AtomicUsize>) {
        self.case = case.map(|case| (case.into(), count));
    }
    pub(super) fn try_close(&mut self, case: &str) -> bool {
        if let Some((current, count)) = &self.case
            && (current != case || count.load(Ordering::Acquire) > 0)
        {
            return false;
        }
        self.case = None;
        true
    }
}

#[derive(Clone)]
pub(in crate::protocols::replay::http) struct Handle {
    registry: Arc<std::sync::Mutex<Registry>>,
    run: Arc<AtomicUsize>,
    changed: Arc<tokio::sync::Notify>,
}
impl Handle {
    pub(super) fn new(
        registry: Arc<std::sync::Mutex<Registry>>,
        run: Arc<AtomicUsize>,
        changed: Arc<tokio::sync::Notify>,
    ) -> Self {
        Self {
            registry,
            run,
            changed,
        }
    }
    /// Called synchronously by Hyper's service closure, before its future can
    /// queue for the Replay mutex. Closing an epoch uses this very same lock.
    pub(in crate::protocols::replay::http) fn admit(&self) -> Admission {
        let mut registry = self
            .registry
            .lock()
            .expect("HTTP ingress registry poisoned");
        let (case, counter) = registry
            .case
            .as_ref()
            .map(|(case, count)| (Some(case.clone()), count.clone()))
            .unwrap_or_else(|| (None, self.run.clone()));
        counter.fetch_add(1, Ordering::AcqRel);
        let observation = Arc::new(Observation {
            id: uuid::Uuid::new_v4(),
            observed_case_id: case,
            started_at: Utc::now(),
            startup_open: registry.startup_open,
            process_head_unique: AtomicBool::new(false),
            head_sha256: Default::default(),
            status: AtomicU8::new(READING),
        });
        if registry.observations.len() < MAX_OBSERVATIONS {
            registry.observations.push(observation.clone());
        } else {
            registry.omitted += 1;
        }
        Admission {
            observation,
            counter,
            registry: self.registry.clone(),
            changed: self.changed.clone(),
            released: false,
            started: tokio::time::Instant::now(),
            evidence: Default::default(),
        }
    }
}

#[derive(Debug)]
pub(in crate::protocols::replay::http) struct Admission {
    pub(in crate::protocols::replay::http) evidence:
        std::sync::OnceLock<(Option<uuid::Uuid>, bool)>,
    observation: Arc<Observation>,
    counter: Arc<AtomicUsize>,
    registry: Arc<std::sync::Mutex<Registry>>,
    changed: Arc<tokio::sync::Notify>,
    released: bool,
    started: tokio::time::Instant,
}
impl Admission {
    pub(in crate::protocols::replay::http) fn case_id(&self) -> Option<&str> {
        self.observation.observed_case_id.as_deref()
    }
    pub(in crate::protocols::replay::http) fn observation_id(&self) -> uuid::Uuid {
        self.observation.id
    }
    pub(in crate::protocols::replay::http) fn permits_startup(&self) -> bool {
        self.observation.startup_open
    }
    pub(in crate::protocols::replay::http) fn started_at(&self) -> chrono::DateTime<Utc> {
        self.observation.started_at
    }
    pub(in crate::protocols::replay::http) fn started(&self) -> tokio::time::Instant {
        self.started
    }
    pub(super) fn configure_head(&mut self, digest: String, process: bool, run: &Arc<AtomicUsize>) {
        let _ = self.observation.head_sha256.set(digest);
        if process {
            let _registry = self
                .registry
                .lock()
                .expect("HTTP ingress registry poisoned");
            if !Arc::ptr_eq(&self.counter, run) {
                // Increment the destination first: session finalization must
                // never observe an empty window while the guard changes lanes.
                run.fetch_add(1, Ordering::AcqRel);
                self.counter.fetch_sub(1, Ordering::AcqRel);
                self.counter = run.clone();
                self.changed.notify_waiters();
            }
            self.observation
                .process_head_unique
                .store(true, Ordering::Release);
        }
    }
    pub(in crate::protocols::replay::http) fn complete(&mut self) {
        self.observation.status.store(COMPLETE, Ordering::Release);
        self.release();
    }
    pub(in crate::protocols::replay::http) fn body_error(&mut self) {
        self.observation.status.store(BODY_ERROR, Ordering::Release);
        self.release();
    }
    fn release(&mut self) {
        if !self.released {
            self.released = true;
            self.counter.fetch_sub(1, Ordering::AcqRel);
            self.changed.notify_waiters();
        }
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        if !self.released {
            self.observation.status.store(CANCELLED, Ordering::Release);
            self.release();
        }
    }
}
