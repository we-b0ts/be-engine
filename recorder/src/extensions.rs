//! Recording-local state supplied by application protocol bindings.
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct RecordingExtensions {
    values: Arc<Mutex<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>>,
}

impl RecordingExtensions {
    pub fn insert<T: Send + Sync + 'static>(&self, value: T) {
        self.values
            .lock()
            .expect("recording extensions poisoned")
            .insert(TypeId::of::<T>(), Arc::new(value));
    }

    pub fn existing<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.values
            .lock()
            .expect("recording extensions poisoned")
            .get(&TypeId::of::<T>())?
            .clone()
            .downcast()
            .ok()
    }

    pub fn get<T: Default + Send + Sync + 'static>(&self) -> Arc<T> {
        self.values
            .lock()
            .expect("recording extensions poisoned")
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Arc::new(T::default()))
            .clone()
            .downcast()
            .expect("recording extension type differs from its identity")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_protocol_state_and_independent_recordings_have_their_own_state() {
        let recording = RecordingExtensions::default();
        let state = recording.get::<Mutex<Vec<u64>>>();
        state.lock().unwrap().push(7);
        let same = recording.clone().get::<Mutex<Vec<u64>>>();
        assert!(Arc::ptr_eq(&state, &same));
        assert_eq!(*same.lock().unwrap(), [7]);
        let independent = RecordingExtensions::default().get::<Mutex<Vec<u64>>>();
        assert!(independent.lock().unwrap().is_empty());
        assert!(!Arc::ptr_eq(&state, &independent));
        assert!(
            recording
                .get::<Mutex<Vec<String>>>()
                .lock()
                .unwrap()
                .is_empty()
        );
    }
}
