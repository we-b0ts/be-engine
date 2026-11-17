use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::request_headers::read_request_file_parts;

pub(super) struct RequestCaseView {
    request_path: PathBuf,
    request: Vec<u8>,
    decrypted_request: Option<Vec<u8>>,
}

impl RequestCaseView {
    pub(super) fn prepare(case_dir: &Path) -> Result<Self> {
        let request_path = case_dir.join("request.json");
        let (request, decrypted_request) = read_request_file_parts(&request_path)?;
        Ok(Self {
            request_path,
            request,
            decrypted_request,
        })
    }

    pub(super) fn request_path(&self) -> &Path {
        &self.request_path
    }

    pub(super) fn request(&self) -> &[u8] {
        &self.request
    }

    pub(super) fn replay_request(&self) -> &[u8] {
        self.decrypted_request.as_deref().unwrap_or(&self.request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_plain_requests_in_memory_without_a_temporary_view() {
        let temp = tempfile::tempdir().unwrap();
        let case = temp.path().join("case-id");
        std::fs::create_dir(&case).unwrap();
        std::fs::write(case.join("request.json"), br#"{"method":"GET"}"#).unwrap();

        let view = RequestCaseView::prepare(&case).unwrap();

        assert_eq!(view.request(), br#"{"method":"GET"}"#);
        assert_eq!(view.replay_request(), view.request());
        assert!(!temp.path().join("decrypted-request-views").exists());
    }
}
