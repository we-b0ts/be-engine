//! Recording directory ownership follows confirmed Source methods and routes.
use hyper::{Method, Uri};
use sha2::{Digest, Sha256};

use super::rules::{CaseGroup, resolve_case_group};
use crate::config::HttpSourceRoutes;

pub(super) fn resolve(method: &Method, uri: &Uri, sources: &HttpSourceRoutes) -> CaseGroup {
    let owner = sources.resolve(method.as_str(), uri.path());
    let selector = owner.map_or(uri.path(), |api| api.path_pattern());
    let mut group = resolve_case_group(uri, &[selector.to_owned()]);
    // Unconfirmed methods cannot share a directory before Source analysis.
    // Confirmed methods of one canonical route deliberately share a directory.
    let identity = owner.map_or_else(
        || format!("{method} {}", uri.path()),
        |_| selector.to_owned(),
    );
    let hash = Sha256::digest(identity.as_bytes());
    let suffix = hash[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    group.directory = format!("{}-{suffix}", group.directory);
    group
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directories_follow_method_coverage_and_confirmed_static_exceptions() {
        let sources: HttpSourceRoutes = vec!["GET /items/*".into(), "POST /items/upload".into()]
            .try_into()
            .unwrap();
        let get = resolve(&Method::GET, &"/items/upload".parse().unwrap(), &sources);
        let post = resolve(&Method::POST, &"/items/upload".parse().unwrap(), &sources);
        assert_eq!(get.pattern, "/items/*");
        assert_eq!(post.pattern, "/items/upload");
        assert_ne!(get.directory, post.directory);
        let sources = sources.merged(["POST /items/*".into()]).unwrap();
        assert_eq!(
            resolve(&Method::POST, &"/items/42".parse().unwrap(), &sources).directory,
            get.directory
        );
        assert_eq!(
            resolve(&Method::POST, &"/items/upload".parse().unwrap(), &sources),
            post
        );
    }

    #[test]
    fn unconfirmed_methods_and_colliding_slugs_cannot_mix_apis() {
        let sources = HttpSourceRoutes::default();
        let get = resolve(&Method::GET, &"/items/upload".parse().unwrap(), &sources);
        let post = resolve(&Method::POST, &"/items/upload".parse().unwrap(), &sources);
        assert_ne!(get.directory, post.directory);
        assert_ne!(
            resolve(&Method::GET, &"/items/a_b".parse().unwrap(), &sources).directory,
            resolve(&Method::GET, &"/items/a-b".parse().unwrap(), &sources).directory
        );
    }
}
