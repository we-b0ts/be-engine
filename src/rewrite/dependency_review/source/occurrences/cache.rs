//! Disposable occurrence metadata. Original Source proof uses its own full loader.
use super::*;
use crate::dependency_index::{FileStamp, store};
use serde::{Deserialize, Serialize};

const VERSION: u32 = 1;
const FILE: &str = "diagnostic-occurrences-v1.json";
type NativeEntry = ((String, String, u64), BTreeSet<Uuid>);
type BorrowedNativeEntry<'a> = (&'a (String, String, u64), &'a BTreeSet<Uuid>);

#[derive(Deserialize)]
struct Cached {
    version: u32,
    identity: String,
    central_stamp: FileStamp,
    #[serde(default)]
    scope: Option<String>,
    exchanges: BTreeMap<Uuid, SourceExchange>,
    apis: BTreeMap<Uuid, String>,
    native: Vec<NativeEntry>,
    http: HttpReferences,
}

fn path(root: &Path, scope: Option<&str>) -> PathBuf {
    let file = scope.map_or_else(
        || FILE.into(),
        |scope| {
            format!(
                "diagnostic-occurrences-v1-{}.json",
                scope.trim_start_matches("sha256:")
            )
        },
    );
    store::cache_directory(root).join(file)
}

pub(super) fn read(
    root: &Path,
    identity: &str,
    stamp: &FileStamp,
    scope: Option<&str>,
) -> Option<Occurrences> {
    // The caller authenticates every sealed member before consulting this cache.
    let cached: Cached = store::read_json(&path(root, scope)).ok()?;
    if cached.version != VERSION
        || cached.identity != identity
        || &cached.central_stamp != stamp
        || cached.scope.as_deref() != scope
    {
        return None;
    }
    let entries = cached.native.len();
    let native: NativeReferences = cached.native.into_iter().collect();
    if native.len() != entries
        || cached
            .exchanges
            .iter()
            .any(|(id, event)| *id != event.capture.exchange_id)
    {
        return None;
    }
    Some(Occurrences {
        identity: cached.identity,
        exchanges: cached.exchanges,
        apis: cached.apis,
        native,
        http: cached.http,
        case_defaults: BTreeMap::new(),
    })
}

pub(super) fn write(
    root: &Path,
    stamp: &FileStamp,
    scope: Option<&str>,
    result: &Occurrences,
) -> Result<()> {
    #[derive(Serialize)]
    struct Metadata<'a> {
        version: u32,
        identity: &'a str,
        central_stamp: &'a FileStamp,
        scope: Option<&'a str>,
        exchanges: &'a BTreeMap<Uuid, SourceExchange>,
        apis: &'a BTreeMap<Uuid, String>,
        native: Vec<BorrowedNativeEntry<'a>>,
        http: &'a HttpReferences,
    }
    let directory = store::cache_directory(root);
    store::private_directory(&directory)?;
    store::write_json(
        &path(root, scope),
        &Metadata {
            version: VERSION,
            identity: &result.identity,
            central_stamp: stamp,
            scope,
            exchanges: &result.exchanges,
            apis: &result.apis,
            native: result.native.iter().collect(),
            http: &result.http,
        },
    )
}
