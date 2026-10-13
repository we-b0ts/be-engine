//! Exact Lua digest and KEYS envelope, with the captured identity in ARGV.
use super::*;
use crate::config::RedisKeyPatternConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiTriggerRedisScript {
    pub sha1: String,
    pub keys: Vec<RedisKeyPatternConfig>,
    pub argv_count: usize,
    pub identity_argv_index: usize,
}

impl ApiTriggerRedisScript {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.sha1.len() == 40
                && self
                    .sha1
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "script.sha1 must be a lowercase SHA-1 digest"
        );
        ensure!(
            (1..=32).contains(&self.keys.len())
                && (1..=64).contains(&self.argv_count)
                && self.identity_argv_index < self.argv_count,
            "script requires bounded KEYS/ARGV and a present identity_argv_index"
        );
        ensure!(
            self.keys.iter().all(|k| !k.prefix.is_empty()
                && k.prefix.len() <= 256
                && k.suffix.len() <= 256
                && !k.prefix.contains(['\r', '\n', '{', '}'])
                && !k.suffix.contains(['\r', '\n', '{', '}'])),
            "script keys require fixed bounded affixes and optional numeric middles"
        );
        Ok(())
    }

    pub(crate) fn identity(&self, args: &[Vec<u8>]) -> Option<String> {
        if args.len() != 2 + self.keys.len() + self.argv_count
            || args.first()? != self.sha1.as_bytes()
            || args.get(1)? != self.keys.len().to_string().as_bytes()
        {
            return None;
        }
        for (pattern, key) in self.keys.iter().zip(args.iter().skip(2)) {
            let key = std::str::from_utf8(key).ok()?;
            let middle = key
                .strip_prefix(&pattern.prefix)?
                .strip_suffix(&pattern.suffix)?;
            if if pattern.numeric_middle {
                middle.is_empty()
                    || middle.len() > 20
                    || !middle.bytes().all(|b| b.is_ascii_digit())
            } else {
                !middle.is_empty()
            } {
                return None;
            }
        }
        let id =
            std::str::from_utf8(args.get(2 + self.keys.len() + self.identity_argv_index)?).ok()?;
        id.parse::<u64>()
            .ok()
            .filter(|n| *n > 0 && n.to_string() == id)?;
        Some(id.into())
    }

    pub(crate) fn exists(&self, args: &[Vec<u8>]) -> bool {
        args.len() == 2
            && args[0].eq_ignore_ascii_case(b"EXISTS")
            && args[1] == self.sha1.as_bytes()
    }
}
