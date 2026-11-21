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
    pub fn validate(&self) -> Result<()> {
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

    pub fn identity(&self, args: &[Vec<u8>]) -> Option<String> {
        self.check_identity(args).ok()
    }

    pub fn check_identity(&self, args: &[Vec<u8>]) -> Result<String> {
        ensure!(
            args.len() == 2 + self.keys.len() + self.argv_count,
            "script argument count does not match KEYS/ARGV declaration"
        );
        ensure!(
            args[0] == self.sha1.as_bytes(),
            "script SHA-1 does not match"
        );
        ensure!(
            args[1] == self.keys.len().to_string().as_bytes(),
            "script numkeys does not match declared KEYS count"
        );
        for (i, (pattern, key)) in self.keys.iter().zip(args.iter().skip(2)).enumerate() {
            let key = std::str::from_utf8(key)
                .map_err(|_| anyhow::anyhow!("script KEYS[{i}] is not UTF-8"))?;
            let middle = key
                .strip_prefix(&pattern.prefix)
                .and_then(|s| s.strip_suffix(&pattern.suffix))
                .ok_or_else(|| {
                    anyhow::anyhow!("script KEYS[{i}] does not match declared prefix/suffix")
                })?;
            if pattern.numeric_middle {
                ensure!(
                    !middle.is_empty()
                        && middle.len() <= 20
                        && middle.bytes().all(|b| b.is_ascii_digit()),
                    "script KEYS[{i}] requires a nonempty numeric middle"
                );
            } else {
                ensure!(
                    middle.is_empty(),
                    "script KEYS[{i}]: numeric_middle=false requires an exact prefix+suffix key; the recorded key has a nonempty middle"
                );
            }
        }
        let id = std::str::from_utf8(&args[2 + self.keys.len() + self.identity_argv_index])
            .map_err(|_| anyhow::anyhow!("script identity ARGV is not UTF-8"))?;
        ensure!(
            id.parse::<u64>()
                .is_ok_and(|n| n > 0 && n.to_string() == id),
            "script identity ARGV must be a canonical positive integer"
        );
        Ok(id.into())
    }

    pub fn exists(&self, args: &[Vec<u8>]) -> bool {
        args.len() == 2
            && args[0].eq_ignore_ascii_case(b"EXISTS")
            && args[1] == self.sha1.as_bytes()
    }
}
