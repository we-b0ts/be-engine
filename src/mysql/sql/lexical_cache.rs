//! Bounded reuse of immutable lexer output. Parameters and policy decisions are
//! never cached; invalid SQL retains the lexer's original failure behavior.
use super::Token;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, OnceLock},
};

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENTRIES: usize = 1024;
const MAX_SQL: usize = 64 * 1024;

#[derive(Default)]
struct Cache {
    entries: HashMap<String, CachedTokens>,
    order: VecDeque<String>,
    bytes: usize,
}
type CachedTokens = (Arc<Option<Vec<Token>>>, usize);

pub(super) fn tokens(sql: &str) -> Option<Vec<Token>> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    if sql.len() > MAX_SQL {
        return super::scan(sql, |_| {});
    }
    let cache = CACHE.get_or_init(Mutex::default);
    let hit = cache
        .lock()
        .expect("SQL lexer cache")
        .entries
        .get(sql)
        .map(|v| v.0.clone());
    if let Some(hit) = hit {
        return (*hit).clone();
    }
    let parsed = Arc::new(super::scan(sql, |_| {}));
    let charge = sql.len() * 2
        + parsed.as_ref().as_ref().map_or(0, |ts| {
            ts.capacity() * std::mem::size_of::<Token>()
                + ts.iter()
                    .map(|t| match t {
                        Token::Word(s)
                        | Token::Identifier(s)
                        | Token::Number(s)
                        | Token::Symbol(s) => s.capacity(),
                        Token::Bytes(b) => b.capacity(),
                        _ => 0,
                    })
                    .sum::<usize>()
        });
    if charge <= MAX_BYTES {
        let mut cache = cache.lock().expect("SQL lexer cache");
        if !cache.entries.contains_key(sql) {
            while cache.entries.len() >= MAX_ENTRIES || cache.bytes + charge > MAX_BYTES {
                let Some(key) = cache.order.pop_front() else {
                    break;
                };
                if let Some((_, bytes)) = cache.entries.remove(&key) {
                    cache.bytes -= bytes;
                }
            }
            cache.bytes += charge;
            cache.order.push_back(sql.into());
            cache.entries.insert(sql.into(), (parsed.clone(), charge));
        }
    }
    (*parsed).clone()
}

#[cfg(test)]
mod tests {
    #[test]
    fn cached_lexer_preserves_values_and_rejections() {
        for sql in [
            "SELECT 'AbC', ?, 1.00",
            "SELECT /*!50000 x */ 1",
            "SELECT 'unterminated",
            "SELECT `a` FROM t WHERE x = 2",
        ] {
            for _ in 0..3 {
                assert_eq!(super::tokens(sql), super::super::scan(sql, |_| {}));
            }
        }
    }
}
