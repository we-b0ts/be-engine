//! Numeric recording-local identities projected into existing UUID-based APIs.
use uuid::Uuid;

#[derive(Clone, Copy)]
pub enum IdentityKind {
    Dependency,
    Case,
    Connection,
}

impl IdentityKind {
    fn prefix(self) -> &'static str {
        match self {
            Self::Dependency => "",
            Self::Case => "case-",
            Self::Connection => "conn-",
        }
    }

    fn namespace(self) -> u128 {
        match self {
            Self::Dependency => 0,
            Self::Case => 1,
            Self::Connection => 2,
        }
    }

    pub fn bridge(self, recording_id: Uuid, seq: u64) -> Uuid {
        Uuid::from_u128(recording_id.as_u128() ^ (self.namespace() << 64) ^ u128::from(seq))
    }

    pub fn sequence(self, recording_id: Uuid, id: Uuid) -> Option<u64> {
        let bits = recording_id.as_u128() ^ id.as_u128() ^ (self.namespace() << 64);
        u64::try_from(bits).ok().filter(|number| *number != 0)
    }

    /// Keep explicitly assigned identities visible when they have no local sequence.
    pub fn display(self, recording_id: Uuid, id: Uuid) -> String {
        self.sequence(recording_id, id)
            .map_or_else(|| id.to_string(), |seq| format!("{}{seq}", self.prefix()))
    }

    pub fn parse(self, recording_id: Uuid, label: &str) -> Option<Uuid> {
        if let Some(number) = label.strip_prefix(self.prefix())
            && !number.is_empty()
            && !number.starts_with('0')
            && number.bytes().all(|byte| byte.is_ascii_digit())
        {
            return number
                .parse::<u64>()
                .ok()
                .map(|seq| self.bridge(recording_id, seq));
        }
        Uuid::parse_str(label).ok()
    }
}
