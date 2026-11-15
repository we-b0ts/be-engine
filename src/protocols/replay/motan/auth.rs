use std::fmt;

const AUTHORIZATION_ATTACHMENT: &str = "Authorization";

#[derive(Clone, PartialEq, Eq)]
pub(super) enum Authentication {
    None,
    Tauth2 { parameters: String },
    Other { scheme: String },
    Malformed { scheme: Option<String> },
}

impl Authentication {
    pub(super) fn from_attachments(attachments: &motan_codec::Attachments) -> Self {
        attachments
            .get(AUTHORIZATION_ATTACHMENT)
            .map_or(Self::None, Self::parse)
    }

    pub(super) fn mismatch_fields(&self, actual: &Self) -> Vec<&'static str> {
        match self {
            Self::None => Vec::new(),
            Self::Malformed { .. } => vec!["auth_format"],
            Self::Tauth2 { parameters } => match actual {
                Self::None => vec!["auth_presence"],
                Self::Malformed { .. } => vec!["auth_format"],
                Self::Tauth2 { parameters: actual } if parameters == actual => Vec::new(),
                Self::Tauth2 { .. } => vec!["auth_parameters"],
                Self::Other { .. } => vec!["auth_scheme"],
            },
            Self::Other { scheme } => match actual {
                Self::None => vec!["auth_presence"],
                Self::Malformed { .. } => vec!["auth_format"],
                other if other.scheme() == Some(scheme.as_str()) => Vec::new(),
                Self::Tauth2 { .. } | Self::Other { .. } => vec!["auth_scheme"],
            },
        }
    }

    fn parse(value: &str) -> Self {
        let value = value.trim();
        let (scheme, fields) = value
            .split_once(char::is_whitespace)
            .map_or((value, ""), |(scheme, fields)| (scheme, fields.trim()));
        let scheme = scheme.to_ascii_lowercase();
        if scheme.is_empty() {
            return Self::Malformed { scheme: None };
        }
        if scheme != "tauth2" {
            return Self::Other { scheme };
        }

        let Some(parameters) = tauth2_parameters(fields) else {
            return Self::Malformed {
                scheme: Some(scheme),
            };
        };
        Self::Tauth2 { parameters }
    }

    fn scheme(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Tauth2 { .. } => Some("tauth2"),
            Self::Other { scheme } => Some(scheme),
            Self::Malformed { scheme } => scheme.as_deref(),
        }
    }
}

impl fmt::Debug for Authentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("Authentication::None"),
            Self::Tauth2 { .. } => formatter.write_str("Authentication::Tauth2([REDACTED])"),
            Self::Other { scheme } => formatter
                .debug_struct("Authentication::Other")
                .field("scheme", scheme)
                .finish(),
            Self::Malformed { scheme } => formatter
                .debug_struct("Authentication::Malformed")
                .field("scheme", scheme)
                .finish(),
        }
    }
}

fn tauth2_parameters(fields: &str) -> Option<String> {
    let mut token = None;
    let mut parameters = None;
    let mut signature = None;
    for field in fields.split(',') {
        let (name, value) = field.trim().split_once('=')?;
        let value = value.strip_prefix('"')?.strip_suffix('"')?;
        if value.is_empty() {
            return None;
        }
        match name.trim() {
            "token" if token.is_none() => token = Some(value),
            "param" if parameters.is_none() => parameters = Some(value.to_owned()),
            "sign" if signature.is_none() => signature = Some(value),
            _ => return None,
        }
    }
    token?;
    signature?;
    parameters
}

#[cfg(test)]
mod tests {
    use motan_codec::{Attachment, Attachments};

    use super::*;

    fn auth(value: &str) -> Authentication {
        let mut attachments = Attachments::new();
        attachments.insert(Attachment::new(AUTHORIZATION_ATTACHMENT, value));
        Authentication::from_attachments(&attachments)
    }

    #[test]
    fn tauth2_ignores_dynamic_token_and_signature() {
        let source = auth("TAuth2 token=\"old\",param=\"uid%3D1\",sign=\"first\"");
        let target = auth("TAuth2 token=\"new\",param=\"uid%3D1\",sign=\"second\"");

        assert!(source.mismatch_fields(&target).is_empty());
        assert!(!format!("{source:?}").contains("old"));
    }

    #[test]
    fn reports_presence_scheme_parameter_and_format_mismatches() {
        let source = auth("TAuth2 token=\"old\",param=\"uid%3D1\",sign=\"first\"");

        assert_eq!(
            source.mismatch_fields(&Authentication::None),
            ["auth_presence"]
        );
        assert_eq!(
            source.mismatch_fields(&auth("Bearer credential")),
            ["auth_scheme"]
        );
        assert_eq!(
            source.mismatch_fields(&auth(
                "TAuth2 token=\"new\",param=\"uid%3D2\",sign=\"second\""
            )),
            ["auth_parameters"]
        );
        assert_eq!(
            source.mismatch_fields(&auth("TAuth2 token=\"new\"")),
            ["auth_format"]
        );
    }

    #[test]
    fn source_without_auth_does_not_reject_a_stricter_target() {
        let target = auth("TAuth2 token=\"new\",param=\"uid%3D1\",sign=\"second\"");

        assert!(Authentication::None.mismatch_fields(&target).is_empty());
    }
}
