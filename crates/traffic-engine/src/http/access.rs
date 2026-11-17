use hyper::Method;

use crate::access_policy::OperationClass;

pub(crate) fn classify_method(method: &Method) -> OperationClass {
    match method.as_str() {
        "GET" | "HEAD" | "OPTIONS" | "TRACE" => OperationClass::Read,
        "CONNECT" => OperationClass::Session,
        "POST" | "PUT" | "PATCH" | "DELETE" | "PROPPATCH" | "MKCOL" | "COPY" | "MOVE" | "LOCK"
        | "UNLOCK" | "PURGE" => OperationClass::Write,
        _ => OperationClass::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_standard_and_extension_methods() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
            assert_eq!(classify_method(&method), OperationClass::Read);
        }
        assert_eq!(classify_method(&Method::CONNECT), OperationClass::Session);
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert_eq!(classify_method(&method), OperationClass::Write);
        }
        assert_eq!(
            classify_method(&Method::from_bytes(b"PROPPATCH").unwrap()),
            OperationClass::Write
        );
        assert_eq!(
            classify_method(&Method::from_bytes(b"CUSTOM").unwrap()),
            OperationClass::Unknown
        );
    }
}
