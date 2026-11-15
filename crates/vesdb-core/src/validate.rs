//! Input rules (mirroring EventSourcingDB 1.3) and error codes.

/// Error codes, rendered as `https://vesdb.dev/errors/<slug>`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    #[error("subject-missing")]
    SubjectMissing,
    #[error("subject-malformed")]
    SubjectMalformed,
    #[error("subject-too-long")]
    SubjectTooLong,
    #[error("subject-too-deep")]
    SubjectTooDeep,
    #[error("source-missing")]
    SourceMissing,
    #[error("source-malformed")]
    SourceMalformed,
    #[error("event-type-missing")]
    EventTypeMissing,
    #[error("event-type-malformed")]
    EventTypeMalformed,
    #[error("data-malformed")]
    DataMalformed,
    #[error("traceparent-malformed")]
    TraceparentMalformed,
    #[error("tracestate-malformed")]
    TracestateMalformed,
    #[error("tracestate-without-traceparent")]
    TracestateWithoutTraceparent,
    #[error("event-too-large")]
    EventTooLarge,
}

impl InputError {
    pub fn slug(&self) -> String {
        self.to_string()
    }
}

pub const MAX_SUBJECT_LEN: usize = 1024;
pub const MAX_SUBJECT_SEGMENTS: usize = 32;
pub const MAX_EVENT_BYTES: usize = 64 * 1024;

fn seg_ok(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Normalizes a trailing slash away. `/` is the root subject.
pub fn subject(s: &str) -> Result<String, InputError> {
    if s.is_empty() {
        return Err(InputError::SubjectMissing);
    }
    if !s.starts_with('/') {
        return Err(InputError::SubjectMalformed);
    }
    let norm = if s.len() > 1 {
        s.trim_end_matches('/')
    } else {
        s
    };
    let norm = if norm.is_empty() { "/" } else { norm };
    if norm.len() > MAX_SUBJECT_LEN {
        return Err(InputError::SubjectTooLong);
    }
    if norm == "/" {
        return Ok("/".into());
    }
    let segs: Vec<&str> = norm[1..].split('/').collect();
    if segs.len() > MAX_SUBJECT_SEGMENTS {
        return Err(InputError::SubjectTooDeep);
    }
    if !segs.iter().all(|s| seg_ok(s)) {
        return Err(InputError::SubjectMalformed);
    }
    Ok(norm.to_string())
}

/// At least three dot-separated segments `[A-Za-z0-9_-]+`, first ≥ 2 characters.
pub fn event_type(t: &str) -> Result<(), InputError> {
    if t.is_empty() {
        return Err(InputError::EventTypeMissing);
    }
    let segs: Vec<&str> = t.split('.').collect();
    if segs.len() < 3 || segs[0].len() < 2 || !segs.iter().all(|s| seg_ok(s)) {
        return Err(InputError::EventTypeMalformed);
    }
    Ok(())
}

/// Minimal RFC 3986 absolute-URI check: scheme ":" rest, no whitespace or control characters.
pub fn source(s: &str) -> Result<(), InputError> {
    if s.is_empty() {
        return Err(InputError::SourceMissing);
    }
    let Some((scheme, rest)) = s.split_once(':') else {
        return Err(InputError::SourceMalformed);
    };
    let scheme_ok = scheme
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
    if !scheme_ok
        || rest.is_empty()
        || s.chars()
            .any(|c| c.is_whitespace() || c.is_control() || !c.is_ascii())
    {
        return Err(InputError::SourceMalformed);
    }
    Ok(())
}

/// W3C traceparent `00-<32 hex>-<16 hex>-<2 hex>`, not all-zero ids. Rejects `-` (the compat
/// hash's absent marker), which keeps the compat encoding unambiguous.
pub fn traceparent(s: &str) -> Result<(), InputError> {
    let p: Vec<&str> = s.split('-').collect();
    let hexn = |x: &str, n: usize| {
        x.len() == n
            && x.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let ok = p.len() == 4
        && hexn(p[0], 2)
        && p[0] != "ff"
        && hexn(p[1], 32)
        && p[1] != "0".repeat(32)
        && hexn(p[2], 16)
        && p[2] != "0".repeat(16)
        && hexn(p[3], 2);
    if ok {
        Ok(())
    } else {
        Err(InputError::TraceparentMalformed)
    }
}

pub fn tracestate(s: &str) -> Result<(), InputError> {
    if s.is_empty()
        || s == "-"
        || s.len() > 512
        || s.chars().any(|c| c.is_control() || !c.is_ascii())
    {
        return Err(InputError::TracestateMalformed);
    }
    Ok(())
}

/// `data` must be a JSON object.
pub fn data(raw: &str) -> Result<(), InputError> {
    if raw.trim_start().starts_with('{') {
        Ok(())
    } else {
        Err(InputError::DataMalformed)
    }
}

/// Is `s` the subject `root` or (when `recursive`) below it?
pub fn under(subject: &str, root: &str, recursive: bool) -> bool {
    subject == root
        || (recursive
            && (root == "/"
                || subject
                    .strip_prefix(root)
                    .is_some_and(|r| r.starts_with('/'))))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rules() {
        assert_eq!(subject("/books/42/").unwrap(), "/books/42");
        assert_eq!(subject("/").unwrap(), "/");
        assert!(subject("books").is_err());
        assert!(subject("/a b").is_err());
        assert!(subject(&format!("/{}", vec!["a"; 33].join("/"))).is_err());
        assert!(event_type("io.example.book-acquired").is_ok());
        assert!(event_type("io.book-acquired").is_err());
        assert!(event_type("i.example.x").is_err());
        assert!(source("https://library.example").is_ok());
        assert!(source("tag:example.com,2026:x").is_ok());
        assert!(source("not a uri").is_err());
        assert!(traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_ok());
        assert!(traceparent("-").is_err());
        assert!(under("/books/42/pages/1", "/books/42", true));
        assert!(!under("/books/420", "/books/42", true));
        assert!(under("/x", "/", true));
    }
}
