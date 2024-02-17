//! Minimal helpers for the flat, attribute-free XML documents used by
//! pkeyconfig files and the activation service. A full DOM is not needed and
//! plain substring scanning is considerably faster on 400 KB+ configs.

use std::borrow::Cow;

/// Iterate over the inner content of every `<tag>...</tag>` element.
pub fn elements<'a>(doc: &'a str, tag: &str) -> impl Iterator<Item = &'a str> + 'a {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut rest = doc;
    std::iter::from_fn(move || {
        let start = rest.find(&open)? + open.len();
        let len = rest[start..].find(&close)?;
        let inner = &rest[start..start + len];
        rest = &rest[start + len + close.len()..];
        Some(inner)
    })
}

/// Inner content of the first `<tag>...</tag>` element.
pub fn element<'a>(doc: &'a str, tag: &str) -> Option<&'a str> {
    elements(doc, tag).next()
}

/// Trimmed, unescaped text of the first `<tag>` element.
pub fn text(doc: &str, tag: &str) -> Option<String> {
    element(doc, tag).map(|s| unescape(s.trim()).into_owned())
}

/// Remove namespace prefixes from element names (`<pkc:Foo>` -> `<Foo>`,
/// `</ns1:Foo>` -> `</Foo>`), so documents can be scanned by local name.
pub fn strip_prefixes(doc: &str) -> Cow<'_, str> {
    let bytes = doc.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let name_start = if bytes.get(i + 1) == Some(&b'/') { i + 2 } else { i + 1 };
            let mut j = name_start;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'-' || bytes[j] == b'.') {
                j += 1;
            }
            if j > name_start && bytes.get(j) == Some(&b':') {
                let o = out.get_or_insert_with(|| String::with_capacity(doc.len()));
                o.push_str(&doc[copied..name_start]);
                copied = j + 1;
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    match out {
        Some(mut o) => {
            o.push_str(&doc[copied..]);
            Cow::Owned(o)
        }
        None => Cow::Borrowed(doc),
    }
}

pub fn unescape(s: &str) -> Cow<'_, str> {
    quick_xml::escape::unescape(s).unwrap_or(Cow::Borrowed(s))
}

pub fn escape(s: &str) -> Cow<'_, str> {
    quick_xml::escape::escape(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_elements() {
        let doc = "<a><b>1</b><b> 2 </b><c>&lt;x&gt;</c></a>";
        assert_eq!(elements(doc, "b").collect::<Vec<_>>(), vec!["1", " 2 "]);
        assert_eq!(text(doc, "c").as_deref(), Some("<x>"));
        assert_eq!(element(doc, "d"), None);
        assert_eq!(strip_prefixes("<a:b x=\"1:2\"><c>t:u</c></a:b>"), "<b x=\"1:2\"><c>t:u</c></b>");
    }
}
