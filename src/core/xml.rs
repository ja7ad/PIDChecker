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
