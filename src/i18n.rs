//! Server translations (`locales/<lang>.json`, loaded with `rust-i18n`).
//!
//! Used for every text the server writes for people: emails and push
//! notifications. API error messages stay in English; clients translate
//! `error.<code>`. See `docs/I18N.md`.

use axum::http::HeaderMap;
use axum::http::header::ACCEPT_LANGUAGE;
use rust_i18n::t;

/// Fallback language (it has every key).
pub const DEFAULT: &str = "en";

/// Available languages (BCP 47 codes), sorted.
pub fn available() -> Vec<&'static str> {
    static LOCALES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    let all = LOCALES.get_or_init(|| {
        let mut v: Vec<String> = rust_i18n::available_locales!()
            .into_iter()
            .map(|l| l.into_owned())
            .collect();
        v.sort_unstable();
        v
    });
    all.iter().map(String::as_str).collect()
}

/// Name of a language in that language (`English`, `Español`).
pub fn language_name(locale: &str) -> String {
    t!("language.name", locale = locale).into_owned()
}

/// The available language that matches `tag` exactly (ignoring case and
/// `_` vs `-`), or by its primary subtag (`es-ES` → `es`).
pub fn supported(tag: &str) -> Option<&'static str> {
    let tag = tag.trim().replace('_', "-");
    if tag.is_empty() {
        return None;
    }
    let all = available();
    if let Some(l) = all.iter().find(|l| l.eq_ignore_ascii_case(&tag)) {
        return Some(l);
    }
    let primary = tag.split('-').next().unwrap_or_default();
    all.into_iter().find(|l| l.eq_ignore_ascii_case(primary))
}

/// Best available language from an `Accept-Language` header.
pub fn from_accept_language(headers: &HeaderMap) -> Option<&'static str> {
    let header = headers.get(ACCEPT_LANGUAGE)?.to_str().ok()?;
    let mut ranges: Vec<(&str, f32)> = header
        .split(',')
        .filter_map(|part| {
            let mut it = part.split(';');
            let tag = it.next()?.trim();
            let q = it
                .find_map(|p| p.trim().strip_prefix("q="))
                .and_then(|q| q.trim().parse::<f32>().ok())
                .unwrap_or(1.0);
            (!tag.is_empty() && tag != "*" && q > 0.0).then_some((tag, q))
        })
        .collect();
    // Stable sort: equal weights keep the header order.
    ranges.sort_by(|a, b| b.1.total_cmp(&a.1));
    ranges.into_iter().find_map(|(tag, _)| supported(tag))
}

/// A stored locale, or the default one if it is no longer available.
pub fn resolve(locale: &str) -> &'static str {
    supported(locale).unwrap_or(DEFAULT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_locales() {
        assert_eq!(supported("es"), Some("es"));
        assert_eq!(supported("ES-es"), Some("es"));
        assert_eq!(supported("en_GB"), Some("en"));
        assert_eq!(supported("xx"), None);
        assert_eq!(resolve("xx"), "en");
        assert_eq!(language_name("es"), "Español");
        assert_eq!(language_name("en"), "English");
    }

    #[test]
    fn parses_accept_language() {
        let mut h = HeaderMap::new();
        h.insert(
            ACCEPT_LANGUAGE,
            "fr-CH, fr;q=0.9, es;q=0.8, en;q=0.7".parse().unwrap(),
        );
        assert_eq!(from_accept_language(&h), Some("es"));
        h.insert(ACCEPT_LANGUAGE, "en;q=0.5, es-MX".parse().unwrap());
        assert_eq!(from_accept_language(&h), Some("es"));
        h.insert(ACCEPT_LANGUAGE, "de, *;q=0.1".parse().unwrap());
        assert_eq!(from_accept_language(&h), None);
    }

    #[test]
    fn every_language_has_every_key() {
        let en: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(include_str!("../locales/en.json")).unwrap();
        for lang in available() {
            let path = format!("{}/locales/{lang}.json", env!("CARGO_MANIFEST_DIR"));
            let other: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            for (key, value) in &en {
                let Some(text) = other.get(key).and_then(|v| v.as_str()) else {
                    // Missing keys fall back to English; only English must be complete.
                    assert_ne!(lang, "en", "missing key {key}");
                    continue;
                };
                let placeholders = |s: &str| {
                    let mut v: Vec<String> = s
                        .split("%{")
                        .skip(1)
                        .filter_map(|p| p.split('}').next().map(str::to_string))
                        .collect();
                    v.sort();
                    v
                };
                assert_eq!(
                    placeholders(value.as_str().unwrap()),
                    placeholders(text),
                    "{lang}: placeholders of {key}"
                );
            }
        }
    }
}
