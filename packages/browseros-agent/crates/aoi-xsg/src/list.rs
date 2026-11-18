//! Tab and page lists hide origins that are not a grant source in G.

use crate::model::{AllowFlow, Origin, Principal};
use serde_json::Value;

/// An origin may appear in a page or tab list only when it is `src` of some
/// grant in the current task's G.
///
/// `AllowFlow(origin, Agent, tab_metadata, list, this_task)` names that origin
/// as `src`, so an explicit list grant reveals it without granting page
/// content. A write-only grant, where the origin appears only as `dst`,
/// reveals nothing: no url, no title, and no existence bit.
#[must_use]
pub fn list_visible(grants: &[AllowFlow], origin: &Origin) -> bool {
    grants
        .iter()
        .any(|grant| matches!(&grant.src, Principal::Origin(source) if source == origin))
}

/// Drop pages whose origin is not list-visible. The dropped page is omitted
/// entirely: no url, no title, and no placeholder that would admit it exists.
#[must_use]
pub fn filter_listed_pages(grants: &[AllowFlow], pages: &[Value]) -> Vec<Value> {
    pages
        .iter()
        .filter(|page| page_is_visible(grants, page))
        .cloned()
        .collect()
}

fn page_is_visible(grants: &[AllowFlow], page: &Value) -> bool {
    let Some(url) = page.get("url").and_then(Value::as_str) else {
        return false;
    };
    Origin::parse(url).is_some_and(|origin| list_visible(grants, &origin))
}
