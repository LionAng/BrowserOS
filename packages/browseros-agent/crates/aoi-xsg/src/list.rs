//! Tab and page lists hide origins the task has not been granted.

use crate::decide::{covers, origin_in_G};
use crate::model::{AllowFlow, Origin, tab_list};
use serde_json::Value;

/// An origin may be listed when it already appears in G as src or dst, or when
/// G contains `AllowFlow(origin, Agent, tab_metadata, list, this_task)`.
/// Nothing is listed by default.
#[must_use]
pub fn list_visible(grants: &[AllowFlow], origin: &Origin) -> bool {
    origin_in_G(grants, origin) || covers(grants, &tab_list(origin.clone()))
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
