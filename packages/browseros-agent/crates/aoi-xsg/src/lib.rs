//! Agent-Origin Isolation with Explicit Cross-Site Grants (AOI-XSG).
//!
//! The agent is a principal parallel to a site. Power to move data from one
//! principal to another is a User-issued [`AllowFlow`] with five fields:
//! source, destination, data class, action class, and scope. Missing fields
//! are not wildcards. [`covers`] is equality on all five fields.
//!
//! This crate is the shared decision core. The host mediator calls it from the
//! outer grant guard and from the inner script hook; neither path may invent
//! a second policy.

mod decide;
mod list;
mod model;
mod store;

pub use decide::{
    Decision, REASON_CREDENTIALS_HISTORY, REASON_INDISTINGUISHABLE, REASON_NO_GRANT,
    REASON_UNCONSTRUCTED, authorize, authorize_tool, covers, enforce, origin_in_G,
};
pub use list::{filter_listed_pages, list_visible};
pub use model::{
    ActionClass, AllowFlow, DataClass, FlowDraft, Issuer, Origin, Principal, Scope,
    agent_to_origin, credential_list, history_read, origin_of, page_read, payment_card_list,
    refuse_widen, tab_list,
};
pub use store::{GrantError, GrantStore};

/// Grants for `task_id` only. An unknown task is empty and allows nothing.
#[allow(non_snake_case)]
#[must_use]
pub fn load_G(store: &GrantStore, task_id: &str) -> Vec<AllowFlow> {
    store.load_G(task_id)
}

#[cfg(test)]
mod tests;
