//! Shared decisions. `covers` is five-field equality. A flow that cannot be
//! built is denied. An ambiguous write class is denied rather than guessed.

use crate::model::{
    ActionClass, AllowFlow, DataClass, Origin, Principal, agent_to_origin, credential_list,
    history_read, page_read, payment_card_list, tab_list,
};
use serde_json::Value;

pub const REASON_NO_GRANT: &str = "grant denied: no matching AllowFlow";
pub const REASON_UNCONSTRUCTED: &str = "grant denied: flow cannot be constructed";
pub const REASON_INDISTINGUISHABLE: &str = "grant denied: write class is indistinguishable";
pub const REASON_CREDENTIALS_HISTORY: &str =
    "grant denied: history and credentials stay default-deny until specified";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// The call may run. Its page list must pass [`crate::filter_listed_pages`].
    /// This is not permission to see every origin.
    FilterList,
    /// `run` has no single flow. Each inner primitive is authorized on its own.
    DeferToInner,
    Deny {
        reason: String,
    },
}

/// Equality on all five fields. One differing field is a miss, not a partial hit.
#[must_use]
pub fn covers(grants: &[AllowFlow], flow: &AllowFlow) -> bool {
    grants.iter().any(|grant| grant == flow)
}

/// `None` means the flow could not be constructed and is denied.
#[must_use]
pub fn enforce(grants: &[AllowFlow], flow: Option<&AllowFlow>) -> Decision {
    match flow {
        Some(flow) if covers(grants, flow) => Decision::Allow,
        Some(_) => Decision::Deny {
            reason: REASON_NO_GRANT.to_owned(),
        },
        None => Decision::Deny {
            reason: REASON_UNCONSTRUCTED.to_owned(),
        },
    }
}

/// True when `origin` is the source or destination of any grant in G.
#[allow(non_snake_case)]
#[must_use]
pub fn origin_in_G(grants: &[AllowFlow], origin: &Origin) -> bool {
    grants.iter().any(|grant| {
        principal_is_origin(&grant.src, origin) || principal_is_origin(&grant.dst, origin)
    })
}

fn principal_is_origin(principal: &Principal, origin: &Origin) -> bool {
    matches!(principal, Principal::Origin(granted) if granted == origin)
}

/// Authorize one primitive by method name and target origin.
///
/// `origin` is `None` when the call has no page or the page's URL is not an
/// http(s) origin. That is a deny, except for `pages.list` (results are
/// filtered) and host-local helper/window calls that do not disclose a site.
#[must_use]
pub fn authorize(grants: &[AllowFlow], method: &str, origin: Option<&str>) -> Decision {
    let origin = origin.and_then(Origin::parse);
    authorize_method(grants, method, origin.as_ref())
}

/// Outer tool decision. `page_origin` is the current page URL when the call
/// addresses one. Destination URLs on navigate / tabs-new win over that page.
#[must_use]
pub fn authorize_tool(
    grants: &[AllowFlow],
    tool: &str,
    args: &Value,
    page_origin: Option<&str>,
) -> Decision {
    match tool {
        "run" => Decision::DeferToInner,
        "tabs" => authorize_tabs(grants, args, page_origin),
        "navigate" => {
            let url = args.get("url").and_then(Value::as_str);
            let origin = url
                .and_then(Origin::parse)
                .or_else(|| page_origin.and_then(Origin::parse));
            match origin {
                Some(origin) => enforce(grants, Some(&page_read(origin))),
                None => Decision::Deny {
                    reason: format!(
                        "{REASON_UNCONSTRUCTED} for navigate {}",
                        url.unwrap_or("(no url)")
                    ),
                },
            }
        }
        "history" => enforce_specified(grants, &history_read(), REASON_CREDENTIALS_HISTORY),
        "credentials" => authorize_credentials(grants, args.get("action").and_then(Value::as_str)),
        "payment_cards" => authorize_cards(grants, args.get("action").and_then(Value::as_str)),
        "act" | "upload" | "evaluate_in_page" => indistinguishable(),
        "read_output" | "windows" | "tab_groups" | "browser_profiles" | "browser_target" => {
            Decision::Allow
        }
        "snapshot" | "diff" | "read" | "grep" | "screenshot" | "pdf" | "wait" | "download"
        | "setViewport" => match page_origin.and_then(Origin::parse) {
            Some(origin) => enforce(grants, Some(&page_read(origin))),
            None => Decision::Deny {
                reason: format!("{REASON_UNCONSTRUCTED} for {tool}"),
            },
        },
        other => Decision::Deny {
            reason: format!("{REASON_UNCONSTRUCTED} for {other}"),
        },
    }
}

fn authorize_tabs(grants: &[AllowFlow], args: &Value, page_origin: Option<&str>) -> Decision {
    match args.get("action").and_then(Value::as_str).unwrap_or("list") {
        "list" => Decision::FilterList,
        "new" => {
            let url = args.get("url").and_then(Value::as_str).unwrap_or("");
            match Origin::parse(url) {
                Some(origin) => enforce(grants, Some(&page_read(origin))),
                None => Decision::Deny {
                    reason: format!("{REASON_UNCONSTRUCTED} for tabs new {url}"),
                },
            }
        }
        "active" => match page_origin.and_then(Origin::parse) {
            Some(origin) => {
                if origin_in_G(grants, &origin) || covers(grants, &tab_list(origin)) {
                    Decision::Allow
                } else {
                    Decision::Deny {
                        reason: REASON_NO_GRANT.to_owned(),
                    }
                }
            }
            None => Decision::Deny {
                reason: format!("{REASON_UNCONSTRUCTED} for tabs active"),
            },
        },
        other => Decision::Deny {
            reason: format!("{REASON_UNCONSTRUCTED} for tabs {other}"),
        },
    }
}

fn authorize_method(grants: &[AllowFlow], method: &str, origin: Option<&Origin>) -> Decision {
    if method == "pages.list" {
        return Decision::FilterList;
    }
    if is_host_local(method) {
        return Decision::Allow;
    }
    if is_indistinguishable(method) {
        return indistinguishable();
    }
    if let Some(decision) = classify_named_write(grants, method, origin) {
        return decision;
    }
    if is_history(method) {
        return enforce_specified(grants, &history_read(), REASON_CREDENTIALS_HISTORY);
    }
    if let Some(action) = method.strip_prefix("tool:credentials:") {
        return authorize_credentials(grants, Some(action));
    }
    if let Some(action) = method.strip_prefix("credentials:") {
        return authorize_credentials(grants, Some(action));
    }
    if let Some(action) = method.strip_prefix("tool:payment_cards:") {
        return authorize_cards(grants, Some(action));
    }
    if let Some(action) = method.strip_prefix("payment_cards:") {
        return authorize_cards(grants, Some(action));
    }
    if let Some(cdp) = cdp_method(method) {
        return authorize_cdp(grants, cdp, origin);
    }
    if is_page_read(method) {
        return match origin {
            Some(origin) => enforce(grants, Some(&page_read(origin.clone()))),
            None => Decision::Deny {
                reason: format!("{REASON_UNCONSTRUCTED} for {method}"),
            },
        };
    }
    Decision::Deny {
        reason: format!("{REASON_UNCONSTRUCTED} for {method}"),
    }
}

fn authorize_cdp(grants: &[AllowFlow], cdp: &str, origin: Option<&Origin>) -> Decision {
    if cdp.is_empty() {
        return Decision::Deny {
            reason: format!("{REASON_UNCONSTRUCTED} for cdp"),
        };
    }
    if matches!(
        cdp,
        "Runtime.evaluate" | "Runtime.callFunctionOn" | "Page.addScriptToEvaluateOnNewDocument"
    ) || cdp.starts_with("Input.")
    {
        return indistinguishable();
    }
    const CDP_READ: &[&str] = &[
        "Page.getFrameTree",
        "Page.captureScreenshot",
        "Page.getLayoutMetrics",
        "DOM.getDocument",
        "DOM.describeNode",
        "DOM.getOuterHTML",
        "Accessibility.getFullAXTree",
    ];
    if CDP_READ.contains(&cdp) {
        return match origin {
            Some(origin) => enforce(grants, Some(&page_read(origin.clone()))),
            None => Decision::Deny {
                reason: format!("{REASON_UNCONSTRUCTED} for cdp:{cdp}"),
            },
        };
    }
    Decision::Deny {
        reason: format!("{REASON_UNCONSTRUCTED} for cdp:{cdp}"),
    }
}

fn cdp_method(method: &str) -> Option<&str> {
    method
        .strip_prefix("cdpJsonForPage:")
        .or_else(|| method.strip_prefix("cdp:"))
}

fn authorize_credentials(grants: &[AllowFlow], action: Option<&str>) -> Decision {
    match action {
        Some("list") => enforce_specified(grants, &credential_list(), REASON_CREDENTIALS_HISTORY),
        _ => Decision::Deny {
            reason: REASON_CREDENTIALS_HISTORY.to_owned(),
        },
    }
}

fn authorize_cards(grants: &[AllowFlow], action: Option<&str>) -> Decision {
    match action {
        Some("list") => enforce_specified(grants, &payment_card_list(), REASON_CREDENTIALS_HISTORY),
        _ => Decision::Deny {
            reason: REASON_CREDENTIALS_HISTORY.to_owned(),
        },
    }
}

/// Precise cross-site writes the classifier can name. A composite method that
/// could be more than one class in a precision group returns `None` from the
/// flow and is denied here.
fn classify_named_write(
    grants: &[AllowFlow],
    method: &str,
    origin: Option<&Origin>,
) -> Option<Decision> {
    let flow = match method {
        "mail.compose_draft" => Some((DataClass::Message, ActionClass::ComposeDraft)),
        "mail.send" => Some((DataClass::Message, ActionClass::Send)),
        "calendar.create_event" => Some((DataClass::Event, ActionClass::CreateEvent)),
        "calendar.delete" => Some((DataClass::Event, ActionClass::Delete)),
        "shop.add_to_cart" => Some((DataClass::Cart, ActionClass::AddToCart)),
        "shop.pay" => Some((DataClass::Payment, ActionClass::Pay)),
        "shop.set_address" => Some((DataClass::Payment, ActionClass::SetAddress)),
        "mail.read" => {
            return Some(match origin {
                Some(origin) => enforce(
                    grants,
                    Some(&AllowFlow {
                        src: Principal::Origin(origin.clone()),
                        dst: Principal::Agent,
                        data_class: DataClass::Message,
                        action_class: ActionClass::Read,
                        scope: crate::model::Scope::ThisTask,
                    }),
                ),
                None => unconstructed(method),
            });
        }
        "mail.compose_or_send" | "calendar.create_or_delete" | "shop.cart_or_pay" => {
            return Some(indistinguishable());
        }
        _ => None,
    }?;
    let (data_class, action_class) = flow;
    Some(match origin {
        Some(origin) => enforce(
            grants,
            Some(&agent_to_origin(origin.clone(), data_class, action_class)),
        ),
        None => unconstructed(method),
    })
}

fn enforce_specified(grants: &[AllowFlow], flow: &AllowFlow, reason: &str) -> Decision {
    if covers(grants, flow) {
        Decision::Allow
    } else {
        Decision::Deny {
            reason: reason.to_owned(),
        }
    }
}

fn indistinguishable() -> Decision {
    Decision::Deny {
        reason: REASON_INDISTINGUISHABLE.to_owned(),
    }
}

fn unconstructed(method: &str) -> Decision {
    Decision::Deny {
        reason: format!("{REASON_UNCONSTRUCTED} for {method}"),
    }
}

fn is_history(method: &str) -> bool {
    matches!(method, "history" | "tool:history" | "browser.history")
}

fn is_host_local(method: &str) -> bool {
    matches!(
        method,
        "helpers.save"
            | "helpers.list"
            | "helpers.read"
            | "tool:windows"
            | "tool:tab_groups"
            | "tool:browser_profiles"
            | "tool:browser_target"
            | "tool:read_output"
    )
}

fn is_indistinguishable(method: &str) -> bool {
    method.starts_with("input.")
        || matches!(
            method,
            "act"
                | "tool:act"
                | "upload"
                | "tool:upload"
                | "evaluate_in_page"
                | "tool:evaluate_in_page"
        )
}

fn is_page_read(method: &str) -> bool {
    matches!(
        method,
        "observe.snapshot"
            | "observe.diff"
            | "observe.resolveRef"
            | "pages.getInfo"
            | "pages.newPage"
            | "nav.goto"
            | "nav.back"
            | "nav.forward"
            | "nav.reload"
            | "snapshot"
            | "diff"
            | "read"
            | "grep"
            | "screenshot"
            | "pdf"
            | "wait"
            | "navigate"
            | "download"
            | "setViewport"
            | "viewport.set"
            | "tool:snapshot"
            | "tool:diff"
            | "tool:read"
            | "tool:grep"
            | "tool:screenshot"
            | "tool:pdf"
            | "tool:wait"
            | "tool:navigate"
            | "tool:download"
            | "tool:setViewport"
    )
}
