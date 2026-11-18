//! Cross-site grant check. This is not an ownership check and not a per-site
//! Allow/Ask/Block list. Ownership stays a label. A call proceeds only when
//! [`aoi_xsg`] can name a five-field flow that the task's grants cover, when
//! the call is a list whose results will be filtered, or when `run` defers
//! each primitive to the inner hook.

use crate::api::mcp::dispatch::{ARBITRARY_SCRIPT_TOOLS, ToolCall, ToolGuard};
use aoi_xsg::{Decision, authorize_tool};
use browseros_mcp::ToolResult;
use futures_util::future::BoxFuture;
use tracing::warn;

pub fn guard(call: &ToolCall) -> BoxFuture<'_, Option<ToolResult>> {
    Box::pin(async move {
        let task = call.state.targets.canonical_task(&call.session_id).await;
        let grants = call.state.grants.load_G(task.as_str());
        let page_origin = call.page_snapshot.as_ref().map(|page| page.url.as_str());
        let decision = authorize_tool(&grants, call.tool().name, &call.raw_args, page_origin);
        let rejection = match decision {
            Decision::Allow | Decision::FilterList => None,
            Decision::DeferToInner => {
                if call.identity.is_some() && ARBITRARY_SCRIPT_TOOLS.contains(&call.tool().name) {
                    None
                } else {
                    Some("grant denied: script tool has no inner authorize hook".to_owned())
                }
            }
            Decision::Deny { reason } => Some(reason),
        };
        if let Some(reason) = rejection {
            warn!(
                tool = call.tool().name,
                session_id = %call.session_id,
                reason = %reason,
                "cockpit tool dispatch rejected"
            );
            return Some(ToolResult::error(reason));
        }
        None
    })
}

const _: ToolGuard = guard;

#[cfg(test)]
mod tests {
    use super::*;
    use aoi_xsg::{Issuer, page_read};
    use browseros_core::{PageId, TabId, TargetId};
    use rmcp::model::ContentBlock;
    use serde_json::json;

    fn text_of(result: &ToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|block| match block {
                ContentBlock::Text(text) => Some(text.text.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn outer_guard_denies_a_page_read_without_a_grant() -> anyhow::Result<()> {
        let mut call =
            crate::api::mcp::test_support::tool_call("snapshot", json!({ "page": 1 })).await?;
        call.page_snapshot = Some(browseros_core::pages::PageInfo {
            page_id: PageId(1),
            target_id: TargetId::from("t".to_owned()),
            tab_id: TabId(1),
            url: "https://news.example/story".to_owned(),
            title: "News".to_owned(),
            is_active: false,
            is_loading: false,
            load_progress: 1.0,
            is_pinned: false,
            window_id: None,
            index: None,
            group_id: None,
            browser_profile_id: None,
            live_browser_context_id: None,
        });
        let denied = guard(&call)
            .await
            .ok_or_else(|| anyhow::anyhow!("snapshot was allowed with an empty G"))?;
        assert!(text_of(&denied).contains("no matching AllowFlow"));
        let task = call.state.targets.canonical_task(&call.session_id).await;
        let origin = aoi_xsg::Origin::parse("https://news.example/story")
            .ok_or_else(|| anyhow::anyhow!("origin"))?;
        call.state
            .grants
            .issue_grant(Issuer::User, task.as_str(), page_read(origin).to_draft())?;
        assert!(guard(&call).await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn outer_guard_denies_evaluate_in_page_even_with_a_read_grant() -> anyhow::Result<()> {
        let mut call = crate::api::mcp::test_support::tool_call(
            "evaluate_in_page",
            json!({ "page": 1, "code": "return 1" }),
        )
        .await?;
        call.page_snapshot = Some(browseros_core::pages::PageInfo {
            page_id: PageId(1),
            target_id: TargetId::from("t".to_owned()),
            tab_id: TabId(1),
            url: "https://news.example/".to_owned(),
            title: String::new(),
            is_active: false,
            is_loading: false,
            load_progress: 1.0,
            is_pinned: false,
            window_id: None,
            index: None,
            group_id: None,
            browser_profile_id: None,
            live_browser_context_id: None,
        });
        let task = call.state.targets.canonical_task(&call.session_id).await;
        let origin = aoi_xsg::Origin::parse("https://news.example/")
            .ok_or_else(|| anyhow::anyhow!("origin"))?;
        call.state
            .grants
            .issue_grant(Issuer::User, task.as_str(), page_read(origin).to_draft())?;
        let denied = guard(&call)
            .await
            .ok_or_else(|| anyhow::anyhow!("evaluate_in_page was allowed"))?;
        assert!(text_of(&denied).contains("indistinguishable"));
        Ok(())
    }

    #[tokio::test]
    async fn outer_guard_defers_run_to_the_inner_hook() -> anyhow::Result<()> {
        let call =
            crate::api::mcp::test_support::tool_call("run", json!({ "code": "return 1" })).await?;
        assert!(call.identity.is_some());
        assert!(guard(&call).await.is_none());
        Ok(())
    }
}
