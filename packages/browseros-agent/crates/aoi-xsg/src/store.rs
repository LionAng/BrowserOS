//! Grants are stored by task id. An unknown task is empty and allows nothing.

use crate::model::{AllowFlow, FlowDraft, Issuer, Scope, refuse_widen};
use std::collections::BTreeMap;
use std::sync::RwLock;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("grant denied: {0} cannot issue or widen G")]
    IssuerRefused(&'static str),
    #[error("grant denied: missing {0} is not a wildcard")]
    MissingField(&'static str),
}

#[derive(Debug, Default)]
pub struct GrantStore {
    by_task: RwLock<BTreeMap<String, Vec<AllowFlow>>>,
}

impl GrantStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Grants for this task only. An unknown task yields an empty set.
    #[allow(non_snake_case)]
    #[must_use]
    pub fn load_G(&self, task_id: &str) -> Vec<AllowFlow> {
        self.read().get(task_id).cloned().unwrap_or_default()
    }

    /// Insert one complete grant. Scope defaults to `this_task` when the draft
    /// omits it. Any other missing field refuses the write.
    pub fn issue_grant(
        &self,
        issuer: Issuer,
        task_id: &str,
        draft: FlowDraft,
    ) -> Result<AllowFlow, GrantError> {
        if refuse_widen(issuer) {
            return Err(GrantError::IssuerRefused(issuer_name(issuer)));
        }
        let flow = complete(draft)?;
        self.write()
            .entry(task_id.to_owned())
            .or_default()
            .push(flow.clone());
        Ok(flow)
    }

    /// Remove grants equal to `flow` on this task. Returns whether one was removed.
    pub fn revoke_grant(
        &self,
        issuer: Issuer,
        task_id: &str,
        flow: &AllowFlow,
    ) -> Result<bool, GrantError> {
        if refuse_widen(issuer) {
            return Err(GrantError::IssuerRefused(issuer_name(issuer)));
        }
        let mut tasks = self.write();
        let Some(grants) = tasks.get_mut(task_id) else {
            return Ok(false);
        };
        let before = grants.len();
        grants.retain(|grant| grant != flow);
        Ok(grants.len() != before)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, Vec<AllowFlow>>> {
        self.by_task.read().unwrap_or_else(|err| err.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<String, Vec<AllowFlow>>> {
        self.by_task.write().unwrap_or_else(|err| err.into_inner())
    }
}

fn complete(draft: FlowDraft) -> Result<AllowFlow, GrantError> {
    Ok(AllowFlow {
        src: draft.src.ok_or(GrantError::MissingField("src"))?,
        dst: draft.dst.ok_or(GrantError::MissingField("dst"))?,
        data_class: draft
            .data_class
            .ok_or(GrantError::MissingField("data_class"))?,
        action_class: draft
            .action_class
            .ok_or(GrantError::MissingField("action_class"))?,
        scope: draft.scope.unwrap_or(Scope::ThisTask),
    })
}

fn issuer_name(issuer: Issuer) -> &'static str {
    match issuer {
        Issuer::User => "user",
        Issuer::Page => "page",
        Issuer::Planner => "planner",
        Issuer::Llm => "llm",
        Issuer::SaveSkill => "save_skill",
        Issuer::Helper => "helper",
        Issuer::Agent => "agent",
    }
}
