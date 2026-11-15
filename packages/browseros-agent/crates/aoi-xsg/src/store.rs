//! Grants are stored by task id. An unknown task is empty and allows nothing.

use crate::model::{AllowFlow, FlowDraft, Issuer, Scope, refuse_widen};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::RwLock,
};
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("grant denied: {0} cannot issue or widen G")]
    IssuerRefused(&'static str),
    #[error("grant denied: missing {0} is not a wildcard")]
    MissingField(&'static str),
    #[error("grant storage error: {0}")]
    Storage(String),
}

type GrantsByTask = BTreeMap<String, Vec<AllowFlow>>;

#[derive(Debug)]
pub struct GrantStore {
    backend: Backend,
}

#[derive(Debug)]
enum Backend {
    Memory(RwLock<GrantsByTask>),
    File { path: PathBuf, lock_path: PathBuf },
}

impl Default for GrantStore {
    fn default() -> Self {
        Self {
            backend: Backend::Memory(RwLock::default()),
        }
    }
}

impl GrantStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a store in an existing local state directory. A missing file starts empty.
    pub fn open(path: PathBuf) -> io::Result<Self> {
        read_file(&path)?;
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        Ok(Self {
            backend: Backend::File {
                path,
                lock_path: lock_path.into(),
            },
        })
    }

    /// Grants for this task only. An unknown task or a failed disk read yields an empty set.
    #[allow(non_snake_case)]
    #[must_use]
    pub fn load_G(&self, task_id: &str) -> Vec<AllowFlow> {
        match &self.backend {
            Backend::Memory(tasks) => tasks
                .read()
                .unwrap_or_else(|error| error.into_inner())
                .get(task_id)
                .cloned()
                .unwrap_or_default(),
            Backend::File { path, .. } => read_file(path)
                .ok()
                .and_then(|mut tasks| tasks.remove(task_id))
                .unwrap_or_default(),
        }
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
        self.update(|tasks| {
            let grants = tasks.entry(task_id.to_owned()).or_default();
            if grants.contains(&flow) {
                return ((), false);
            }
            grants.push(flow.clone());
            ((), true)
        })?;
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
        self.update(|tasks| {
            let Some(grants) = tasks.get_mut(task_id) else {
                return (false, false);
            };
            let before = grants.len();
            grants.retain(|grant| grant != flow);
            let revoked = grants.len() != before;
            if grants.is_empty() {
                tasks.remove(task_id);
            }
            (revoked, revoked)
        })
    }

    fn update<T>(
        &self,
        change: impl FnOnce(&mut GrantsByTask) -> (T, bool),
    ) -> Result<T, GrantError> {
        match &self.backend {
            Backend::Memory(tasks) => {
                let mut tasks = tasks.write().unwrap_or_else(|error| error.into_inner());
                Ok(change(&mut tasks).0)
            }
            Backend::File { path, lock_path } => {
                // Lock a separate file so the lock survives replacement of the snapshot.
                let update = || -> io::Result<T> {
                    let lock = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(lock_path)?;
                    lock.lock()?;
                    let mut tasks = read_file(path)?;
                    let (result, changed) = change(&mut tasks);
                    if changed {
                        write_file(path, &tasks)?;
                    }
                    Ok(result)
                };
                update().map_err(|error| GrantError::Storage(error.to_string()))
            }
        }
    }
}

fn read_file(path: &Path) -> io::Result<GrantsByTask> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::from),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(GrantsByTask::new()),
        Err(error) => Err(error),
    }
}

fn write_file(path: &Path, tasks: &GrantsByTask) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent)?;
    serde_json::to_writer(temporary.as_file_mut(), tasks)?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
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
