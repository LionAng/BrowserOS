//! Five-field cross-site grants. A missing field is not a wildcard.

use std::fmt;

/// The agent is a principal parallel to a site. It is not a site, and it is not
/// "the user".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
    Agent,
    Origin(Origin),
    /// Browser history is its own store. It is not implied by a page-content grant.
    BrowserHistory,
    /// Saved passwords. Distinct from a site origin.
    CredentialStore,
    /// Saved payment cards. Distinct from a site's pay action.
    PaymentStore,
}

/// `scheme + host + port`, with default ports omitted. Paths are not part of
/// the principal. `www.example` and `example` are different origins.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
}

impl Origin {
    /// Parse an absolute http(s) URL into its origin. Non-http(s) URLs, opaque
    /// origins, and unparseable strings are `None` (they do not become "any").
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        let url = url::Url::parse(input.trim()).ok()?;
        match url.origin() {
            url::Origin::Tuple(scheme, host, port) if scheme == "http" || scheme == "https" => {
                let default_port =
                    (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
                Some(Self {
                    scheme,
                    host: host.to_string(),
                    port: if default_port { None } else { Some(port) },
                })
            }
            _ => None,
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(port) => write!(formatter, "{}://{}:{port}", self.scheme, self.host),
            None => write!(formatter, "{}://{}", self.scheme, self.host),
        }
    }
}

/// Origin key for an http(s) URL, or `None` when a flow cannot name an origin.
#[must_use]
pub fn origin_of(url: &str) -> Option<String> {
    Origin::parse(url).map(|origin| origin.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataClass {
    PageContent,
    TabMetadata,
    Message,
    Event,
    Cart,
    Payment,
    Credentials,
    History,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionClass {
    Read,
    List,
    ComposeDraft,
    Send,
    CreateEvent,
    Delete,
    AddToCart,
    Pay,
    SetAddress,
}

/// Issued scope defaults to [`Scope::ThisTask`]. Any other scope is a different
/// grant, not a wider one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    ThisTask,
    Explicit(String),
}

/// A complete five-field grant. Equality is the only match. There is no subset
/// and no wildcard field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowFlow {
    pub src: Principal,
    pub dst: Principal,
    pub data_class: DataClass,
    pub action_class: ActionClass,
    pub scope: Scope,
}

impl AllowFlow {
    #[must_use]
    pub fn to_draft(&self) -> FlowDraft {
        FlowDraft {
            src: Some(self.src.clone()),
            dst: Some(self.dst.clone()),
            data_class: Some(self.data_class),
            action_class: Some(self.action_class),
            scope: Some(self.scope.clone()),
        }
    }
}

/// A grant someone tried to write down. Absent fields stay absent; they are
/// never filled with "any".
#[derive(Clone, Debug, Default)]
pub struct FlowDraft {
    pub src: Option<Principal>,
    pub dst: Option<Principal>,
    pub data_class: Option<DataClass>,
    pub action_class: Option<ActionClass>,
    pub scope: Option<Scope>,
}

#[must_use]
pub fn page_read(origin: Origin) -> AllowFlow {
    AllowFlow {
        src: Principal::Origin(origin),
        dst: Principal::Agent,
        data_class: DataClass::PageContent,
        action_class: ActionClass::Read,
        scope: Scope::ThisTask,
    }
}

#[must_use]
pub fn tab_list(origin: Origin) -> AllowFlow {
    AllowFlow {
        src: Principal::Origin(origin),
        dst: Principal::Agent,
        data_class: DataClass::TabMetadata,
        action_class: ActionClass::List,
        scope: Scope::ThisTask,
    }
}

#[must_use]
pub fn agent_to_origin(
    origin: Origin,
    data_class: DataClass,
    action_class: ActionClass,
) -> AllowFlow {
    AllowFlow {
        src: Principal::Agent,
        dst: Principal::Origin(origin),
        data_class,
        action_class,
        scope: Scope::ThisTask,
    }
}

#[must_use]
pub fn history_read() -> AllowFlow {
    AllowFlow {
        src: Principal::BrowserHistory,
        dst: Principal::Agent,
        data_class: DataClass::History,
        action_class: ActionClass::Read,
        scope: Scope::ThisTask,
    }
}

#[must_use]
pub fn credential_list() -> AllowFlow {
    AllowFlow {
        src: Principal::CredentialStore,
        dst: Principal::Agent,
        data_class: DataClass::Credentials,
        action_class: ActionClass::Read,
        scope: Scope::ThisTask,
    }
}

#[must_use]
pub fn payment_card_list() -> AllowFlow {
    AllowFlow {
        src: Principal::PaymentStore,
        dst: Principal::Agent,
        data_class: DataClass::Payment,
        action_class: ActionClass::Read,
        scope: Scope::ThisTask,
    }
}

/// Who is asking to change G. Only [`Issuer::User`] may issue or revoke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issuer {
    User,
    Page,
    Planner,
    Llm,
    SaveSkill,
    Helper,
    Agent,
}

/// Page, planner, LLM, `save_skill`, helper, and the agent itself cannot widen G.
#[must_use]
pub fn refuse_widen(issuer: Issuer) -> bool {
    !matches!(issuer, Issuer::User)
}
