use crate::{
    ActionClass, AllowFlow, DataClass, Decision, FlowDraft, GrantStore, Issuer, Origin, Principal,
    Scope, agent_to_origin, authorize, authorize_tool, covers, credential_list, enforce,
    filter_listed_pages, history_read, load_G, page_read, refuse_widen, tab_list,
};
use serde_json::json;

fn origin(url: &str) -> Origin {
    Origin::parse(url).unwrap_or_else(|| panic!("origin {url}"))
}

fn store_with(task: &str, flows: &[AllowFlow]) -> GrantStore {
    let store = GrantStore::new();
    for flow in flows {
        store
            .issue_grant(Issuer::User, task, flow.to_draft())
            .unwrap_or_else(|err| panic!("{err}"));
    }
    store
}

fn allow(grants: &[AllowFlow], method: &str, url: &str) -> bool {
    authorize(grants, method, Some(url)) == Decision::Allow
}

#[test]
fn covers_is_equality_on_all_five_fields() {
    let news = origin("https://news.example/story");
    let flow = page_read(news.clone());
    let grants = [flow.clone()];
    assert!(covers(&grants, &flow));
    assert!(!covers(
        &grants,
        &AllowFlow {
            action_class: ActionClass::List,
            ..flow.clone()
        }
    ));
    assert!(!covers(
        &grants,
        &AllowFlow {
            data_class: DataClass::Message,
            ..flow.clone()
        }
    ));
    assert!(!covers(
        &grants,
        &AllowFlow {
            dst: Principal::Origin(news.clone()),
            ..flow.clone()
        }
    ));
    assert!(!covers(
        &grants,
        &AllowFlow {
            src: Principal::Agent,
            ..flow.clone()
        }
    ));
    assert!(!covers(
        &grants,
        &AllowFlow {
            scope: Scope::Explicit("later".to_owned()),
            ..flow
        }
    ));
}

#[test]
fn missing_field_is_not_a_wildcard_and_scope_defaults_to_this_task() {
    let store = GrantStore::new();
    let news = origin("https://news.example/");
    let err = match store.issue_grant(
        Issuer::User,
        "task",
        FlowDraft {
            src: Some(Principal::Origin(news.clone())),
            dst: Some(Principal::Agent),
            data_class: None,
            action_class: Some(ActionClass::Read),
            scope: None,
        },
    ) {
        Err(err) => err,
        Ok(_) => panic!("missing data class was stored"),
    };
    assert!(err.to_string().contains("missing data_class"));
    assert!(load_G(&store, "task").is_empty());

    let issued = store
        .issue_grant(Issuer::User, "task", page_read(news.clone()).to_draft())
        .unwrap_or_else(|err| panic!("{err}"));
    // The draft carried scope: Some(ThisTask) via to_draft. Issue another with scope omitted.
    let mut omitted = page_read(news).to_draft();
    omitted.scope = None;
    let defaulted = store
        .issue_grant(Issuer::User, "task", omitted)
        .unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(issued.scope, Scope::ThisTask);
    assert_eq!(defaulted.scope, Scope::ThisTask);
    assert!(enforce(&load_G(&store, "task"), Some(&defaulted)) == Decision::Allow);
    assert!(
        enforce(&load_G(&store, "no-such-task"), Some(&defaulted))
            == Decision::Deny {
                reason: crate::REASON_NO_GRANT.to_owned()
            }
    );
}

#[test]
fn issuance_and_revocation_require_a_user() {
    let store = GrantStore::new();
    let flow = page_read(origin("https://news.example/"));
    for issuer in [
        Issuer::Page,
        Issuer::Planner,
        Issuer::Llm,
        Issuer::SaveSkill,
        Issuer::Helper,
        Issuer::Agent,
    ] {
        assert!(refuse_widen(issuer));
        assert!(store.issue_grant(issuer, "task", flow.to_draft()).is_err());
        assert!(store.revoke_grant(issuer, "task", &flow).is_err());
    }
    assert!(!refuse_widen(Issuer::User));
    store
        .issue_grant(Issuer::User, "task", flow.to_draft())
        .unwrap_or_else(|err| panic!("{err}"));
    assert!(covers(&load_G(&store, "task"), &flow));
    assert!(
        store
            .revoke_grant(Issuer::User, "task", &flow)
            .unwrap_or_else(|err| panic!("{err}"))
    );
    assert!(!covers(&load_G(&store, "task"), &flow));
}

#[test]
fn load_g_does_not_leak_across_tasks() {
    let store = store_with("alpha", &[page_read(origin("https://news.example/"))]);
    assert!(load_G(&store, "beta").is_empty());
    assert_eq!(load_G(&store, "alpha").len(), 1);
    assert!(
        authorize(
            &load_G(&store, "beta"),
            "observe.snapshot",
            Some("https://news.example/")
        ) != Decision::Allow
    );
}

#[test]
fn list_omits_unauthorized_origins_entirely() {
    let news = origin("https://news.example/a");
    let grants = [page_read(news)];
    let pages = [
        json!({"pageId": 1, "url": "https://news.example/a", "title": "News"}),
        json!({"pageId": 2, "url": "https://bank.example/home", "title": "Bank"}),
        json!({"pageId": 3, "title": "no url"}),
        json!({"pageId": 4, "url": "about:blank", "title": "blank"}),
    ];
    let visible = filter_listed_pages(&grants, &pages);
    let rendered = serde_json::to_string(&visible).unwrap_or_default();
    assert_eq!(visible.len(), 1);
    assert!(rendered.contains("news.example"));
    assert!(!rendered.contains("bank"));
    assert!(!rendered.contains("no url"));
    assert!(!rendered.contains("blank"));
    assert!(!rendered.contains("pageId\":2") && !rendered.contains("\"pageId\":2"));
}

#[test]
fn explicit_list_grant_reveals_an_origin_that_is_not_otherwise_in_g() {
    let shop = origin("https://shop.example/");
    let grants = [tab_list(shop)];
    let pages = [json!({"url": "https://shop.example/cart", "title": "Cart"})];
    assert_eq!(filter_listed_pages(&grants, &pages).len(), 1);
}

#[test]
fn write_classes_that_cannot_be_distinguished_are_denied() {
    let mail = origin("https://mail.example/");
    let grants = [
        agent_to_origin(mail.clone(), DataClass::Message, ActionClass::ComposeDraft),
        agent_to_origin(mail.clone(), DataClass::Message, ActionClass::Send),
    ];
    assert_eq!(
        authorize(
            &grants,
            "mail.compose_or_send",
            Some("https://mail.example/")
        ),
        Decision::Deny {
            reason: crate::REASON_INDISTINGUISHABLE.to_owned()
        }
    );
    assert!(allow(
        &grants,
        "mail.compose_draft",
        "https://mail.example/"
    ));
    assert!(allow(&grants, "mail.send", "https://mail.example/"));
    let _ = mail;
}

#[test]
fn history_and_credentials_stay_denied_until_the_precise_grant_exists() {
    let empty = [];
    assert!(matches!(
        authorize(&empty, "history", None),
        Decision::Deny { .. }
    ));
    assert!(matches!(
        authorize(&empty, "tool:credentials:list", None),
        Decision::Deny { .. }
    ));
    assert!(matches!(
        authorize(&empty, "tool:credentials:fill", None),
        Decision::Deny { .. }
    ));
    let specified = [history_read(), credential_list()];
    assert_eq!(authorize(&specified, "history", None), Decision::Allow);
    assert_eq!(
        authorize(&specified, "tool:credentials:list", None),
        Decision::Allow
    );
    assert!(matches!(
        authorize(&specified, "tool:credentials:add", None),
        Decision::Deny { .. }
    ));
}

#[test]
fn page_absent_primitives_do_not_silently_allow() {
    let grants = [page_read(origin("https://news.example/"))];
    for method in [
        "cdp:",
        "cdpJsonForPage:",
        "pages.newPage",
        "cdp:Page.getFrameTree",
    ] {
        assert!(
            matches!(authorize(&grants, method, None), Decision::Deny { .. }),
            "{method}"
        );
    }
    assert_eq!(authorize(&grants, "pages.list", None), Decision::FilterList);
    assert!(matches!(
        authorize(&grants, "tool:evaluate_in_page", Some("https://news.example/")),
        Decision::Deny { reason } if reason == crate::REASON_INDISTINGUISHABLE
    ));
    assert_eq!(
        authorize(
            &grants,
            "cdp:Page.getFrameTree",
            Some("https://news.example/home")
        ),
        Decision::Allow
    );
    assert!(matches!(
        authorize(&grants, "cdp:Runtime.evaluate", Some("https://news.example/")),
        Decision::Deny { reason } if reason == crate::REASON_INDISTINGUISHABLE
    ));
}

#[test]
fn outer_tool_policy_defers_run_and_denies_unclassified_writes() {
    let grants = [page_read(origin("https://news.example/"))];
    assert_eq!(
        authorize_tool(&grants, "run", &json!({}), None),
        Decision::DeferToInner
    );
    assert!(matches!(
        authorize_tool(&grants, "evaluate_in_page", &json!({"page": 1}), Some("https://news.example/")),
        Decision::Deny { reason } if reason == crate::REASON_INDISTINGUISHABLE
    ));
    assert!(matches!(
        authorize_tool(
            &grants,
            "act",
            &json!({"kind": "click"}),
            Some("https://news.example/")
        ),
        Decision::Deny { .. }
    ));
    assert_eq!(
        authorize_tool(&grants, "tabs", &json!({"action": "list"}), None),
        Decision::FilterList
    );
    assert_eq!(
        authorize_tool(&[], "read_output", &json!({}), None),
        Decision::Allow
    );
    assert!(matches!(
        authorize_tool(&[], "navigate", &json!({"url": "javascript:alert(1)"}), None),
        Decision::Deny { reason } if reason.contains("javascript:alert(1)")
    ));
    assert_eq!(
        authorize_tool(
            &grants,
            "snapshot",
            &json!({"page": 1}),
            Some("https://news.example/item")
        ),
        Decision::Allow
    );
}

#[test]
fn scenario_rows_match_the_hook_contract() {
    // The hook layer replays these method names. Keeping the decisions here
    // makes a mediator that stops calling `authorize` fail this crate, and a
    // hook that invents its own matcher fail the server test.
    let news = "https://news.example/story";
    let mail = "https://mail.example/inbox";
    let calendar = "https://calendar.example/week";
    let shop_a = "https://shop-a.example/item";
    let shop_b = "https://shop-b.example/item";
    let bank = "https://bank.example/";
    let mut grants = vec![
        page_read(origin(news)),
        agent_to_origin(origin(mail), DataClass::Message, ActionClass::ComposeDraft),
    ];
    assert!(allow(&grants, "observe.snapshot", news));
    assert!(allow(&grants, "mail.compose_draft", mail));
    assert!(!allow(&grants, "mail.send", mail));

    let wrong_scope = AllowFlow {
        scope: Scope::Explicit("next-task".to_owned()),
        ..agent_to_origin(origin(mail), DataClass::Message, ActionClass::Send)
    };
    grants.push(wrong_scope);
    assert!(!allow(&grants, "mail.send", mail));

    grants.push(AllowFlow {
        src: Principal::Origin(origin(mail)),
        dst: Principal::Agent,
        data_class: DataClass::Message,
        action_class: ActionClass::Read,
        scope: Scope::ThisTask,
    });
    grants.push(agent_to_origin(
        origin(calendar),
        DataClass::Event,
        ActionClass::CreateEvent,
    ));
    assert!(allow(&grants, "mail.read", mail));
    assert!(allow(&grants, "calendar.create_event", calendar));
    assert!(!allow(&grants, "calendar.delete", calendar));

    grants.push(page_read(origin(shop_a)));
    grants.push(page_read(origin(shop_b)));
    grants.push(agent_to_origin(
        origin(shop_a),
        DataClass::Cart,
        ActionClass::AddToCart,
    ));
    assert!(allow(&grants, "observe.snapshot", shop_a));
    assert!(allow(&grants, "observe.snapshot", shop_b));
    assert!(allow(&grants, "shop.add_to_cart", shop_a));
    assert!(!allow(&grants, "shop.pay", shop_a));
    assert!(!allow(&grants, "shop.set_address", shop_a));

    grants.push(agent_to_origin(
        origin(mail),
        DataClass::Message,
        ActionClass::Send,
    ));
    grants.push(agent_to_origin(
        origin(calendar),
        DataClass::Event,
        ActionClass::Delete,
    ));
    grants.push(agent_to_origin(
        origin(shop_a),
        DataClass::Payment,
        ActionClass::Pay,
    ));
    grants.push(agent_to_origin(
        origin(shop_a),
        DataClass::Payment,
        ActionClass::SetAddress,
    ));
    assert_eq!(
        authorize(&grants, "mail.compose_or_send", Some(mail)),
        Decision::Deny {
            reason: crate::REASON_INDISTINGUISHABLE.to_owned()
        }
    );
    assert_eq!(
        authorize(&grants, "calendar.create_or_delete", Some(calendar)),
        Decision::Deny {
            reason: crate::REASON_INDISTINGUISHABLE.to_owned()
        }
    );
    assert_eq!(
        authorize(&grants, "shop.cart_or_pay", Some(shop_a)),
        Decision::Deny {
            reason: crate::REASON_INDISTINGUISHABLE.to_owned()
        }
    );
    assert!(!allow(&[], "mail.send", mail));
    assert!(!allow(&grants, "observe.snapshot", bank));
    let _ = bank;
}
