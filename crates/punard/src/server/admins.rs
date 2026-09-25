//! F0-S1: device administrators, and the rule for acting on other people
//! (docs/api/ipc.md section 23).
//!
//! THE RULE. An action *reaches another person* when it signals or ends
//! another uid's process, scope or session, or a system service; reveals
//! another person's data; or changes device-wide state that every person on
//! the device depends on — an `/etc` file, device policy, who manages the
//! device, what the operating system runs. Such an action needs uid 0, or a
//! device administrator who has just confirmed their password. An agent is
//! refused at any uid, before either question is asked. Every attempt is
//! audited.
//!
//! THE ORDER, and why it is part of the rule. Everything that does not depend
//! on who is asking is settled first; then the role; then the ticket. The
//! role is checked *before* the ticket is spent, so a person without the role
//! never spends a password on a call that cannot succeed, and their ticket is
//! still theirs to use on something they may do.
//!
//! A child module of [`super`] for the reason `m9` is: these are `Inner`
//! methods over the daemon's private state.

use super::*;

use crate::admins::{ADMIN_GROUP, AdminSources, Origin, SetError, name_ok};
use crate::policy::{AdminRoster, resolve_admin_roster};

/// The refusal reason every surface keys on (docs/api/ipc.md section 23.1).
pub(super) const REASON_DEVICE_ADMIN_REQUIRED: &str = "device_admin_required";

/// Which list decides a role check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RosterScope {
    /// The organization's roster decides while it has one; the device's own
    /// `punar-admin` members otherwise. Every action but one.
    Governed,
    /// Only the device's own members. Leaving an enrollment the organization
    /// made removable must never depend on that organization's permission:
    /// if it could forbid every local administrator, "removable" would mean
    /// nothing.
    DeviceOnly,
}

/// What the governing roster says, flattened for refusals and `admins.list`.
struct RosterView {
    mode: &'static str,
    administrators: Vec<String>,
    /// `(name, policy_id)` of the organization that decides, when one does.
    organization: Option<(String, String)>,
    source: Option<PolicySourceRef>,
}

impl Inner {
    /// Where the role is read and written, from this daemon's configuration.
    pub(super) fn admin_sources(&self) -> AdminSources {
        AdminSources {
            identity_accounts: self.cfg.identity_accounts_dir.clone(),
            userdb_dir: self.cfg.userdb_dir.clone(),
            group_file: self.cfg.group_file.clone(),
            passwd_file: self.cfg.passwd_file.clone(),
        }
    }

    /// The roster that decides for `scope`, and who it names.
    fn roster_view(&self, sources: &AdminSources, scope: RosterScope) -> RosterView {
        let governing = match scope {
            RosterScope::Governed => {
                resolve_admin_roster(&self.admin_roster.lock().unwrap()).cloned()
            }
            RosterScope::DeviceOnly => None,
        };
        let local = || {
            sources
                .accounts()
                .into_iter()
                .filter(|account| account.administrator)
                .map(|account| account.user)
                .collect::<Vec<_>>()
        };
        match governing {
            None => RosterView {
                mode: "local",
                administrators: local(),
                organization: None,
                source: None,
            },
            Some(layer) => {
                let administrators = match &layer.roster {
                    AdminRoster::Local => local(),
                    AdminRoster::Pinned(names) => names.clone(),
                    AdminRoster::None => Vec::new(),
                };
                RosterView {
                    mode: layer.roster.mode(),
                    administrators,
                    organization: Some((
                        layer.provenance.source_name.clone(),
                        layer.provenance.policy_id.clone(),
                    )),
                    source: Some(source_ref(&layer.provenance)),
                }
            }
        }
    }

    /// Whether `uid` holds the role now, under `scope`. uid 0 is not "an
    /// administrator" — it needs no role, and callers test it first.
    pub(super) fn is_device_admin(&self, uid: u32, scope: RosterScope) -> bool {
        let sources = self.admin_sources();
        let Some(user) = sources.username_of(uid) else {
            return false;
        };
        let view = self.roster_view(&sources, scope);
        match view.mode {
            "local" => sources.is_member(&user),
            _ => view.administrators.contains(&user),
        }
    }

    /// THE RULE, in one place: `Ok` for uid 0 and for a device
    /// administrator; otherwise a `denied` naming who can act, audited. Call
    /// it after the agent refusal and before any ticket is spent.
    ///
    /// `doing` is the action as a person would say it ("Changing device
    /// policy"); `retry` is the command they would run.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn require_device_admin(
        &self,
        peer: &Peer,
        actor: &AuditActor,
        action: &str,
        resource: &str,
        doing: &str,
        scope: RosterScope,
    ) -> Result<(), IpcError> {
        if peer.uid == 0 || self.is_device_admin(peer.uid, scope) {
            return Ok(());
        }
        let sources = self.admin_sources();
        let user = sources
            .username_of(peer.uid)
            .unwrap_or_else(|| format!("uid:{}", peer.uid));
        let view = self.roster_view(&sources, scope);
        let mut event = AuditEvent::denial(&self.device_id, actor, action, resource);
        event.result = REASON_DEVICE_ADMIN_REQUIRED.to_string();
        if let Some((_, policy_id)) = &view.organization {
            event.policy_ids = vec![policy_id.clone()];
        }
        self.log_audit(event);
        Err(device_admin_refusal(doing, &user, &view))
    }

    /// A device-wide change a person makes with their password (contract
    /// section 23.1): the role, then the confirmation, spent here for
    /// `method`. Root needs neither. The caller refuses agents before this,
    /// and settles everything that does not depend on who is asking first,
    /// so a person without the role never spends a password on a change
    /// they could not make.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit_device_change(
        &self,
        peer: &Peer,
        actor: &AuditActor,
        method: &str,
        action: &str,
        resource: &str,
        ticket: Option<&str>,
        doing: &str,
        retry: &str,
    ) -> Result<(), IpcError> {
        self.require_device_admin(peer, actor, action, resource, doing, RosterScope::Governed)?;
        if peer.uid != 0 && ticket.is_none() {
            let mut event = AuditEvent::denial(&self.device_id, actor, action, resource);
            event.result = "reauthentication_required".to_string();
            self.log_audit(event);
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "{doing} needs your password, and this request did not carry a \
                     confirmation.\n\
                     Policy: personal defaults — a change that reaches everyone on this \
                     device is confirmed at the moment it is made (docs/api/ipc.md \
                     section 23).\n\
                     Next step: run `{retry}` in a terminal; it asks for your password."
                ),
                json!({ "decision": "deny", "reason": "reauthentication_required" }),
            ));
        }
        self.spend_reauth_ticket(peer, actor, method, action, resource, ticket, retry)
    }

    /// `admins.list` (contract section 23.3): who administers this device,
    /// who decides that, and whether the caller is one. Open to every
    /// admitted peer — a person must be able to find out whom to ask.
    pub(super) fn handle_admins_list(&self, peer: &Peer) -> Result<Value, IpcError> {
        let sources = self.admin_sources();
        let view = self.roster_view(&sources, RosterScope::Governed);
        let pinned = view.mode != "local";
        let accounts: Vec<Value> = sources
            .accounts()
            .into_iter()
            .map(|account| {
                let administrator = if pinned {
                    view.administrators.contains(&account.user)
                } else {
                    account.administrator
                };
                json!({
                    "user": account.user,
                    "uid": account.uid,
                    "administrator": administrator,
                    "origin": account.origin,
                })
            })
            .collect();
        let caller_user = if peer.uid == 0 {
            "root".to_string()
        } else {
            sources
                .username_of(peer.uid)
                .unwrap_or_else(|| format!("uid:{}", peer.uid))
        };
        Ok(json!({
            "mode": view.mode,
            "administrators": view.administrators,
            "accounts": accounts,
            "source": view.source,
            "group": ADMIN_GROUP,
            "caller": {
                "user": caller_user,
                "root": peer.uid == 0,
                "administrator": peer.uid != 0
                    && self.is_device_admin(peer.uid, RosterScope::Governed),
            },
        }))
    }

    /// `admins.set` (contract section 23.3). The ladder, each rung settled
    /// before the next is asked:
    ///
    /// ```text
    /// 1. an agent, at any uid?            -> denied (agent_scope)
    /// 2. does an organization decide?     -> denied, naming it
    /// 3. a well-formed account name?      -> invalid_params
    /// 4. an account this device has?      -> not_found / invalid_params
    /// 5. would it remove the last one?    -> denied (last_administrator)
    /// 6. is the caller an administrator?  -> denied (device_admin_required)
    /// 7. a fresh ticket (non-root)?       -> spent here
    /// 8. change the record, then the drop-in; audit either way.
    /// ```
    pub(super) fn handle_admins_set(
        &self,
        peer: &Peer,
        params: &AdminsSetParams,
    ) -> Result<Value, IpcError> {
        const ACTION: &str = "admins.set";
        let actor = self.actor_of(peer);
        let user = params.user.trim();
        let resource = if name_ok(user) {
            format!("account/{user}")
        } else {
            "account".to_string()
        };
        let verb = if params.administrator {
            "add"
        } else {
            "remove"
        };
        let retry = format!("punarctl admins {verb} {}", term_word(user));

        // 1. No agent, at any uid: an agent that could hand out the role
        //    could hand it to the person it acts for, or keep it.
        if let Some(who) = self.agent_shaped_peer(peer, &actor) {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                ACTION,
                &resource,
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "An AI agent may not change who administers this device.\n\
                     Requested by: {who}\n\
                     Policy: personal defaults — the administrator role decides who \
                     may act on other people, and only a person who has just proved \
                     their password may hand it out (docs/api/ipc.md section 23).\n\
                     Next step: run `{retry}` yourself."
                ),
                json!({ "decision": "deny", "reason": "agent_scope" }),
            ));
        }

        // 2. An organization that decides who administers the device makes
        //    the local list inert while it is enrolled; changing it would be
        //    a change nobody could see take effect.
        let sources = self.admin_sources();
        let view = self.roster_view(&sources, RosterScope::Governed);
        if let Some((org, policy_id)) = view.organization.clone().filter(|_| view.mode != "local") {
            let mut event = AuditEvent::denial(&self.device_id, &actor, ACTION, &resource);
            event.policy_ids = vec![policy_id.clone()];
            self.log_audit(event);
            let decides = if view.mode == "none" {
                "turns local administration off on this device".to_string()
            } else {
                "decides who administers this device while it is enrolled".to_string()
            };
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "{org} ({policy_id}) {decides}, so the device's own list cannot be \
                     changed here.\n\
                     User override: not permitted.\n\
                     Next step: ask {org} to change its list centrally — this device \
                     picks it up on its next sync."
                ),
                json!({
                    "decision": "deny",
                    "reason": "administrators_set_by_organization",
                    "administrators_policy": view.mode,
                    "policy_ids": [policy_id],
                }),
            ));
        }

        // 3. and 4. The account must be one this device has, and one whose
        //    role lives in a record punard may edit. Every refusal from here
        //    on is audited too (contract section 23.3: "always audited"): a
        //    probe for account names is an attempt like any other.
        let refused = |result: &str| {
            let mut event = AuditEvent::denial(&self.device_id, &actor, ACTION, &resource);
            event.result = result.to_string();
            self.log_audit(event);
        };
        if !name_ok(user) {
            refused("invalid_params");
            return Err(IpcError::with_details(
                ErrorCode::InvalidParams,
                format!(
                    "{:?} is not an account name.\n\
                     Policy: os default — account names are lowercase letters, digits, \
                     '_' and '-', starting with a letter or '_'.\n\
                     Next step: `punarctl admins list` shows this device's accounts.",
                    params.user
                ),
                json!({ "param": "user", "reason": "not an account name" }),
            ));
        }
        // From the count below to the change itself, one `admins.set` at a
        // time: two administrators removing each other at once must not both
        // count the other and leave nobody.
        let _change = self.admins_change.lock().unwrap();
        let accounts = sources.accounts();
        let Some(target) = accounts.iter().find(|account| account.user == user) else {
            refused("not_found");
            return Err(IpcError::with_details(
                ErrorCode::NotFound,
                format!(
                    "This device has no account named {user}.\n\
                     Policy: os default — the role belongs to an account on this device.\n\
                     Next step: `punarctl admins list` shows this device's accounts."
                ),
                json!({ "param": "user", "user": user }),
            ));
        };
        if target.origin == Origin::Image {
            refused("image_account");
            return Err(IpcError::with_details(
                ErrorCode::InvalidParams,
                format!(
                    "{user}'s role is part of this device's image, not a setting that \
                     can be changed here.\n\
                     Policy: os default — only accounts created on this device keep \
                     their role in a record the device may edit.\n\
                     Next step: none on this device; an image that should differ is \
                     built differently."
                ),
                json!({ "param": "user", "user": user, "reason": "image_account" }),
            ));
        }

        // 5. Never zero administrators. Settled before the caller's standing,
        //    because it is a fact about the device and not about who asks —
        //    and a password spent on it would buy nothing. Only an
        //    administrator someone can sign in as counts: a role held by an
        //    account whose record boot does not publish administers nothing.
        let remaining = accounts
            .iter()
            .filter(|account| account.administrator && account.signs_in && account.user != user)
            .count();
        if !params.administrator && target.administrator && remaining == 0 {
            let mut event = AuditEvent::denial(&self.device_id, &actor, ACTION, &resource);
            event.result = "last_administrator".to_string();
            self.log_audit(event);
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "{user} is this device's only administrator, and a device always \
                     keeps one.\n\
                     Policy: personal defaults — with no administrator nobody could \
                     change device policy, updates or enrollment again (docs/api/ipc.md \
                     section 23.3).\n\
                     Next step: make someone else an administrator first with \
                     `punarctl admins add <name>`, then remove {user}."
                ),
                json!({ "decision": "deny", "reason": "last_administrator", "user": user }),
            ));
        }

        // 6. and 7. Who is asking, then their password.
        self.require_device_admin(
            peer,
            &actor,
            ACTION,
            &resource,
            "Changing who administers this device",
            RosterScope::Governed,
        )?;
        if peer.uid != 0 && params.ticket.is_none() {
            refused("reauthentication_required");
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "Changing who administers this device needs your password, and this \
                     request did not carry a confirmation.\n\
                     Policy: personal defaults — handing out or taking away the role is \
                     confirmed at the moment it is made.\n\
                     Next step: run `{retry}` in a terminal; it asks for your password."
                ),
                json!({ "decision": "deny", "reason": "reauthentication_required" }),
            ));
        }
        self.spend_reauth_ticket(
            peer,
            &actor,
            ACTION,
            ACTION,
            &resource,
            params.ticket.as_deref(),
            &retry,
        )?;

        // 8. The change.
        match sources.set_member(user, params.administrator) {
            Ok(changed) => {
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    &resource,
                    Decision::Allow,
                    if changed {
                        AuditOutcome::Success
                    } else {
                        AuditOutcome::Noop
                    },
                ));
                let after = self.roster_view(&sources, RosterScope::Governed);
                Ok(json!({
                    "user": user,
                    "administrator": params.administrator,
                    "changed": changed,
                    "administrators": after.administrators,
                }))
            }
            Err(error) => {
                self.log_audit(AuditEvent::action(
                    &self.device_id,
                    &actor,
                    ACTION,
                    &resource,
                    Decision::Allow,
                    AuditOutcome::Failure,
                ));
                Err(match error {
                    SetError::NoSuchAccount | SetError::ImageManaged => IpcError::with_details(
                        ErrorCode::Conflict,
                        format!(
                            "{user}'s account changed while the role was being set; \
                             nothing was changed.\n\
                             Policy: os default.\n\
                             Next step: `punarctl admins list`, then try again."
                        ),
                        json!({ "user": user }),
                    ),
                    SetError::Storage(e) => {
                        self.internal(&format!("recording {user}'s role failed: {e}"))
                    }
                })
            }
        }
    }
}

/// The refusal a person without the role reads, in the section 73 voice: what
/// happened, which rule, who can act, and what to do now.
fn device_admin_refusal(doing: &str, user: &str, view: &RosterView) -> IpcError {
    let names = if view.administrators.is_empty() {
        None
    } else {
        Some(view.administrators.join(", "))
    };
    let (message, policy_ids) = match (&view.organization, view.mode) {
        (Some((org, policy_id)), "none") => (
            format!(
                "{doing} reaches everyone who uses this device, so it needs a device \
                 administrator — and {org} has turned local administration off.\n\
                 Policy: {org} ({policy_id}) — nobody at this device administers it \
                 while it is enrolled.\n\
                 Next step: ask {org} to make this change centrally."
            ),
            vec![policy_id.clone()],
        ),
        (Some((org, policy_id)), "pinned") => (
            format!(
                "{doing} reaches everyone who uses this device, so it needs a device \
                 administrator, and {org} does not list {user} as one.\n\
                 Administrators: {}.\n\
                 Policy: {org} ({policy_id}) decides who administers this device while \
                 it is enrolled.\n\
                 Next step: ask {} to do it, or ask {org} to add you to its list.",
                names.as_deref().unwrap_or("none"),
                names.as_deref().unwrap_or(org.as_str()),
            ),
            vec![policy_id.clone()],
        ),
        _ => match &names {
            Some(names) => (
                format!(
                    "{doing} reaches everyone who uses this device, so it needs a device \
                     administrator, and {user} is not one.\n\
                     Administrators: {names}.\n\
                     Policy: personal defaults — an action that reaches other people \
                     needs an administrator who has just confirmed their password \
                     (docs/api/ipc.md section 23).\n\
                     Next step: ask {names} to do it, or to make you an administrator \
                     with `punarctl admins add {user}`."
                ),
                Vec::new(),
            ),
            None => (
                format!(
                    "{doing} reaches everyone who uses this device, so it needs a device \
                     administrator, and this device has none right now.\n\
                     Policy: personal defaults — a device always keeps one; the account \
                     that set it up becomes its administrator again when it starts.\n\
                     Next step: restart this device, then sign in as the account that \
                     set it up."
                ),
                Vec::new(),
            ),
        },
    };
    IpcError::with_details(
        ErrorCode::Denied,
        message,
        json!({
            "decision": "deny",
            "reason": REASON_DEVICE_ADMIN_REQUIRED,
            "user": user,
            "administrators": view.administrators,
            "administrators_policy": view.mode,
            "policy_ids": policy_ids,
        }),
    )
}

/// A name as it may appear inside a suggested command: account names are a
/// closed alphabet, and anything else is shown as a placeholder rather than
/// echoed into something a person might paste.
fn term_word(user: &str) -> String {
    if name_ok(user) {
        user.to_string()
    } else {
        "<name>".to_string()
    }
}
