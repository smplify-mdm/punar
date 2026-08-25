//! Milestone 9: approval gates, AI authority, and just-in-time privilege
//! (SPEC sections 20, 28, 48, 60, 73; docs/api/ipc.md sections 14-15).
//!
//! A child module of [`super`] rather than a sibling crate module, for one
//! reason: these handlers are `Inner` methods — they need the registry, the
//! audit writer, the effective document and the approval store, which are
//! the daemon's private state. Everything the parent calls is marked
//! `pub(super)`, so the boundary between "the M3-M5 daemon" and "the M9
//! gate" is visible in the signatures instead of living in a comment.

use super::*;

// ---------------------------------------------------------------------------
// Milestone 9: approval gates, AI authority, just-in-time privilege
// (SPEC sections 20, 28, 48, 60, 73; docs/api/ipc.md sections 14-15)
// ---------------------------------------------------------------------------

/// What authorized a `capabilities.set`. Every variant is a *reason*, not a
/// permission bit: the audit event cites it, so the trail says why the call
/// was allowed and not merely that it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MutationAuthority {
    /// uid 0, the unchanged M3 rule.
    Root,
    /// A live section 48 grant for exactly this capability.
    Grant { grant_id: String },
    /// AI authority policy said `allow`. **No shipped M9 policy does** —
    /// the personal defaults are `approval_required` or `deny` across the
    /// board — but the value is part of SPEC section 20 and is implemented
    /// rather than left as a hole that would panic the day someone writes
    /// it.
    AiAllowed { policy_id: String },
}

/// The Plate D-003 contract line: the typed call a human is being asked to
/// authorize, spelled the way SPEC section 10 names its capabilities.
pub(super) fn contract_line(kind: ApprovalKind, capability: &str, resource: &str) -> String {
    match kind {
        ApprovalKind::CapabilitySet => {
            let leaf = capability.rsplit('.').next().unwrap_or(capability);
            let mut verb = String::from("Set");
            let mut upper = true;
            for c in leaf.chars() {
                if c == '_' {
                    upper = true;
                } else if upper {
                    verb.extend(c.to_uppercase());
                    upper = false;
                } else {
                    verb.push(c);
                }
            }
            format!("{verb}({resource})")
        }
        ApprovalKind::CredentialRequest => format!("RequestCredential({resource})"),
        ApprovalKind::PrivilegeRequest => format!("RequestPrivilege({capability}, {resource})"),
    }
}

/// Everything needed to raise one approval. Built by the caller that knows
/// the domain; validated and bounded by [`Inner::create_approval`].
pub(super) struct NewApproval {
    pub(super) kind: ApprovalKind,
    pub(super) capability: String,
    pub(super) resource: String,
    pub(super) reason: String,
    pub(super) risk: Risk,
    pub(super) user: String,
    pub(super) requester: Requester,
    pub(super) ttl: Option<u64>,
    pub(super) contract: Option<String>,
    pub(super) policy: PolicyCitation,
    pub(super) request: ApprovalRequest,
    pub(super) requester_peer: Option<RequesterPeer>,
}

impl Inner {
    /// Append an event and hand back its `evt_` id, which is how an approval
    /// points at the audit trail (contract section 14.3). `None` means the
    /// append failed — already logged loudly by [`Inner::log_audit`], and
    /// recorded honestly as a missing link rather than a fabricated one.
    pub(super) fn log_audit_id(&self, event: AuditEvent) -> Option<String> {
        let id = event.event_id.clone();
        let before = self.audit_events.load(Ordering::SeqCst);
        self.log_audit(event);
        (self.audit_events.load(Ordering::SeqCst) > before).then_some(id)
    }

    /// A schema-complete audit event for the M9 actions, which have no M3
    /// builder (`AuditEvent`'s builders cover the M3 vocabulary; these fill
    /// every required field the same way).
    pub(super) fn m9_event(
        &self,
        actor: &AuditActor,
        action: &str,
        resource: &str,
        decision: Decision,
        result: &str,
        policy_ids: Vec<String>,
    ) -> AuditEvent {
        AuditEvent {
            event_id: next_event_id(),
            timestamp: utc_now_rfc3339(),
            device_id: self.device_id.clone(),
            user_id: Some(actor.user_id.clone()),
            agent_session_id: Some(
                actor
                    .agent_session_id
                    .clone()
                    .unwrap_or_else(|| AGENT_SESSION_NONE.to_string()),
            ),
            project_id: Some(PROJECT_ID_SYSTEM.to_string()),
            source: actor.source,
            action: action.to_string(),
            resource: Some(resource.to_string()),
            decision,
            policy_ids: if policy_ids.is_empty() {
                vec![punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string()]
            } else {
                policy_ids
            },
            result: result.to_string(),
        }
    }

    /// The resolved username of a peer (`uid:<n>` when unresolvable).
    pub(super) fn peer_user(&self, peer: &Peer) -> String {
        lookup_username(&self.cfg.passwd_file, peer.uid)
            .unwrap_or_else(|| format!("uid:{}", peer.uid))
    }

    /// **Law 2 of this milestone, in one place.** `Some(who)` when the peer
    /// is attributed to a managed agent session — or when its cgroup merely
    /// *names* one, even malformed (docs/api/ipc.md section 14.5).
    ///
    /// Deliberately wider than attribution, and deliberately shared by every
    /// method that lets a caller author or answer a human's consent. Two
    /// copies of a rule this load-bearing would be a privilege boundary with
    /// two opinions, and a fourth method added later would be one `if` away
    /// from having no opinion at all — which is exactly how
    /// `approvals.create` came to check only `uid == 0`.
    ///
    /// The uid is **not** consulted: SPEC section 60 says root-ness inside an
    /// agent scope buys no bypass, so an agent that talks a person into
    /// running `sudo punarctl` inside its own scope must not thereby become a
    /// person. `who` is the attested session id when there is one, and the
    /// honest phrase for a scope that names no well-formed session otherwise.
    pub(super) fn agent_shaped_peer(&self, peer: &Peer, actor: &AuditActor) -> Option<String> {
        if let Some(session) = actor.agent_session_id.clone() {
            return Some(session);
        }
        punar_common::principal::peer_smells_of_agent_scope(&self.cfg.proc_root, peer.pid)
            .then(|| "a process inside a managed agent scope".to_string())
    }

    /// The AI authority citation for a ruling, in the DESIGN_LANGUAGE
    /// section 8 shape: personal mode cites PERSONAL DEFAULTS, an org
    /// citation appears only when an org layer actually won.
    pub(super) fn citation_of(&self, ruling: &AiRuling) -> PolicyCitation {
        PolicyCitation {
            name: ruling.source_name.clone(),
            policy_id: ruling.policy_id.clone(),
        }
    }

    /// Lazy expiry (contract section 14.4), for approvals **and** grants.
    ///
    /// Runs on every read, at resolve, at consume, and on every reconcile
    /// pass — no timer anywhere (SPEC section 6.3). Each lapse is audited
    /// once, attributed to the daemon: nobody *did* this, time passed.
    pub(super) fn sweep_approvals(&self, store: &mut ApprovalStore) {
        let now = approvals::now_secs();
        let daemon = AuditActor::daemon();
        let mut changed = false;
        for env in store.sweep(now) {
            changed = true;
            self.log_audit(self.m9_event(
                &daemon,
                "approval.expire",
                &env.approval.approval_id,
                Decision::Deny,
                "expired",
                vec![env.policy.policy_id.clone()],
            ));
        }
        for grant in store.sweep_grants(now) {
            changed = true;
            self.log_audit(self.m9_event(
                &daemon,
                "privilege.expire",
                &grant.grant_id,
                Decision::Deny,
                "expired",
                vec![],
            ));
        }
        if changed {
            self.publish_approvals_summary(store);
        }
    }

    /// Rewrite `/run/punard/approvals.json`. Best-effort and non-fatal: the
    /// file is a display view, and the socket is the authority (contract
    /// section 15).
    pub(super) fn publish_approvals_summary(&self, store: &ApprovalStore) {
        if let Err(e) = store.publish_summary(approvals::now_secs()) {
            eprintln!(
                "punard: could not write {}: {e}",
                self.cfg.approvals_file.display()
            );
        }
    }

    /// Raise an approval: validate, bound, persist, audit, publish.
    ///
    /// The bounds are the interesting part. Approval fatigue is the classic
    /// attack on an approval gate — flood the human until they stop reading
    /// and start pressing `A` — so a flood is refused **in code**, audited,
    /// and told to the requester in the section 73 voice.
    pub(super) fn create_approval(
        &self,
        store: &mut ApprovalStore,
        actor: &AuditActor,
        spec: NewApproval,
    ) -> Result<ApprovalEnvelope, IpcError> {
        punar_common::approval::validate_reason(&spec.reason).map_err(|reason| {
            IpcError::with_details(
                ErrorCode::InvalidParams,
                format!(
                    "The justification was not accepted: {reason}.\n\
                     Policy: personal defaults — a request a human has to answer must say \
                     why, in one line, so it cannot forge a dialog (docs/api/ipc.md section 14.4).\n\
                     Next step: pass --reason \"<why this is needed>\"."
                ),
                json!({ "param": "reason", "reason": reason }),
            )
        })?;

        let now = approvals::now_secs();
        let device_pending = store.pending_count(now);
        let mine = store.pending_for_requester(&spec.requester.id, now);
        if device_pending >= MAX_PENDING_APPROVALS || mine >= MAX_PENDING_PER_REQUESTER {
            self.log_audit(self.m9_event(
                actor,
                "approval.create",
                &spec.capability,
                Decision::Deny,
                RESULT_APPROVAL_FLOOD,
                vec![spec.policy.policy_id.clone()],
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "Too many approvals are already waiting for an answer, so this one \
                     was not raised.\n\
                     Policy: personal defaults — at most {MAX_PENDING_APPROVALS} pending \
                     device-wide and {MAX_PENDING_PER_REQUESTER} per requester, because a \
                     queue nobody can read is not a gate.\n\
                     Next step: answer the pending requests (`punarctl approvals list`), \
                     then ask again."
                ),
                json!({
                    "decision": "deny",
                    "reason": RESULT_APPROVAL_FLOOD,
                    "pending": device_pending,
                    "pending_for_requester": mine,
                }),
            ));
        }

        let ttl = punar_common::approval::clamp_ttl(spec.ttl);
        let approval_id = format!(
            "{}{}",
            punar_common::approval::APPROVAL_ID_PREFIX,
            random_hex(4).map_err(|e| self.internal(&format!("approval id: {e}")))?
        );
        let contract = spec
            .contract
            .unwrap_or_else(|| contract_line(spec.kind, &spec.capability, &spec.resource));
        let envelope = ApprovalEnvelope {
            v: 1,
            approval: Approval {
                approval_id: approval_id.clone(),
                requester: spec.requester,
                user: spec.user,
                capability: spec.capability,
                resource: spec.resource,
                reason: spec.reason,
                risk: spec.risk,
                status: ApprovalStatus::Pending,
                expires_at: approvals::rfc3339_in(ttl),
            },
            kind: spec.kind,
            created_at: utc_now_rfc3339(),
            request: spec.request,
            requester_peer: spec.requester_peer,
            policy: spec.policy,
            contract,
            resolved_at: None,
            resolved_by: None,
            consumed_at: None,
            execution: None,
        };
        store
            .put(envelope.clone())
            .map_err(|e| self.internal(&format!("persisting the approval failed: {e}")))?;
        self.log_audit(self.m9_event(
            actor,
            "approval.create",
            &approval_id,
            Decision::ApprovalRequired,
            "pending",
            vec![envelope.policy.policy_id.clone()],
        ));
        self.publish_approvals_summary(store);
        Ok(envelope)
    }

    /// The Milestone 9 authorization ladder for `capabilities.set`
    /// (contract section 14.8):
    ///
    /// ```text
    /// 1. peer attributed to an agent session?
    ///      -> AI AUTHORITY PATH: allow | deny | approval_required
    ///         Checked BEFORE the uid test, on purpose.
    /// 2. otherwise HUMAN PATH:
    ///      uid == 0                                 -> allow (unchanged)
    ///      live grant for (uid, capability)          -> allow (new)
    ///      otherwise                                 -> deny  (unchanged)
    /// ```
    ///
    /// Step 1 runs first because SPEC section 60 forbids bypassing AI policy
    /// enforcement: **root-ness inside an agent scope buys no bypass.** A
    /// human doing the same thing as root is unaffected, which is precisely
    /// the section 20/28 story — the agent raises an approval, the person
    /// does not.
    pub(super) fn authorize_capability_set(
        &self,
        peer: &Peer,
        actor: &AuditActor,
        id: &str,
        params: &CapabilitiesSetParams,
    ) -> Result<MutationAuthority, IpcError> {
        let state_hint = match &params.desired_state {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if let Some(session) = actor.agent_session_id.clone() {
            return self.authorize_agent_capability_set(actor, &session, id, params, &state_hint);
        }
        if peer.uid == 0 {
            return Ok(MutationAuthority::Root);
        }

        // Section 48: a live, unexpired, unrevoked grant for exactly this
        // capability makes a non-root peer's mutation legitimate.
        {
            let mut store = self.approvals.lock().unwrap();
            self.sweep_approvals(&mut store);
            if let Some(grant) = store.live_grant(peer.uid, id, approvals::now_secs()) {
                return Ok(MutationAuthority::Grant {
                    grant_id: grant.grant_id.clone(),
                });
            }
        }

        // The unchanged M3/M5 denial. M5 amendment (contract section 5.4):
        // when the target path is org-pinned, the citation names the pinning
        // source — "personal defaults" would be a false citation there.
        let pinning = {
            let doc = self.effective.lock().unwrap();
            doc.get(id).and_then(|entry| {
                (!entry.user_override_permitted).then(|| {
                    (
                        entry.provenance.source_name.clone(),
                        entry.provenance.policy_id.clone(),
                    )
                })
            })
        };
        let mut denial_event = AuditEvent::denial(&self.device_id, actor, "capabilities.set", id);
        if let Some((_, policy_id)) = &pinning {
            denial_event.policy_ids = vec![policy_id.clone()];
        }
        self.log_audit(denial_event);
        if let Some((source_name, policy_id)) = pinning {
            return Err(IpcError::denied_org_pinned(id, &source_name, &policy_id));
        }
        Err(IpcError::denied_needs_root(
            id,
            Some(id),
            &format!("sudo punarctl capabilities set {id} {state_hint}"),
        ))
    }

    /// The AI authority path of the ladder above.
    fn authorize_agent_capability_set(
        &self,
        actor: &AuditActor,
        session: &str,
        id: &str,
        params: &CapabilitiesSetParams,
        state_hint: &str,
    ) -> Result<MutationAuthority, IpcError> {
        let ruling = punar_common::aipolicy::host_token_for_capability(id)
            .and_then(|token| self.ai.lock().unwrap().host_ruling(token));
        let Some(ruling) = ruling else {
            // Fail closed. A capability that AI policy does not name is not
            // an oversight to be resolved in the agent's favour.
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                actor,
                "capabilities.set",
                id,
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "No AI authority rule covers {id}, so the request was refused.\n\
                     Punar does not guess: an agent may not change a capability that \
                     policy does not name.\n\
                     Policy: personal defaults — the AI authority document is \
                     {}.\n\
                     Next step: add a rule under ai.agents.default.host, or make the \
                     change yourself: sudo punarctl capabilities set {id} {state_hint}",
                    punar_common::aipolicy::AI_DEFAULTS_FILE
                ),
                json!({
                    "decision": "deny",
                    "capability": id,
                    "agent_session_id": session,
                    "reason": "no_ai_rule",
                }),
            ));
        };

        match ruling.decision {
            Decision::Allow => Ok(MutationAuthority::AiAllowed {
                policy_id: ruling.policy_id.clone(),
            }),
            Decision::Deny => {
                let mut event = AuditEvent::denial(&self.device_id, actor, "capabilities.set", id);
                event.policy_ids = vec![ruling.policy_id.clone()];
                self.log_audit(event);
                Err(IpcError::with_details(
                    ErrorCode::Denied,
                    format!(
                        "An AI agent may not change {id} on this device.\n\
                         Requested by: {session}\n\
                         Policy: {} ({}) — this capability is denied to agents, and \
                         approval is not available for it.\n\
                         Next step: make the change yourself: \
                         sudo punarctl capabilities set {id} {state_hint}",
                        ruling.source_name, ruling.policy_id
                    ),
                    json!({
                        "decision": "deny",
                        "capability": id,
                        "agent_session_id": session,
                        "policy_ids": [ruling.policy_id],
                    }),
                ))
            }
            Decision::ApprovalRequired => {
                let risk = self
                    .registry
                    .get(id)
                    .map(|cap| cap.descriptor().risk)
                    .unwrap_or(Risk::High);
                let policy = self.citation_of(&ruling);
                let user = self.console_user();
                let mut store = self.approvals.lock().unwrap();
                self.sweep_approvals(&mut store);
                let envelope = self.create_approval(
                    &mut store,
                    actor,
                    NewApproval {
                        kind: ApprovalKind::CapabilitySet,
                        capability: id.to_string(),
                        resource: state_hint.to_string(),
                        reason: format!(
                            "{session} requested {id} = {state_hint} through the typed \
                             capability API"
                        ),
                        risk,
                        user,
                        requester: Requester {
                            kind: PrincipalKind::AiAgent,
                            id: session.to_string(),
                        },
                        ttl: None,
                        contract: None,
                        policy: policy.clone(),
                        request: ApprovalRequest {
                            method: "capabilities.set".to_string(),
                            params: json!({
                                "capability": id,
                                "desired_state": params.desired_state.clone(),
                            }),
                        },
                        requester_peer: None,
                    },
                )?;
                // The trail names the request under the capability as well
                // as under the approval id: an incident review greps for
                // `security.firewall`, and the lifecycle greps for `apr_`.
                // Two indexes on one fact, both human-paced.
                let mut event = self.m9_event(
                    actor,
                    "capabilities.set",
                    id,
                    Decision::ApprovalRequired,
                    "pending",
                    vec![policy.policy_id.clone()],
                );
                event.resource = Some(id.to_string());
                self.log_audit(event);
                Err(IpcError::approval_required(
                    &envelope.approval.approval_id,
                    id,
                    state_hint,
                    &envelope.approval.expires_at,
                    &policy.name,
                    &policy.policy_id,
                ))
            }
        }
    }

    /// Who an agent-raised approval is routed to.
    ///
    /// M9 routes to the device's console user — the person at this machine,
    /// which in personal mode is the only person there is. The honest limit
    /// (contract section 14.5): "the console user" here means *the owner of
    /// the session user account*, not a seat-presence check; a logind
    /// `sd_session_is_active` check is named as deferred rather than
    /// implied.
    pub(super) fn console_user(&self) -> String {
        lookup_username(&self.cfg.passwd_file, self.cfg.console_uid)
            .unwrap_or_else(|| format!("uid:{}", self.cfg.console_uid))
    }

    // -- approvals.* --------------------------------------------------------

    pub(super) fn handle_approvals_list(&self) -> Result<Value, IpcError> {
        let mut store = self.approvals.lock().unwrap();
        self.sweep_approvals(&mut store);
        Ok(to_value(ApprovalsListResult {
            approvals: store.list(),
            checked_at: utc_now_rfc3339(),
        }))
    }

    pub(super) fn handle_approvals_get(
        &self,
        params: &ApprovalIdParams,
    ) -> Result<Value, IpcError> {
        let mut store = self.approvals.lock().unwrap();
        self.sweep_approvals(&mut store);
        match store.get(&params.approval_id) {
            Some(env) => Ok(to_value(env.clone())),
            None => Err(self.no_such_approval(&params.approval_id)),
        }
    }

    pub(super) fn no_such_approval(&self, approval_id: &str) -> IpcError {
        IpcError::with_details(
            ErrorCode::NotFound,
            format!(
                "No approval named {approval_id:?} exists on this device.\n\
                 Policy: os default — approvals are local records with a bounded \
                 lifetime, and an evicted one does not come back.\n\
                 Next step: `punarctl approvals list` shows what is pending."
            ),
            json!({ "approval_id": approval_id }),
        )
    }

    /// `approvals.create` — root only, and **never from inside an agent
    /// scope** (contract section 14.2).
    ///
    /// The second rule is not redundant with the first. Everything on this
    /// call is requester-authored: the `requester` block (an agent may name
    /// itself `{"type": "human"}`), the `reason`, the `contract` line and the
    /// `user` the card is routed to — and those four strings *are* the D-003
    /// overlay a person reads before consenting. A uid-only test would let an
    /// agent that got a root-privileged call inside its own scope write a
    /// consent dialog attributed to a person, and the `approval.resolve`
    /// event that follows would name that person for real. So the same wide
    /// agent test that guards `resolve` guards authorship, checked **first**
    /// for the same reason it is checked first there: it is the section-60
    /// rule, and root-ness inside an agent scope buys no bypass.
    ///
    /// `punar-secrets` is unaffected: it runs as a system unit in
    /// `system.slice`, so its cgroup names no agent scope, and the session it
    /// is asking *on behalf of* travels in `requester_peer` rather than in
    /// its own attribution (contract section 14.2).
    pub(super) fn handle_approvals_create(
        &self,
        peer: &Peer,
        params: &ApprovalsCreateParams,
    ) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        if let Some(who) = self.agent_shaped_peer(peer, &actor) {
            self.log_audit(self.m9_event(
                &actor,
                "approval.create",
                &params.capability,
                Decision::Deny,
                RESULT_AGENT_CREATE_REFUSED,
                vec![],
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "An AI agent cannot raise an approval on someone's behalf.\n\
                     This call came from {who}, and the words on an approval card — who \
                     asked, why, and what exactly is being authorized — are what a person \
                     reads before saying yes, so an agent does not get to write them.\n\
                     Policy: personal defaults — refused by architecture, not by \
                     configuration (SPEC section 60); being root inside an agent scope \
                     changes nothing.\n\
                     Next step: make the typed capability call itself \
                     (`punarctl capabilities set …`) and let the gate raise the approval \
                     with the identity the kernel attested."
                ),
                json!({
                    "decision": "deny",
                    "capability": params.capability,
                    "result": RESULT_AGENT_CREATE_REFUSED,
                }),
            ));
        }
        if peer.uid != 0 {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                "approval.create",
                &params.capability,
            ));
            return Err(IpcError::denied_needs_root(
                "approvals",
                None,
                "sudo punarctl approvals ...",
            ));
        }
        // The caller's citation when it has one (the broker evaluated the
        // credential policy and knows whether an org layer won); the
        // personal-defaults citation otherwise. Never a guess.
        let policy = params.policy.clone().unwrap_or_else(|| PolicyCitation {
            name: crate::aipolicy::PERSONAL_DEFAULTS_NAME.to_string(),
            policy_id: punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string(),
        });
        let mut store = self.approvals.lock().unwrap();
        self.sweep_approvals(&mut store);
        let envelope = self.create_approval(
            &mut store,
            &actor,
            NewApproval {
                kind: params.kind,
                capability: params.capability.clone(),
                resource: params.resource.clone(),
                reason: params.reason.clone(),
                risk: params.risk,
                user: params.user.clone(),
                requester: params.requester.clone(),
                ttl: params.ttl,
                contract: params.contract.clone(),
                policy,
                request: params.request.clone().unwrap_or_else(|| ApprovalRequest {
                    method: match params.kind {
                        ApprovalKind::CredentialRequest => "credential.request".to_string(),
                        ApprovalKind::PrivilegeRequest => "privilege.request".to_string(),
                        ApprovalKind::CapabilitySet => "capabilities.set".to_string(),
                    },
                    params: json!({
                        "capability": params.capability,
                        "resource": params.resource,
                    }),
                }),
                requester_peer: params.requester_peer.clone(),
            },
        )?;
        Ok(to_value(envelope))
    }

    /// `approvals.resolve` — **human only** (contract section 14.5).
    ///
    /// Rule 1 (not an agent) is checked **first and unconditionally**,
    /// before the routing check and before the state check, because it is
    /// the section-60-class rule: an approval gate an agent can answer is
    /// not a gate. Rule 2 routes: root, or the person the approval names.
    /// Rule 3 is state: pending, and not past `expires_at`.
    pub(super) fn handle_approvals_resolve(
        &self,
        peer: &Peer,
        params: &ApprovalsResolveParams,
    ) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        let id = params.approval_id.as_str();

        // --- Rule 1: Law 2 of this milestone. An AI agent may resolve
        // nothing, ever, including a human's request — and the refusal is
        // recorded with the agent's own kernel-attested identity.
        if let Some(who) = self.agent_shaped_peer(peer, &actor) {
            self.log_audit(self.m9_event(
                &actor,
                "approval.resolve",
                id,
                Decision::Deny,
                RESULT_SELF_APPROVAL_REFUSED,
                vec![],
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "An AI agent cannot approve a request.\n\
                     This call came from {who}, and only a person at this device can \
                     answer an approval.\n\
                     Policy: personal defaults — self-approval is refused by \
                     architecture, not by configuration (SPEC section 60).\n\
                     Next step: answer it in the approval overlay, or run \
                     `punarctl approvals resolve {id} --decision approved` as the \
                     console user."
                ),
                json!({
                    "decision": "deny",
                    "approval_id": id,
                    "result": RESULT_SELF_APPROVAL_REFUSED,
                }),
            ));
        }

        let mut store = self.approvals.lock().unwrap();
        self.sweep_approvals(&mut store);
        let Some(env) = store.get(id).cloned() else {
            return Err(self.no_such_approval(id));
        };

        // --- Rule 2: approvals are routed to a person; only that person
        // (or root) answers. A stranger with socket access may read an
        // approval and may not decide it.
        let user = self.peer_user(peer);
        if peer.uid != 0 && user != env.approval.user {
            self.log_audit(self.m9_event(
                &actor,
                "approval.resolve",
                id,
                Decision::Deny,
                "not_routed_to_this_user",
                vec![env.policy.policy_id.clone()],
            ));
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "{id} is waiting for {} to answer it, not {user}.\n\
                     Policy: personal defaults — an approval is routed to a person, and \
                     only that person or an administrator may decide it.\n\
                     Next step: ask {} to answer it, or re-run as root.",
                    env.approval.user, env.approval.user
                ),
                json!({ "decision": "deny", "approval_id": id, "user": env.approval.user }),
            ));
        }

        // --- Rule 3: state. Expiry beats everything: a lapsed approval is
        // `expired`, never `conflict`, because "you were too late" and
        // "someone already answered" are different facts.
        if env.approval.status == ApprovalStatus::Pending && env.has_lapsed(approvals::now_secs()) {
            self.sweep_approvals(&mut store);
            return Err(IpcError::expired(id, &env.approval.expires_at));
        }
        if env.approval.status == ApprovalStatus::Expired {
            return Err(IpcError::expired(id, &env.approval.expires_at));
        }
        if env.approval.status.is_terminal() {
            return Err(IpcError::with_details(
                ErrorCode::Conflict,
                format!(
                    "{id} was already {} and cannot be answered again.\n\
                     Policy: personal defaults — an approval is answered once; a second \
                     answer would make the trail ambiguous about who decided.\n\
                     Next step: `punarctl approvals get {id}` shows the recorded \
                     decision.",
                    env.approval.status.as_str()
                ),
                json!({ "approval_id": id, "state": env.approval.status.as_str() }),
            ));
        }

        let mut resolved = env;
        resolved.approval.status = params.decision.status();
        resolved.resolved_at = Some(utc_now_rfc3339());
        resolved.resolved_by = Some(ResolvedBy {
            uid: peer.uid,
            user: user.clone(),
            pid: peer.pid,
            // Recorded so an attribution escape is visible after the fact,
            // even where M9 cannot prevent it (contract section 14.5).
            cgroup: punar_common::principal::peer_cgroup(&self.cfg.proc_root, peer.pid),
        });

        if params.decision == ResolveDecision::Approved {
            let execution = self.execute_approved(&mut store, &resolved);
            resolved.execution = execution;
        }

        store
            .put(resolved.clone())
            .map_err(|e| self.internal(&format!("persisting the resolution failed: {e}")))?;
        // The resolver's identity, not the requester's: `source: human`,
        // `agent_session_id: agt_none`. The agent did it, the human allowed
        // it, and the trail says both (SPEC section 22).
        self.log_audit(self.m9_event(
            &actor,
            "approval.resolve",
            id,
            match params.decision {
                ResolveDecision::Approved => Decision::Allow,
                ResolveDecision::Denied => Decision::Deny,
            },
            resolved.approval.status.as_str(),
            vec![resolved.policy.policy_id.clone()],
        ));
        self.publish_approvals_summary(&store);
        Ok(to_value(resolved))
    }

    /// Execution ownership follows capability ownership (contract section
    /// 14.6): punard executes what punard owns, and never touches a
    /// credential.
    fn execute_approved(
        &self,
        store: &mut ApprovalStore,
        env: &ApprovalEnvelope,
    ) -> Option<Execution> {
        match env.kind {
            // The broker spends this later through `approvals.consume`.
            // punard flips the status and does nothing else — a plaintext
            // token must never enter the daemon that writes /etc.
            ApprovalKind::CredentialRequest => None,
            ApprovalKind::CapabilitySet => Some(self.execute_approved_capability(env)),
            ApprovalKind::PrivilegeRequest => Some(self.execute_approved_privilege(store, env)),
        }
    }

    /// Run the recorded `capabilities.set` — re-derived from **punard's own
    /// record**, never from anything the approving client sent back.
    fn execute_approved_capability(&self, env: &ApprovalEnvelope) -> Execution {
        let params: CapabilitiesSetParams = match serde_json::from_value(env.request.params.clone())
        {
            Ok(params) => params,
            Err(e) => {
                return Execution {
                    result: "invalid_record".to_string(),
                    error: Some(format!(
                        "The recorded request could not be read back ({e}); nothing \
                             was executed."
                    )),
                    ..Execution::default()
                };
            }
        };
        let Some(cap) = self.registry.get(params.capability.as_str()) else {
            return Execution {
                result: "not_found".to_string(),
                error: Some(format!(
                    "{} is no longer a registered capability; nothing was executed.",
                    params.capability
                )),
                ..Execution::default()
            };
        };
        // SPEC section 22: the execution carries **the requesting agent's**
        // identity, because the agent is the proximate actor. The human's
        // consent is the separate `approval.resolve` event.
        let actor = match env.approval.requester.kind {
            PrincipalKind::AiAgent => AuditActor::cli_peer(env.approval.user.clone())
                .with_agent_session(env.approval.requester.id.clone()),
            _ => AuditActor::cli_peer(env.approval.user.clone()),
        };
        let (_, execution) = self.execute_capability_set(
            &actor,
            cap,
            &params,
            std::slice::from_ref(&env.approval.approval_id),
        );
        execution
    }

    /// Mint the grant a resolved `privilege_request` earned.
    fn execute_approved_privilege(
        &self,
        store: &mut ApprovalStore,
        env: &ApprovalEnvelope,
    ) -> Execution {
        let minutes = env
            .approval
            .resource
            .trim_end_matches('m')
            .parse::<u64>()
            .unwrap_or(punar_common::approval::GRANT_DEFAULT_MINUTES);
        let uid = env
            .requester_peer
            .as_ref()
            .map(|p| p.uid)
            .unwrap_or(self.cfg.console_uid);
        let grant_id = match random_hex(4) {
            Ok(hex) => format!("{}{hex}", punar_common::approval::GRANT_ID_PREFIX),
            Err(e) => {
                return Execution {
                    result: "internal".to_string(),
                    error: Some(format!("could not generate a grant id: {e}")),
                    ..Execution::default()
                };
            }
        };
        let grant = Grant {
            v: 1,
            grant_id: grant_id.clone(),
            approval_id: env.approval.approval_id.clone(),
            uid,
            user: env.approval.user.clone(),
            capability: env.approval.capability.clone(),
            reason: env.approval.reason.clone(),
            granted_at: utc_now_rfc3339(),
            expires_at: approvals::rfc3339_in(minutes.saturating_mul(60)),
            revoked_at: None,
        };
        if let Err(e) = store.put_grant(grant.clone()) {
            return Execution {
                result: "internal".to_string(),
                error: Some(format!("could not persist the grant: {e}")),
                ..Execution::default()
            };
        }
        let actor = AuditActor::cli_peer(env.approval.user.clone());
        let event_id = self.log_audit_id(self.m9_event(
            &actor,
            "privilege.grant",
            &grant_id,
            Decision::Allow,
            "granted",
            vec![
                punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string(),
                env.approval.approval_id.clone(),
            ],
        ));
        Execution {
            result: "granted".to_string(),
            changed: Some(true),
            audit_event_id: event_id,
            grant_id: Some(grant_id),
            error: None,
        }
    }

    /// `approvals.consume` — root only, single use (contract section 14.7).
    pub(super) fn handle_approvals_consume(
        &self,
        peer: &Peer,
        params: &ApprovalIdParams,
    ) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        let id = params.approval_id.as_str();
        if peer.uid != 0 {
            self.log_audit(AuditEvent::denial(
                &self.device_id,
                &actor,
                "approval.consume",
                id,
            ));
            return Err(IpcError::denied_needs_root(
                "an approval",
                None,
                "sudo punarctl approvals ...",
            ));
        }
        let mut store = self.approvals.lock().unwrap();
        self.sweep_approvals(&mut store);
        let Some(env) = store.get(id).cloned() else {
            return Err(self.no_such_approval(id));
        };
        if env.kind != ApprovalKind::CredentialRequest {
            return Err(IpcError::with_details(
                ErrorCode::InvalidParams,
                format!(
                    "{id} is a {} approval, which punard executes itself; it is not \
                     something to consume.\n\
                     Policy: os default — execution ownership follows capability \
                     ownership (docs/api/ipc.md section 14.6).\n\
                     Next step: `punarctl approvals get {id}` shows what it did.",
                    env.kind.as_str()
                ),
                json!({ "approval_id": id, "kind": env.kind.as_str() }),
            ));
        }
        // An approved credential approval **still expires**: a human's yes
        // is not a standing grant, and a second issuance raises a new one.
        if env.has_lapsed(approvals::now_secs()) {
            return Err(IpcError::expired(id, &env.approval.expires_at));
        }
        if env.approval.status != ApprovalStatus::Approved {
            return Err(IpcError::with_details(
                ErrorCode::Conflict,
                format!(
                    "{id} is {}, so there is nothing to consume.\n\
                     Policy: personal defaults — only an approved request may be spent.\n\
                     Next step: `punarctl approvals get {id}`.",
                    env.approval.status.as_str()
                ),
                json!({ "approval_id": id, "state": env.approval.status.as_str() }),
            ));
        }
        if let Some(consumed_at) = &env.consumed_at {
            return Err(IpcError::with_details(
                ErrorCode::Conflict,
                format!(
                    "{id} was already spent at {consumed_at}.\n\
                     Policy: personal defaults — an approval authorizes one issuance, \
                     once. A second credential needs a second decision.\n\
                     Next step: request the credential again to raise a fresh approval."
                ),
                json!({ "approval_id": id, "state": "consumed", "consumed_at": consumed_at }),
            ));
        }

        let consumed_at = utc_now_rfc3339();
        let mut consumed = env;
        // A sibling field, not a fifth status: the shipped enum is not
        // widened (contract section 14.3).
        consumed.consumed_at = Some(consumed_at.clone());
        store
            .put(consumed.clone())
            .map_err(|e| self.internal(&format!("persisting the consumption failed: {e}")))?;
        self.log_audit(self.m9_event(
            &actor,
            "approval.consume",
            id,
            Decision::Allow,
            "consumed",
            vec![consumed.policy.policy_id.clone()],
        ));
        self.publish_approvals_summary(&store);
        Ok(to_value(ApprovalsConsumeResult {
            approval: consumed,
            consumed_at,
        }))
    }

    // -- privilege.* --------------------------------------------------------

    /// `privilege.request` (contract section 14.8; SPEC section 48).
    pub(super) fn handle_privilege_request(
        &self,
        peer: &Peer,
        params: &PrivilegeRequestParams,
    ) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        let id = params.capability.as_str();

        // **A grant is never issued to an AI agent.** Agents get
        // per-request approvals; they never get a time window. The
        // difference between one approved call and fifteen minutes of
        // privilege is the whole of SPEC sections 48 and 60.
        //
        // The **wide** agent test, the same one `resolve` and `create` use: a
        // peer whose cgroup names an agent scope it cannot spell is still
        // plainly agent-shaped, and letting it through would put a card
        // reading "requested by: <the console user>" in front of a person
        // whose yes mints a grant — the one thing section 48 says an agent
        // never gets. Refusing a human who happens to be inside an agent
        // scope costs them one shell they can step out of; the other
        // direction costs a privilege window.
        if let Some(who) = self.agent_shaped_peer(peer, &actor) {
            self.log_audit(self.m9_event(
                &actor,
                "privilege.request",
                id,
                Decision::Deny,
                RESULT_AGENT_PRIVILEGE_REFUSED,
                vec![],
            ));
            let mut details = json!({
                "decision": "deny",
                "capability": id,
                "result": RESULT_AGENT_PRIVILEGE_REFUSED,
            });
            if let (Some(map), Some(session)) =
                (details.as_object_mut(), actor.agent_session_id.clone())
            {
                map.insert("agent_session_id".to_string(), json!(session));
            }
            return Err(IpcError::with_details(
                ErrorCode::Denied,
                format!(
                    "An AI agent cannot hold elevated privilege.\n\
                     Requested by: {who}\n\
                     Policy: personal defaults — agents ask for one call at a time and a \
                     person answers each one; a time window is not available to them \
                     (SPEC sections 48, 60).\n\
                     Next step: run the typed capability call and let the approval gate \
                     do its work."
                ),
                details,
            ));
        }

        let cap = self.lookup(&params.capability)?;
        let risk = cap.descriptor().risk;
        let minutes = punar_common::approval::clamp_grant_minutes(params.duration_minutes);
        let user = self.peer_user(peer);
        let policy = PolicyCitation {
            name: crate::aipolicy::PERSONAL_DEFAULTS_NAME.to_string(),
            policy_id: punar_common::audit::POLICY_PERSONAL_DEFAULTS.to_string(),
        };
        let mut store = self.approvals.lock().unwrap();
        self.sweep_approvals(&mut store);
        let envelope = self.create_approval(
            &mut store,
            &actor,
            NewApproval {
                kind: ApprovalKind::PrivilegeRequest,
                capability: id.to_string(),
                // Two different clocks: the approval TTL is how long the
                // human has to answer; this is how long privilege lasts.
                resource: format!("{minutes}m"),
                reason: params.reason.clone(),
                risk,
                user: user.clone(),
                requester: Requester {
                    kind: PrincipalKind::Human,
                    id: user,
                },
                ttl: None,
                contract: None,
                policy,
                request: ApprovalRequest {
                    method: "privilege.request".to_string(),
                    params: json!({
                        "capability": id,
                        "duration_minutes": minutes,
                    }),
                },
                requester_peer: Some(RequesterPeer {
                    uid: peer.uid,
                    agent_session_id: None,
                }),
            },
        )?;
        self.log_audit(self.m9_event(
            &actor,
            "privilege.request",
            &envelope.approval.approval_id,
            Decision::ApprovalRequired,
            "pending",
            vec![envelope.policy.policy_id.clone()],
        ));
        Err(IpcError::approval_required(
            &envelope.approval.approval_id,
            id,
            &envelope.approval.resource,
            &envelope.approval.expires_at,
            &envelope.policy.name,
            &envelope.policy.policy_id,
        ))
    }

    pub(super) fn handle_privilege_status(&self, peer: &Peer) -> Result<Value, IpcError> {
        let mut store = self.approvals.lock().unwrap();
        self.sweep_approvals(&mut store);
        let scope = (peer.uid != 0).then_some(peer.uid);
        Ok(to_value(PrivilegeStatusResult {
            grants: store.live_grants(scope, approvals::now_secs()),
            checked_at: utc_now_rfc3339(),
        }))
    }

    pub(super) fn handle_privilege_revoke(
        &self,
        peer: &Peer,
        params: &PrivilegeRevokeParams,
    ) -> Result<Value, IpcError> {
        let actor = self.actor_of(peer);
        let target = params.target().map_err(|reason| {
            IpcError::with_details(
                ErrorCode::InvalidParams,
                format!(
                    "Nothing was revoked: {reason}.\n\
                     Policy: os default — punard does not guess which privilege you \
                     meant to hand back.\n\
                     Next step: `punarctl privilege status` lists your grants."
                ),
                json!({ "reason": reason }),
            )
        })?;
        let mut store = self.approvals.lock().unwrap();
        self.sweep_approvals(&mut store);
        let now = approvals::now_secs();

        let ids: Vec<String> = match target {
            Some(grant_id) => {
                let Some(grant) = store.grant(grant_id) else {
                    return Err(IpcError::with_details(
                        ErrorCode::NotFound,
                        format!(
                            "No grant named {grant_id:?} exists.\n\
                             Policy: os default — a grant that expired is unlinked, not \
                             tombstoned.\n\
                             Next step: `punarctl privilege status`."
                        ),
                        json!({ "grant_id": grant_id }),
                    ));
                };
                if peer.uid != 0 && grant.uid != peer.uid {
                    self.log_audit(AuditEvent::denial(
                        &self.device_id,
                        &actor,
                        "privilege.revoke",
                        grant_id,
                    ));
                    return Err(IpcError::with_details(
                        ErrorCode::Denied,
                        format!(
                            "{grant_id} belongs to another user.\n\
                             Policy: personal defaults — a grant is revoked by its owner \
                             or by an administrator.\n\
                             Next step: re-run as root."
                        ),
                        json!({ "decision": "deny", "grant_id": grant_id }),
                    ));
                }
                vec![grant_id.to_string()]
            }
            None => store
                .live_grants((peer.uid != 0).then_some(peer.uid), now)
                .into_iter()
                .map(|g| g.grant_id)
                .collect(),
        };

        let mut revoked = Vec::new();
        for id in ids {
            match store.drop_grant(&id) {
                Ok(Some(_)) => {
                    self.log_audit(self.m9_event(
                        &actor,
                        "privilege.revoke",
                        &id,
                        Decision::Allow,
                        "revoked",
                        vec![],
                    ));
                    revoked.push(id);
                }
                Ok(None) => {}
                Err(e) => return Err(self.internal(&format!("revoking {id} failed: {e}"))),
            }
        }
        self.publish_approvals_summary(&store);
        Ok(to_value(PrivilegeRevokeResult {
            revoked,
            revoked_at: utc_now_rfc3339(),
        }))
    }
}
