//! Fixtures for this crate's tests: a temp directory, the NSS files, and a
//! **mock approval engine** that speaks punard's `approvals.*` shapes.
//!
//! Kept in the library rather than behind `cfg(test)` so the external
//! integration-test binary can build the same fixtures — the `punard`
//! `capability::mock` and `punar-agentd` `testsupport` precedent. Nothing
//! in the shipped daemon wiring calls any of it; `punar-secrets run` never
//! touches this module.
//!
//! The mock is deliberately **not** a second approval engine: it stores
//! what it is told, answers `approvals.list`, and enforces exactly one
//! rule — an approval can be consumed once. That single rule is the one
//! the broker's behaviour depends on (ipc.md section 14.7); everything
//! else about approvals (human-only resolution, the expiry sweep, the
//! store on disk) belongs to punard and is tested there.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use punar_common::approval::{Approval, ApprovalEnvelope, ApprovalStatus};
use punar_common::ipc::{ApprovalIdParams, ApprovalsCreateParams};
use serde_json::{Value, json};

/// A fresh, uniquely named temp directory.
pub fn temp_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "punar-secrets-{tag}-{}-{nanos}-{seq}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `/etc/{group,passwd}` substitutes, so username resolution is
/// deterministic regardless of the host.
pub fn write_nss_files(dir: &Path) -> (PathBuf, PathBuf) {
    let group_file = dir.join("group");
    std::fs::write(&group_file, "root:x:0:\npunar:x:970:\n").unwrap();
    let passwd_file = dir.join("passwd");
    std::fs::write(
        &passwd_file,
        "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/bash\n",
    )
    .unwrap();
    (group_file, passwd_file)
}

/// A fixture `/proc` tree with one process in a managed agent scope, so a
/// test can drive the attribution rule without a real cgroup.
pub fn fake_agent_proc(dir: &Path, pid: i32, session_id: &str) -> PathBuf {
    let root = dir.join("proc");
    let entry = root.join(pid.to_string());
    std::fs::create_dir_all(&entry).unwrap();
    std::fs::write(
        entry.join("cgroup"),
        format!(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/\
             punar-agent-{session_id}.scope\n"
        ),
    )
    .unwrap();
    root
}

/// The shipped credential catalog, written where a test daemon can read it.
pub fn write_catalog(dir: &Path) -> PathBuf {
    let path = dir.join("classes.yaml");
    std::fs::write(&path, include_str!("../share/classes.yaml")).unwrap();
    path
}

/// A personal-defaults AI authority document with the spec section 20
/// credentials block (`github: allow`, `aws_dev: request`,
/// `aws_prod: deny`).
pub fn write_ai_defaults(dir: &Path) -> PathBuf {
    let path = dir.join("ai-defaults.yaml");
    std::fs::write(
        &path,
        "ai:\n  agents:\n    default:\n      filesystem:\n        workspace: read_write\n      \
         host:\n        firewall: approval_required\n      network:\n        internet: allow\n      \
         credentials:\n        github: allow\n        aws_dev: request\n        aws_prod: deny\n",
    )
    .unwrap();
    path
}

#[derive(Debug, Default)]
struct MockState {
    /// Envelopes, in creation order.
    approvals: Vec<Value>,
    seq: u64,
    /// When set, `approvals.create` answers this wire error instead of
    /// creating (used to exercise the flood path).
    refuse_create: Option<(String, String)>,
    /// Every method name the broker called, in order.
    calls: Vec<String>,
}

/// A mock punard that answers `approvals.create`, `approvals.list` and
/// `approvals.consume`.
pub struct MockPunard {
    socket_path: PathBuf,
    state: Arc<Mutex<MockState>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MockPunard {
    /// Start the mock on `dir/punard.sock`.
    pub fn start(dir: &Path) -> MockPunard {
        let socket_path = dir.join("punard.sock");
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("mock punard binds");
        let state = Arc::new(Mutex::new(MockState::default()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let thread_state = Arc::clone(&state);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                match stream {
                    Ok(stream) => serve(&thread_state, stream),
                    Err(_) => break,
                }
            }
        });

        MockPunard {
            socket_path,
            state,
            shutdown,
            thread: Some(thread),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket_path
    }

    /// Approve a pending approval, as a human would through punard.
    pub fn approve(&self, approval_id: &str) {
        let mut state = self.state.lock().unwrap();
        for envelope in &mut state.approvals {
            if envelope["approval"]["approval_id"] == json!(approval_id) {
                envelope["approval"]["status"] = json!("approved");
                envelope["resolved_at"] = json!("2026-08-25T10:01:00Z");
                envelope["resolved_by"] = json!({"uid": 1000, "user": "punar"});
            }
        }
    }

    /// Approve everything pending; returns the ids it approved.
    pub fn approve_all(&self) -> Vec<String> {
        let ids = self.pending_ids();
        for id in &ids {
            self.approve(id);
        }
        ids
    }

    pub fn pending_ids(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .approvals
            .iter()
            .filter(|e| e["approval"]["status"] == json!("pending"))
            .map(|e| e["approval"]["approval_id"].as_str().unwrap().to_string())
            .collect()
    }

    /// Every approval envelope the broker created, for shape assertions.
    pub fn envelopes(&self) -> Vec<Value> {
        self.state.lock().unwrap().approvals.clone()
    }

    /// Method names the broker called, in order.
    pub fn calls(&self) -> Vec<String> {
        self.state.lock().unwrap().calls.clone()
    }

    /// Make the next `approvals.create` fail with this wire error.
    pub fn refuse_create(&self, code: &str, message: &str) {
        self.state.lock().unwrap().refuse_create = Some((code.to_string(), message.to_string()));
    }

    pub fn stop(mut self) {
        self.shutdown_and_join();
    }

    /// Set the flag, wake the accept loop by connecting to it, and join.
    ///
    /// The join is conditional on the wake having connected: if the socket
    /// file is already gone (a test tore its temp directory down first),
    /// nothing can wake a thread parked in `accept(2)`, and joining it
    /// would hang the test suite instead of failing it. In that case the
    /// handle is dropped and the thread is reaped at process exit.
    fn shutdown_and_join(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let woken = UnixStream::connect(&self.socket_path).is_ok();
        if let Some(thread) = self.thread.take() {
            if woken {
                let _ = thread.join();
            }
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for MockPunard {
    fn drop(&mut self) {
        self.shutdown_and_join();
    }
}

fn serve(state: &Arc<Mutex<MockState>>, mut stream: UnixStream) {
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(reader_stream);
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => break,
        };
        let id = request["id"].clone();
        let method = request["method"].as_str().unwrap_or("").to_string();
        let params = request.get("params").cloned().unwrap_or(json!({}));
        let response = answer(state, &method, &params, &id);
        if stream
            .write_all(format!("{response}\n").as_bytes())
            .and_then(|()| stream.flush())
            .is_err()
        {
            break;
        }
        line.clear();
    }
}

fn answer(state: &Arc<Mutex<MockState>>, method: &str, params: &Value, id: &Value) -> Value {
    let mut state = state.lock().unwrap();
    state.calls.push(method.to_string());
    match method {
        "approvals.create" => {
            if let Some((code, message)) = state.refuse_create.take() {
                return json!({"v":1,"id":id,"error":{"code":code,"message":message}});
            }
            // The params are parsed with the **shared strict struct**, so
            // this mock fails exactly where the real punard would: a
            // broker that sent the wrong shape does not get a pass here.
            let created: ApprovalsCreateParams = match serde_json::from_value(params.clone()) {
                Ok(params) => params,
                Err(e) => {
                    return json!({"v":1,"id":id,"error":{
                        "code":"invalid_params",
                        "message":format!("approvals.create params: {e}")}});
                }
            };
            if punar_common::approval::validate_reason(&created.reason).is_err() {
                return json!({"v":1,"id":id,"error":{
                    "code":"invalid_params","message":"reason is not one printable line"}});
            }
            state.seq += 1;
            let approval_id = format!("apr_{:08x}", state.seq);
            let envelope = ApprovalEnvelope {
                v: 1,
                approval: Approval {
                    approval_id,
                    requester: created.requester.clone(),
                    user: created.user.clone(),
                    capability: created.capability.clone(),
                    resource: created.resource.clone(),
                    reason: created.reason.clone(),
                    risk: created.risk,
                    status: ApprovalStatus::Pending,
                    expires_at: "2026-08-25T10:05:00Z".to_string(),
                },
                kind: created.kind,
                created_at: "2026-08-25T10:00:00Z".to_string(),
                request: created.request.clone().unwrap_or(
                    punar_common::approval::ApprovalRequest {
                        method: "credential.request".to_string(),
                        params: json!({}),
                    },
                ),
                requester_peer: created.requester_peer.clone(),
                policy: created
                    .policy
                    .clone()
                    .unwrap_or(punar_common::approval::PolicyCitation {
                        name: "Personal defaults".to_string(),
                        policy_id: "personal-defaults".to_string(),
                    }),
                contract: created.contract.clone().unwrap_or_default(),
                resolved_at: None,
                resolved_by: None,
                consumed_at: None,
                execution: None,
            };
            let value = serde_json::to_value(&envelope).expect("envelope serializes");
            state.approvals.push(value.clone());
            // The result **is** the envelope (ipc.md section 14.3).
            json!({"v":1,"id":id,"result": value})
        }
        "approvals.list" => {
            json!({"v":1,"id":id,"result":{
                "approvals": state.approvals.clone(),
                "checked_at": "2026-08-25T10:00:00Z"}})
        }
        "approvals.consume" => {
            let wanted: ApprovalIdParams = match serde_json::from_value(params.clone()) {
                Ok(params) => params,
                Err(e) => {
                    return json!({"v":1,"id":id,"error":{
                        "code":"invalid_params",
                        "message":format!("approvals.consume params: {e}")}});
                }
            };
            let wanted = json!(wanted.approval_id);
            let Some(envelope) = state
                .approvals
                .iter_mut()
                .find(|e| e["approval"]["approval_id"] == wanted)
            else {
                return json!({"v":1,"id":id,"error":{
                    "code":"not_found","message":"no such approval"}});
            };
            if envelope["approval"]["status"] != json!("approved") {
                return json!({"v":1,"id":id,"error":{
                    "code":"conflict","message":"not approved"}});
            }
            if !envelope["consumed_at"].is_null() {
                return json!({"v":1,"id":id,"error":{
                    "code":"conflict","message":"already consumed"}});
            }
            envelope["consumed_at"] = json!("2026-08-25T10:02:00Z");
            json!({"v":1,"id":id,"result":{
                "approval": envelope.clone(),
                "consumed_at": "2026-08-25T10:02:00Z"}})
        }
        other => json!({"v":1,"id":id,"error":{
            "code":"unknown_method","message":format!("mock punard has no {other}")}}),
    }
}
