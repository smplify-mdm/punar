//! User-facing half of Milestone 11 web apps and browser contexts.
//!
//! `punard` owns the records and decisions. This module materializes only
//! derived files in the connected user's home and launches upstream Chromium
//! through a closed argv builder. It never accepts an executable or shell
//! fragment from IPC, a manifest, or the command line.

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use clap::Subcommand;
use punar_common::time::utc_now_rfc3339;
use punar_common::webapp::{
    BrowserContext, WebAppArtifacts, WebAppIconRequest, WebAppInstallResult, WebAppManifest,
    WebAppRecord, origin_from_start_url, validate_context_id, validate_manifest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;

use crate::fmt::{self, Row, Slot, Style};
use crate::ipc::{CallError, Client};

const USER_FILE_MODE: u32 = 0o600;
const DESKTOP_FILE_MODE: u32 = 0o644;
const USER_DIR_MODE: u32 = 0o700;
const MAX_MANIFEST_BYTES: u64 = 4096;
// Invoke the browser binary, not the distribution wrapper. Both Punar's Arch
// and Debian substrates install Chromium here. Their wrappers accept extra
// flag files from mutable locations, which would turn the closed builder
// below into only one input among several.
const CHROMIUM_PROGRAM: &str = "/usr/lib/chromium/chromium";
const FIXED_DISABLE_FEATURES: &str = "PunarNone";
const ALLOWED_FLAG_PREFIXES: [&str; 7] = [
    "--app=",
    "--user-data-dir=",
    "--class=",
    "--ozone-platform=wayland",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-features=PunarNone",
];

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

type WebResult<T> = std::result::Result<T, WebAppsError>;

#[derive(Debug)]
enum WebAppsError {
    Call(CallError),
    Local(String),
}

impl From<String> for WebAppsError {
    fn from(value: String) -> Self {
        Self::Local(value)
    }
}

impl From<&str> for WebAppsError {
    fn from(value: &str) -> Self {
        Self::Local(value.to_string())
    }
}

impl std::fmt::Display for WebAppsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call(error) => formatter.write_str(&error.message()),
            Self::Local(message) => formatter.write_str(message),
        }
    }
}

#[derive(Subcommand)]
pub enum WebAppsCommand {
    /// List installed web apps and browser contexts.
    List,
    /// Inspect one installed web app.
    Show { id: String },
    /// Install an HTTPS or absolute local-file web app.
    Install {
        /// HTTPS or file:/// start URL. Omit when using --from-manifest.
        url: Option<String>,
        /// Human-readable application name.
        #[arg(long)]
        name: Option<String>,
        /// Caller-owned local PNG; no icon is downloaded.
        #[arg(long, value_name = "PNG")]
        icon: Option<PathBuf>,
        /// Browser storage context. Defaults to the active context.
        #[arg(long)]
        context: Option<String>,
        /// Target workspace. Defaults to the chosen context.
        #[arg(long)]
        workspace: Option<String>,
        /// Read Punar's strict, local JSON manifest instead of URL/name.
        #[arg(long, value_name = "JSON", conflicts_with_all = ["url", "name", "icon", "workspace"])]
        from_manifest: Option<PathBuf>,
    },
    /// Remove an installed web app; browser data is kept unless requested.
    Uninstall {
        id: String,
        #[arg(long)]
        purge_data: bool,
        /// Skip the interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Launch one installed web app through the closed Chromium argv builder.
    Launch {
        id: String,
        #[arg(long)]
        context: Option<String>,
        /// Print the exact closed Chromium argv without launching it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Open a normal browser window in the active or named context.
    Browse {
        #[arg(long)]
        context: Option<String>,
        /// A link delivered by the desktop default-handler path. Every value
        /// is validated as HTTPS or an absolute local file before launch.
        #[arg(value_name = "URL", num_args = 0..=16)]
        urls: Vec<String>,
    },
    /// Rebuild all user-home artifacts from root-owned records.
    Sync,
    /// List, create, delete, or activate browser storage contexts.
    Context {
        #[command(subcommand)]
        command: BrowserContextCommand,
    },
}

#[derive(Subcommand)]
pub enum BrowserContextCommand {
    List,
    Create {
        id: String,
        #[arg(long)]
        name: Option<String>,
    },
    Delete {
        id: String,
        #[arg(long)]
        purge_data: bool,
    },
    Use {
        id: String,
    },
    Status,
}

#[derive(Debug, Deserialize)]
struct WebAppView {
    #[serde(flatten)]
    app: WebAppRecord,
    #[serde(default)]
    artifacts: Option<WebAppArtifacts>,
}

#[derive(Debug, Deserialize)]
struct PolicySummary {
    managed: bool,
    policy_ids: Vec<String>,
    allow_user_install: bool,
}

#[derive(Debug, Deserialize)]
struct WebAppsList {
    apps: Vec<WebAppView>,
    contexts: Vec<BrowserContext>,
    #[serde(default)]
    required_web_apps: Vec<WebAppManifest>,
    policy: PolicySummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContextBinding {
    workspace: String,
    context: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ActiveContext {
    version: u64,
    updated: String,
    active: String,
    active_cause: String,
    bindings: Vec<ContextBinding>,
}

pub fn run(command: WebAppsCommand, client: &Client, style: &Style, json_output: bool) -> ExitCode {
    match execute(command, client, style, json_output) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            match error {
                WebAppsError::Call(error) => ExitCode::from(error.exit_code()),
                WebAppsError::Local(_) => ExitCode::FAILURE,
            }
        }
    }
}

fn execute(
    command: WebAppsCommand,
    client: &Client,
    style: &Style,
    json_output: bool,
) -> WebResult<ExitCode> {
    match command {
        WebAppsCommand::List => {
            let result = call(client, "webapps.list", None)?;
            print_result(json_output, &result, || render_list(style, &result))
        }
        WebAppsCommand::Show { id } => {
            let result = call(
                client,
                "webapps.get",
                Some(json!({"id": id, "include_artifacts": false})),
            )?;
            print_result(json_output, &result, || render_show(style, &result))
        }
        WebAppsCommand::Install {
            url,
            name,
            icon,
            context,
            workspace,
            from_manifest,
        } => {
            let active = active_context().unwrap_or_else(|_| "personal".into());
            let mut manifest = if let Some(path) = from_manifest {
                read_manifest(&path)?
            } else {
                let url = url.ok_or_else(|| {
                    "Install needs a URL or --from-manifest. Nothing was changed.".to_string()
                })?;
                let name = name.ok_or_else(|| {
                    "Install needs --name with a URL. Nothing was changed.".to_string()
                })?;
                let chosen_context = context.clone().unwrap_or(active);
                WebAppManifest {
                    v: 1,
                    id: slug(&name)?,
                    name,
                    start_url: url,
                    context: chosen_context.clone(),
                    workspace: workspace.unwrap_or(chosen_context),
                    icon: match icon {
                        Some(path) => WebAppIconRequest::File {
                            path: absolute_path(&path)?.to_string_lossy().into_owned(),
                        },
                        None => WebAppIconRequest::Generated,
                    },
                }
            };
            if let Some(context) = context {
                manifest.context = context;
            }
            validate_manifest(&manifest)
                .map_err(|reason| format!("The web-app manifest was refused: {reason}."))?;
            let result = call(client, "webapps.install", Some(json!({"app": manifest})))?;
            let installed: WebAppInstallResult = serde_json::from_value(result.clone())
                .map_err(|error| format!("punard returned an invalid install result ({error})"))?;
            materialize(&installed.app, &installed.artifacts)?;
            sync(client)?;
            if json_output {
                print_json(&result)?;
            } else {
                let mut out = fmt::masthead(style, "Web app installed", &local_hostname());
                out.push_str(&fmt::verdict(
                    style,
                    Slot::Ok,
                    &format!("✓ {} · installed", installed.app.name),
                ));
                out.push_str(&fmt::note(
                    style,
                    "Launcher, icon, profile, and workspace rule are ready",
                ));
                print!("{out}");
            }
            Ok(ExitCode::SUCCESS)
        }
        WebAppsCommand::Uninstall {
            id,
            purge_data,
            yes,
        } => {
            if !confirmed(
                yes || json_output,
                &format!(
                    "Remove web app {id}? Browser data is {}. Type yes to continue: ",
                    if purge_data { "deleted" } else { "kept" }
                ),
            )? {
                eprintln!("Uninstall aborted — nothing was changed.");
                return Ok(ExitCode::FAILURE);
            }
            let result = call(
                client,
                "webapps.uninstall",
                Some(json!({"id": id, "purge_data": purge_data})),
            )?;
            remove_app_artifacts(&id)?;
            if purge_data {
                if let Some(relative) = result
                    .get("purged")
                    .and_then(|value| value.get("profile_path_rel"))
                    .and_then(Value::as_str)
                {
                    remove_profile(relative)?;
                }
            }
            sync(client)?;
            if json_output {
                print_json(&result)?;
            } else {
                let mut out = fmt::masthead(style, "Web app removed", &local_hostname());
                out.push_str(&fmt::verdict(style, Slot::Ok, &format!("✓ {id} · removed")));
                if !purge_data {
                    out.push_str(&fmt::note(style, "Browser profile data was kept"));
                }
                print!("{out}");
            }
            Ok(ExitCode::SUCCESS)
        }
        WebAppsCommand::Launch {
            id,
            context,
            dry_run,
        } => launch(client, &id, context.as_deref(), dry_run, json_output),
        WebAppsCommand::Browse { context, urls } => browse(client, context.as_deref(), &urls),
        WebAppsCommand::Sync => {
            let count = sync(client)?;
            if json_output {
                print_json(&json!({"synced": count}))?;
            } else {
                println!("SYNCED · {count} WEB APP(S)");
            }
            Ok(ExitCode::SUCCESS)
        }
        WebAppsCommand::Context { command } => context_command(command, client, style, json_output),
    }
}

fn context_command(
    command: BrowserContextCommand,
    client: &Client,
    style: &Style,
    json_output: bool,
) -> WebResult<ExitCode> {
    match command {
        BrowserContextCommand::List => {
            let result = call(client, "webapps.list", None)?;
            if json_output {
                let contexts = result.get("contexts").cloned().unwrap_or_else(|| json!([]));
                print_json(&json!({"contexts": contexts}))?;
            } else {
                print!("{}", render_contexts(style, &result)?);
            }
        }
        BrowserContextCommand::Create { id, name } => {
            let display_name = name.unwrap_or_else(|| title(&id));
            let result = call(
                client,
                "webapps.context_create",
                Some(json!({"id": id, "name": display_name})),
            )?;
            let context: BrowserContext = serde_json::from_value(
                result
                    .get("context")
                    .cloned()
                    .ok_or_else(|| "context result is missing context".to_string())?,
            )
            .map_err(|error| format!("punard returned an invalid context ({error})"))?;
            ensure_profile(&context.profile_path_rel)?;
            if json_output {
                print_json(&result)?;
            } else {
                println!(
                    "CREATED · {} · STATE ISOLATION, NOT A SECURITY BOUNDARY",
                    context.id
                );
            }
        }
        BrowserContextCommand::Delete { id, purge_data } => {
            let result = call(
                client,
                "webapps.context_delete",
                Some(json!({"id": id, "purge_data": purge_data})),
            )?;
            if purge_data {
                if let Some(relative) = result.get("profile_path_rel").and_then(Value::as_str) {
                    remove_profile(relative)?;
                }
            }
            let current = list(client, false)?;
            reconcile_active_state(&current.contexts)?;
            if json_output {
                print_json(&result)?;
            } else {
                println!(
                    "DELETED · {id}{}",
                    if purge_data {
                        " · DATA PURGED"
                    } else {
                        " · DATA KEPT"
                    }
                );
            }
        }
        BrowserContextCommand::Use { id } => {
            let list = list(client, false)?;
            if !list.contexts.iter().any(|context| context.id == id) {
                return Err(format!(
                    "Browser context {id:?} does not exist. Next step: run `punarctl web-apps context list`."
                )
                .into());
            }
            let state = ActiveContext {
                version: 1,
                updated: utc_now_rfc3339(),
                active: id.clone(),
                active_cause: "manual".into(),
                bindings: read_active_state()
                    .map(|state| state.bindings)
                    .unwrap_or_default(),
            };
            write_json_atomic(&context_state_path()?, &state, USER_FILE_MODE)?;
            if json_output {
                print_json(&serde_json::to_value(&state).map_err(|e| e.to_string())?)?;
            } else {
                println!("ACTIVE · {id} · NEW WINDOWS USE THIS CONTEXT");
            }
        }
        BrowserContextCommand::Status => {
            let state = read_active_state().unwrap_or(ActiveContext {
                version: 1,
                updated: "not-recorded".into(),
                active: "personal".into(),
                active_cause: "default".into(),
                bindings: Vec::new(),
            });
            if json_output {
                print_json(&serde_json::to_value(&state).map_err(|e| e.to_string())?)?;
            } else {
                let mut out = fmt::masthead(style, "Browser context", &local_hostname());
                out.push_str(&fmt::rows(
                    style,
                    &[
                        Row::new("Active", &state.active, Slot::Ok, &state.active_cause),
                        Row::new(
                            "Existing windows",
                            "unchanged",
                            Slot::Neutral,
                            "contexts cannot migrate",
                        ),
                        Row::new(
                            "Automatic launch",
                            "off",
                            Slot::Neutral,
                            "workspace changes do not start apps",
                        ),
                    ],
                ));
                print!("{out}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn call(client: &Client, method: &str, params: Option<Value>) -> WebResult<Value> {
    client.call(method, params).map_err(WebAppsError::Call)
}

fn list(client: &Client, artifacts: bool) -> WebResult<WebAppsList> {
    let result = call(
        client,
        "webapps.list",
        if artifacts {
            Some(json!({"include_artifacts": true}))
        } else {
            None
        },
    )?;
    Ok(serde_json::from_value(result)
        .map_err(|error| format!("punard returned an invalid web-app list ({error})"))?)
}

fn print_result(
    json_output: bool,
    value: &Value,
    human: impl FnOnce() -> std::result::Result<String, String>,
) -> WebResult<ExitCode> {
    if json_output {
        print_json(value)?;
    } else {
        print!("{}", human()?);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_json(value: &Value) -> WebResult<()> {
    println!(
        "{}",
        serde_json::to_string(value)
            .map_err(|error| format!("result could not be encoded ({error})"))?
    );
    Ok(())
}

fn render_list(style: &Style, value: &Value) -> std::result::Result<String, String> {
    let list: WebAppsList = serde_json::from_value(value.clone())
        .map_err(|error| format!("invalid web-app list ({error})"))?;
    let mut out = fmt::masthead(style, "Web apps", &local_hostname());
    if list.apps.is_empty() {
        out.push_str(&fmt::note(style, "No web apps installed"));
    } else {
        let rows: Vec<Row> = list
            .apps
            .iter()
            .map(|view| {
                Row::new(
                    &view.app.id,
                    &view.app.context,
                    if view.app.managed {
                        Slot::Warn
                    } else {
                        Slot::Ok
                    },
                    &format!(
                        "{} · {} · {}",
                        view.app.name, view.app.workspace, view.app.origin
                    ),
                )
            })
            .collect();
        out.push_str(&fmt::rows(style, &rows));
    }
    out.push_str(&fmt::section(
        style,
        "Contexts",
        if list.policy.managed {
            "managed"
        } else {
            "personal"
        },
    ));
    out.push_str(&context_rows(style, &list.contexts));
    out.push_str(&fmt::rows(
        style,
        &[Row::new(
            "Install policy",
            if list.policy.allow_user_install {
                "allowed"
            } else {
                "restricted"
            },
            if list.policy.allow_user_install {
                Slot::Ok
            } else {
                Slot::Warn
            },
            &list.policy.policy_ids.join(", "),
        )],
    ));
    out.push_str(&fmt::note(
        style,
        "Contexts isolate browser state, not operating-system privilege",
    ));
    Ok(out)
}

fn render_contexts(style: &Style, value: &Value) -> std::result::Result<String, String> {
    let list: WebAppsList = serde_json::from_value(value.clone())
        .map_err(|error| format!("invalid web-app list ({error})"))?;
    let mut out = fmt::masthead(style, "Browser contexts", &local_hostname());
    out.push_str(&context_rows(style, &list.contexts));
    Ok(out)
}

fn context_rows(style: &Style, contexts: &[BrowserContext]) -> String {
    let active = active_context().unwrap_or_else(|_| "personal".into());
    let rows: Vec<Row> = contexts
        .iter()
        .map(|context| {
            Row::new(
                &context.id,
                if context.id == active {
                    "active"
                } else if context.derived {
                    "managed"
                } else {
                    "available"
                },
                if context.id == active {
                    Slot::Ok
                } else if context.derived {
                    Slot::Warn
                } else {
                    Slot::Neutral
                },
                &format!("{} · cookies · storage · sign-ins · history", context.name),
            )
        })
        .collect();
    fmt::rows(style, &rows)
}

fn render_show(style: &Style, value: &Value) -> std::result::Result<String, String> {
    let view: WebAppView = serde_json::from_value(value.clone())
        .map_err(|error| format!("invalid web-app record ({error})"))?;
    let mut out = fmt::masthead(style, &view.app.name, &local_hostname());
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Id",
                &view.app.id,
                Slot::Neutral,
                "persistent launcher identity",
            ),
            Row::new(
                "Origin",
                &view.app.origin,
                Slot::Neutral,
                &view.app.start_url,
            ),
            Row::new(
                "Context",
                &view.app.context,
                Slot::Ok,
                "state isolation, not a security boundary",
            ),
            Row::new(
                "Workspace",
                &view.app.workspace,
                Slot::Neutral,
                "compositor assignment",
            ),
            Row::new(
                "Managed",
                if view.app.managed { "yes" } else { "no" },
                if view.app.managed {
                    Slot::Warn
                } else {
                    Slot::Neutral
                },
                &view.app.policy_ids.join(", "),
            ),
        ],
    ));
    Ok(out)
}

fn sync(client: &Client) -> WebResult<usize> {
    // Inventory stays compact. Pull one bounded artifact bundle at a time so
    // a policy with many apps cannot amplify one IPC response into tens of
    // megabytes of base64 icons.
    let initial = list(client, false)?;
    for manifest in &initial.required_web_apps {
        let current = initial.apps.iter().find(|view| view.app.id == manifest.id);
        if current
            .is_some_and(|view| view.app.managed && record_matches_manifest(&view.app, manifest))
        {
            continue;
        }
        let installed = call(client, "webapps.install", Some(json!({"app": manifest})))?;
        let installed: WebAppInstallResult = serde_json::from_value(installed)
            .map_err(|error| format!("punard returned an invalid required-app result ({error})"))?;
        materialize(&installed.app, &installed.artifacts)?;
    }

    let list = list(client, false)?;
    let mut current = BTreeSet::new();
    let mut rules = Vec::new();
    for view in &list.apps {
        let detail = call(
            client,
            "webapps.get",
            Some(json!({"id": view.app.id, "include_artifacts": true})),
        )?;
        let detail: WebAppView = serde_json::from_value(detail).map_err(|error| {
            format!(
                "punard returned invalid derived artifacts for {:?} ({error})",
                view.app.id
            )
        })?;
        let artifacts = detail
            .artifacts
            .as_ref()
            .ok_or_else(|| format!("web app {:?} has no derived artifacts", detail.app.id))?;
        materialize(&detail.app, artifacts)?;
        current.insert(view.app.id.clone());
        rules.push(artifacts.window_rule.clone());
    }
    clean_stale_artifacts(&current)?;
    let rules = rules.join("\n");
    let rules = if rules.is_empty() {
        rules
    } else {
        format!("{rules}\n")
    };
    let rules_path = hypr_rules_path()?;
    atomic_write(&rules_path, rules.as_bytes(), DESKTOP_FILE_MODE)?;
    // The supported Lua config provider cannot accept `hyprctl keyword
    // source`. Reload the complete config so it evaluates the derived Lua
    // fragment from a clean rule set. This command is a fixed argv and a
    // missing compositor (for example, pre-session repair) is harmless.
    let _ = Command::new("hyprctl")
        .arg("reload")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    for context in &list.contexts {
        ensure_profile(&context.profile_path_rel)?;
    }
    reconcile_active_state(&list.contexts)?;
    Ok(list.apps.len())
}

fn reconcile_active_state(contexts: &[BrowserContext]) -> WebResult<()> {
    let path = context_state_path()?;
    let existing = read_active_state().ok();
    let (state, changed) = repaired_active_state(existing, contexts, utc_now_rfc3339());
    if changed {
        write_json_atomic(&path, &state, USER_FILE_MODE)?;
    }
    Ok(())
}

fn repaired_active_state(
    existing: Option<ActiveContext>,
    contexts: &[BrowserContext],
    now: String,
) -> (ActiveContext, bool) {
    let known: BTreeSet<&str> = contexts.iter().map(|context| context.id.as_str()).collect();
    let original = existing.clone();
    let mut state = existing.unwrap_or(ActiveContext {
        version: 1,
        updated: now.clone(),
        active: "personal".into(),
        active_cause: "default".into(),
        bindings: Vec::new(),
    });
    state
        .bindings
        .retain(|binding| known.contains(binding.context.as_str()));
    if !known.contains(state.active.as_str()) {
        state.active = "personal".into();
        state.active_cause = "default".into();
    }
    let changed = original.as_ref() != Some(&state);
    if changed {
        state.updated = now;
    }
    (state, changed)
}

fn record_matches_manifest(record: &WebAppRecord, manifest: &WebAppManifest) -> bool {
    record.v == manifest.v
        && record.id == manifest.id
        && record.name == manifest.name
        && record.start_url == manifest.start_url
        && record.context == manifest.context
        && record.workspace == manifest.workspace
}

fn materialize(app: &WebAppRecord, artifacts: &WebAppArtifacts) -> WebResult<()> {
    let data_home = data_home()?;
    let desktop_path = safe_relative(&data_home, &artifacts.desktop_path_rel)?;
    let icon_path = safe_relative(&data_home, &artifacts.icon_path_rel)?;
    let icon = base64::engine::general_purpose::STANDARD
        .decode(&artifacts.icon_png_b64)
        .map_err(|error| format!("punard returned invalid icon bytes ({error})"))?;
    let digest = format!("{:x}", sha2::Sha256::digest(&icon));
    if digest != app.icon.sha256 {
        return Err("punard's derived icon did not match the recorded digest".into());
    }
    atomic_write(
        &desktop_path,
        artifacts.desktop_entry.as_bytes(),
        DESKTOP_FILE_MODE,
    )?;
    atomic_write(&icon_path, &icon, DESKTOP_FILE_MODE)?;
    ensure_profile(&format!("punar/browser/contexts/{}", app.context))
}

fn remove_app_artifacts(id: &str) -> WebResult<()> {
    validate_context_id(id).map_err(|reason| format!("invalid web-app id: {reason}"))?;
    for path in [
        data_home()?.join(format!("applications/punar-webapp-{id}.desktop")),
        data_home()?.join(format!("icons/hicolor/256x256/apps/punar-webapp-{id}.png")),
    ] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("could not remove {} ({error})", path.display()).into());
            }
        }
    }
    Ok(())
}

fn clean_stale_artifacts(current: &BTreeSet<String>) -> WebResult<()> {
    for (directory, suffix) in [
        (data_home()?.join("applications"), ".desktop"),
        (data_home()?.join("icons/hicolor/256x256/apps"), ".png"),
    ] {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!("could not inspect {} ({error})", directory.display()).into());
            }
        };
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("could not inspect derived files ({error})"))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(id) = name
                .strip_prefix("punar-webapp-")
                .and_then(|name| name.strip_suffix(suffix))
            else {
                continue;
            };
            if validate_context_id(id).is_ok() && !current.contains(id) {
                fs::remove_file(entry.path())
                    .map_err(|error| format!("could not remove stale derived file ({error})"))?;
            }
        }
    }
    Ok(())
}

fn launch(
    client: &Client,
    id: &str,
    context: Option<&str>,
    dry_run: bool,
    json_output: bool,
) -> WebResult<ExitCode> {
    let result = call(
        client,
        "webapps.get",
        Some(json!({"id": id, "include_artifacts": false})),
    )?;
    let view: WebAppView = serde_json::from_value(result)
        .map_err(|error| format!("punard returned an invalid web-app record ({error})"))?;
    let context = context.unwrap_or(&view.app.context);
    require_context(client, context)?;
    let profile = data_home()?.join(format!("punar/browser/contexts/{context}"));
    if !dry_run {
        ensure_profile(&format!("punar/browser/contexts/{context}"))?;
    }
    let args = chromium_args_for_profile(Some(&view.app), &profile, true)?;
    if dry_run {
        let preview = launch_preview(&args);
        if json_output {
            print_json(&preview)?;
        } else {
            println!("DRY RUN · {}", preview["argv"]);
        }
        return Ok(ExitCode::SUCCESS);
    }
    exec_chromium(args)
}

fn browse(client: &Client, context: Option<&str>, urls: &[String]) -> WebResult<ExitCode> {
    let active = active_context().unwrap_or_else(|_| "personal".into());
    let context = context.unwrap_or(&active);
    require_context(client, context)?;
    let mut args = chromium_args(None, context, false)?;
    append_navigation_urls(&mut args, urls)?;
    exec_chromium(args)
}

/// Launch a catalog web fallback through the same closed browser path used by
/// installed M11 web apps. The catalog supplies only an id and HTTPS URL; it
/// cannot contribute an executable, flag, profile path, or shell fragment.
pub(crate) fn spawn_catalog_web(client: &Client, id: &str, url: &str) -> Result<(), String> {
    validate_context_id(id).map_err(|reason| format!("invalid catalog web-app id: {reason}"))?;
    if !url.starts_with("https://") {
        return Err("the curated web app must use HTTPS".into());
    }
    origin_from_start_url(url)
        .map_err(|reason| format!("the curated web-app URL was refused: {reason}"))?;

    let context = active_context().unwrap_or_else(|_| "personal".into());
    require_context(client, &context).map_err(|error| error.to_string())?;
    let profile = data_home()
        .map_err(|error| error.to_string())?
        .join(format!("punar/browser/contexts/{context}"));
    ensure_profile(&format!("punar/browser/contexts/{context}"))
        .map_err(|error| error.to_string())?;
    let args = chromium_args_for_target(Some((id, url)), &profile, true)
        .map_err(|error| error.to_string())?;
    Command::new(CHROMIUM_PROGRAM)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("Chromium could not start ({error})"))
}

fn require_context(client: &Client, id: &str) -> WebResult<()> {
    validate_context_id(id).map_err(|reason| format!("invalid browser context: {reason}"))?;
    if list(client, false)?
        .contexts
        .iter()
        .any(|context| context.id == id)
    {
        Ok(())
    } else {
        Err(format!(
            "Browser context {id:?} does not exist. Next step: run `punarctl web-apps context list`."
        )
        .into())
    }
}

fn chromium_args(
    app: Option<&WebAppRecord>,
    context: &str,
    app_mode: bool,
) -> WebResult<Vec<OsString>> {
    validate_context_id(context).map_err(|reason| format!("invalid browser context: {reason}"))?;
    let profile = data_home()?.join(format!("punar/browser/contexts/{context}"));
    fs::create_dir_all(&profile)
        .map_err(|error| format!("could not create browser profile ({error})"))?;
    fs::set_permissions(&profile, fs::Permissions::from_mode(USER_DIR_MODE))
        .map_err(|error| format!("could not protect browser profile ({error})"))?;
    chromium_args_for_profile(app, &profile, app_mode)
}

fn chromium_args_for_profile(
    app: Option<&WebAppRecord>,
    profile: &Path,
    app_mode: bool,
) -> WebResult<Vec<OsString>> {
    chromium_args_for_target(
        app.map(|app| (app.id.as_str(), app.start_url.as_str())),
        profile,
        app_mode,
    )
}

fn chromium_args_for_target(
    app: Option<(&str, &str)>,
    profile: &Path,
    app_mode: bool,
) -> WebResult<Vec<OsString>> {
    let mut args = Vec::new();
    if app_mode {
        let (id, start_url) =
            app.ok_or_else(|| "app-mode launch has no web-app identity".to_string())?;
        validate_context_id(id).map_err(|reason| format!("invalid web-app id: {reason}"))?;
        origin_from_start_url(start_url)
            .map_err(|reason| format!("the web-app start URL was refused: {reason}"))?;
        args.push(format!("--app={start_url}").into());
    }
    args.push(format!("--user-data-dir={}", profile.display()).into());
    if let Some((id, _)) = app {
        validate_context_id(id).map_err(|reason| format!("invalid web-app id: {reason}"))?;
        args.push(format!("--class=punar-webapp-{id}").into());
    }
    args.extend([
        // Punar is Wayland-only. `auto` selected X11 when this command was
        // launched from a system exercise despite a valid Wayland socket.
        OsString::from("--ozone-platform=wayland"),
        OsString::from("--no-first-run"),
        OsString::from("--no-default-browser-check"),
        OsString::from(format!("--disable-features={FIXED_DISABLE_FEATURES}")),
    ]);
    for arg in &args {
        let arg = arg.to_string_lossy();
        if !ALLOWED_FLAG_PREFIXES.iter().any(|allowed| {
            allowed.ends_with('=') && arg.starts_with(allowed) || arg.as_ref() == *allowed
        }) {
            return Err(format!(
                "closed Chromium argv builder produced an unsupported flag {arg:?}"
            )
            .into());
        }
    }
    Ok(args)
}

fn append_navigation_urls(args: &mut Vec<OsString>, urls: &[String]) -> WebResult<()> {
    if urls.is_empty() {
        return Ok(());
    }
    if urls.len() > 16 {
        return Err("a browser launch accepts at most 16 links".into());
    }
    for url in urls {
        origin_from_start_url(url)
            .map_err(|reason| format!("browser URL was refused: {reason}"))?;
    }
    // Chromium treats everything after this delimiter as navigation input,
    // never as an option, even if a future URL grammar changes.
    args.push(OsString::from("--"));
    args.extend(urls.iter().map(OsString::from));
    Ok(())
}

fn exec_chromium(args: Vec<OsString>) -> WebResult<ExitCode> {
    let error = Command::new(CHROMIUM_PROGRAM).args(args).exec();
    Err(format!(
        "Chromium could not start ({error}). Next step: verify the browser package is installed."
    )
    .into())
}

fn launch_preview(args: &[OsString]) -> Value {
    json!({
        "program": CHROMIUM_PROGRAM,
        "argv": args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    })
}

fn read_manifest(path: &Path) -> WebResult<WebAppManifest> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("could not read manifest ({error})"))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(format!(
            "Manifest must be a regular file no larger than {MAX_MANIFEST_BYTES} bytes."
        )
        .into());
    }
    let bytes = fs::read(path).map_err(|error| format!("could not read manifest ({error})"))?;
    Ok(serde_json::from_slice(&bytes).map_err(|error| format!("manifest is invalid ({error})"))?)
}

fn confirmed(skip: bool, prompt: &str) -> WebResult<bool> {
    if skip || !std::io::stdin().is_terminal() {
        return Ok(true);
    }
    eprint!("{prompt}");
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| error.to_string())?;
    Ok(answer.trim() == "yes")
}

fn slug(name: &str) -> WebResult<String> {
    let mut output = String::new();
    let mut hyphen = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            hyphen = false;
        } else if !output.is_empty() && !hyphen {
            output.push('-');
            hyphen = true;
        }
        if output.len() == 32 {
            break;
        }
    }
    while output.ends_with('-') {
        output.pop();
    }
    validate_context_id(&output)
        .map_err(|reason| format!("name cannot form a safe id: {reason}"))?;
    Ok(output)
}

fn title(id: &str) -> String {
    id.split('-')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| format!("{}{}", first.to_ascii_uppercase(), chars.as_str()))
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn absolute_path(path: &Path) -> WebResult<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| error.to_string())?)
    }
}

fn user_home() -> WebResult<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "HOME is not an absolute path".into())
}

fn data_home() -> WebResult<PathBuf> {
    Ok(env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or(user_home()?.join(".local/share")))
}

fn config_home() -> WebResult<PathBuf> {
    Ok(env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or(user_home()?.join(".config")))
}

fn state_home() -> WebResult<PathBuf> {
    Ok(env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or(user_home()?.join(".local/state")))
}

fn context_state_path() -> WebResult<PathBuf> {
    Ok(state_home()?.join("punar/browser-context.json"))
}
fn hypr_rules_path() -> WebResult<PathBuf> {
    Ok(config_home()?.join("hypr/punar-webapps.lua"))
}

fn safe_relative(base: &Path, relative: &str) -> WebResult<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("punard returned an unsafe derived path".into());
    }
    Ok(base.join(path))
}

fn ensure_profile(relative: &str) -> WebResult<()> {
    let path = safe_relative(&data_home()?, relative)?;
    fs::create_dir_all(&path)
        .map_err(|error| format!("could not create {} ({error})", path.display()))?;
    Ok(
        fs::set_permissions(&path, fs::Permissions::from_mode(USER_DIR_MODE))
            .map_err(|error| format!("could not protect {} ({error})", path.display()))?,
    )
}

fn remove_profile(relative: &str) -> WebResult<()> {
    let path = safe_relative(&data_home()?, relative)?;
    match fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("could not purge {} ({error})", path.display()).into()),
    }
}

fn active_context() -> WebResult<String> {
    Ok(read_active_state()
        .map(|state| state.active)
        .unwrap_or_else(|_| "personal".into()))
}

fn read_active_state() -> WebResult<ActiveContext> {
    let bytes = fs::read(context_state_path()?).map_err(|error| error.to_string())?;
    let state: ActiveContext = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    validate_context_id(&state.active)
        .map_err(|reason| format!("active context is invalid: {reason}"))?;
    Ok(state)
}

fn write_json_atomic(path: &Path, value: &impl Serialize, mode: u32) -> WebResult<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    atomic_write(path, &bytes, mode)
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> WebResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| "derived file has no parent".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create {} ({error})", parent.display()))?;
    let temp = parent.join(format!(
        ".punar-webapp-tmp-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)
            .map_err(|error| format!("could not create {} ({error})", temp.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("could not write {} ({error})", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("could not sync {} ({error})", temp.display()))?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
        fs::rename(&temp, path)
            .map_err(|error| format!("could not replace {} ({error})", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("could not sync {} ({error})", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    Ok(result?)
}

fn local_hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "this device".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(id: &str) -> BrowserContext {
        BrowserContext {
            id: id.into(),
            name: title(id),
            derived: false,
            deletable: id != "personal",
            isolates: vec!["storage".into()],
            profile_path_rel: format!("punar/browser/contexts/{id}"),
            simulated: Vec::new(),
            not_yet_observed: Vec::new(),
            source: None,
        }
    }

    fn app() -> WebAppRecord {
        serde_json::from_value(json!({
            "v": 1, "id": "linear", "name": "Linear",
            "start_url": "https://linear.app/inbox", "origin": "https://linear.app",
            "context": "atlas", "icon": {"kind":"generated", "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "path_rel":"icons/hicolor/256x256/apps/punar-webapp-linear.png"},
            "workspace": "atlas", "installed_at": "2026-09-04T00:00:00Z",
            "installed_by": {"uid":1000,"source":"cli"}, "policy_ids":["personal-defaults"], "managed":false
        })).unwrap()
    }

    #[test]
    fn slug_and_relative_paths_reject_injection() {
        assert_eq!(slug("Linear Notes").unwrap(), "linear-notes");
        assert!(slug("---").is_err());
        assert!(safe_relative(Path::new("/tmp/base"), "../etc/passwd").is_err());
        assert!(safe_relative(Path::new("/tmp/base"), "/etc/passwd").is_err());
    }

    #[test]
    fn chromium_builder_has_only_the_closed_flag_vocabulary() {
        let args =
            chromium_args_for_profile(Some(&app()), Path::new("/home/alice/atlas"), true).unwrap();
        assert_eq!(args.len(), 7);
        assert!(args.contains(&OsString::from("--ozone-platform=wayland")));
        for arg in args {
            let arg = arg.to_string_lossy();
            assert!(
                ALLOWED_FLAG_PREFIXES
                    .iter()
                    .any(|allowed| allowed.ends_with('=') && arg.starts_with(allowed)
                        || arg.as_ref() == *allowed)
            );
            assert!(!arg.contains("no-sandbox"));
            assert!(!arg.contains("ignore-certificate"));
        }
    }

    #[test]
    fn dry_run_preview_is_exact_and_has_no_shell_field() {
        let args =
            chromium_args_for_profile(Some(&app()), Path::new("/home/alice/atlas"), true).unwrap();
        let preview = launch_preview(&args);
        assert_eq!(preview["program"], json!("/usr/lib/chromium/chromium"));
        assert_eq!(preview["argv"].as_array().unwrap().len(), 7);
        assert!(preview.get("command").is_none());
        assert!(preview.get("shell").is_none());
    }

    #[test]
    fn navigation_is_delimited_and_rejects_flag_like_input() {
        let mut args =
            chromium_args_for_profile(None, Path::new("/home/alice/personal"), false).unwrap();
        append_navigation_urls(&mut args, &["https://example.com/docs".into()]).unwrap();
        assert_eq!(args[5], OsString::from("--"));
        assert_eq!(args[6], OsString::from("https://example.com/docs"));

        assert!(append_navigation_urls(&mut args, &["--no-sandbox".into()]).is_err());
    }

    #[test]
    fn deleting_active_context_falls_back_and_removes_stale_bindings() {
        let existing = ActiveContext {
            version: 1,
            updated: "before".into(),
            active: "atlas".into(),
            active_cause: "manual".into(),
            bindings: vec![
                ContextBinding {
                    workspace: "atlas".into(),
                    context: "atlas".into(),
                },
                ContextBinding {
                    workspace: "one".into(),
                    context: "personal".into(),
                },
            ],
        };
        let (state, changed) =
            repaired_active_state(Some(existing), &[context("personal")], "after".into());

        assert!(changed);
        assert_eq!(state.active, "personal");
        assert_eq!(state.active_cause, "default");
        assert_eq!(state.updated, "after");
        assert_eq!(state.bindings.len(), 1);
        assert_eq!(state.bindings[0].context, "personal");
    }

    #[test]
    fn valid_active_context_is_not_rewritten() {
        let existing = ActiveContext {
            version: 1,
            updated: "before".into(),
            active: "atlas".into(),
            active_cause: "manual".into(),
            bindings: Vec::new(),
        };
        let (state, changed) = repaired_active_state(
            Some(existing.clone()),
            &[context("personal"), context("atlas")],
            "after".into(),
        );

        assert!(!changed);
        assert_eq!(state, existing);
    }
}
