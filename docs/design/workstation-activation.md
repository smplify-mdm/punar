# First desktop — workstation activation

**Status:** accepted product direction, 2026-08-28; implementation pending.
**Owner direction:** after the minimal local-account flow, help people choose
AI tools, secure connectivity, and a practical development starting point,
including REST API testing. Keep the base OS lean and make every action real.

This is not another page in account creation. `onboarding-flow.md` remains one
card with three values. Workstation activation appears only after the desktop
is usable, is dismissible in one action, and can always be reopened from
Command Center or System Control. Skipping it changes no capability.

## Product rules

1. **No demo data.** The guide never creates a project, agent session, alert,
   API history item, VPN connection, or installed-state record to make a screen
   look populated. Progress is derived from observed state.
2. **Choose, do not bundle.** The signed image keeps only the small primitives
   already justified by the developer baseline. Editors, graphical API clients,
   AI products, and overlay-network clients are installed on demand.
3. **Names describe different products.** `Claude` is an official cloud web
   app; `Claude Code` is a local coding-agent client. `ChatGPT` is a web app;
   an OpenAI coding agent is listed under its own product name. The UI never
   collapses either pair into one installed state.
4. **Architecture is a gate.** A source is offered only when the catalog has a
   reviewed source for the observed architecture. Official web apps may be the
   honest ARM fallback; an x86 binary is never presented as installable on a
   Raspberry Pi.
5. **Every install remains typed.** A guide action carries a catalog id to the
   existing application/agent capability. It cannot provide a URL, package
   name, shell command, or installer flags to a privileged process.
6. **Cloud and network consequences are stated before action.** Sign-in needs,
   data leaving the device, requested filesystem/network access, background
   services, and update ownership are shown in plain language.
7. **Convenience never weakens the floor.** Every optional tool must use a
   reviewed, digest-bound source; run with the least filesystem, device,
   credential, and network authority it needs; and remain subject to the same
   approval and audit contracts as a manually installed application. There is
   no onboarding bypass, trusted-vendor bypass, or “developer mode” bypass.
8. **Privacy defaults survive activation.** The guide has no analytics, does
   not upload an installed-tool inventory, does not pre-authorize cloud access,
   and does not start a background service merely because its card was viewed.

## The optional guide

The surface is one responsive page, not a blocking wizard. It has three compact
sections and a persistent **Finish later** action.

### 1. Choose how you build

The first group is labelled **AI assistants and coding tools**, not simply
“AI agents.” It can include:

- official ChatGPT and Claude web apps;
- reviewed Claude Code, Gemini CLI, Codex, or other agent installers when a
  persistent, signature-verifiable source exists for this architecture;
- Cursor and other editors through the normal Editors catalog category;
- a **No AI tools** choice that installs nothing and is treated as complete.

Cards say `WEB APP`, `EDITOR`, or `CODING AGENT` beside the product name. An
installed coding agent still creates no session: a session appears in the AI
panel only after the user explicitly launches it in a project. Authentication
is performed in the vendor's own flow; Punar does not collect vendor tokens.

### 2. Connect securely

Three distinct mechanisms must remain distinct:

- **WireGuard:** native protocol support and import/create UI. Private keys are
  secret-broker material, configuration is a typed capability, and the screen
  shows the routes and DNS effect before activation.
- **Tailscale:** optional third-party client from a reviewed, architecture-
  compatible source. Its account/control-plane relationship and background
  service are disclosed before install.
- **Smplify Private Relay:** a separate subscription/enterprise route. It is
  shown only when a real service is available to the user or organization. It
  must never be presented as an implemented privacy guarantee while the two-hop
  service remains unbuilt.

Punar does not market these as interchangeable “secure VPN” buttons. The UI
explains whether the choice provides a private peer network, a configured VPN
tunnel, an organization route, or privacy relay protection.

### 3. Make something real

The final section offers **Create a project** and **Test an API**. Both use the
project environment rather than installing a host toolchain.

Project creation chooses a small template (empty, web service, CLI, or existing
repository), creates the manifest, and starts a rootless Podman environment.
Language/runtime versions, Kubernetes tools, cloud CLIs, and databases belong
to that project. Local Kubernetes remains an optional project add-on, not a
resident cluster.

**Test an API** opens the Punar API Workbench in the new project. Its minimum
useful version has:

- method, URL, query, headers, and body editing;
- JSON/text response rendering, status, duration, size, and TLS identity;
- project-local collections and `dev` / `staging` / `production` environments;
- secret placeholders resolved by `punar-secrets`, never copied into collection
  files, command history, logs, screenshots, or exported `curl` commands;
- cancellation, timeouts, certificate errors, redirects, and offline errors
  with explicit recovery actions;
- an optional local mock server that runs inside the project container and
  stops with the project.

TLS certificate and hostname verification are always enabled by default. A
temporary exception requires a human-reviewed capability grant scoped to that
project and request environment; it is never silently persisted. Redirects do
not forward authorization or cookie material across origins. Listening mock
servers bind to loopback unless the user reviews an explicit network-exposure
request. Response bodies are bounded before rendering or persistence, and the
workbench treats imported collections as untrusted data rather than commands.

`curl` and `jq` remain available in the terminal for experts. The graphical
workbench is installable/on-demand so it adds no idle daemon or base-image
weight.

## Entry and empty states

On the first desktop, one quiet, dismissible notification says **Set up your
workstation** and opens this page. It never steals focus. The Applications,
AI, Network, and Projects surfaces also expose contextual entry points.

Empty states are truthful and actionable:

- AI panel: **No AI sessions yet** · choose a coding agent or launch an
  installed one in a project;
- Network: **No secure connection configured** · import WireGuard, install
  Tailscale, or learn about an available relay;
- Projects: **No projects yet** · create one or open an existing repository;
- API Workbench: **No requests yet** · make a request or import a collection.

## Definition of done

1. Fresh release reaches the desktop without installing or fabricating any of
   the options above.
2. Finish later dismisses the guide permanently until explicitly reopened.
3. Search and guide results are identical for the same signed catalog and
   architecture; unsupported sources have no actionable install button.
4. Web app, editor, and coding-agent labels cannot be confused in accessibility
   text or visuals.
5. Every action opens its real review/permission step and observed state updates
   only after backend verification succeeds.
6. WireGuard/Tailscale/relay routes, DNS effects, service ownership, and cloud
   dependencies are shown before activation and are reversible.
7. A generated project can build/run a service, expose it to the host browser,
   test it through the API Workbench, and be destroyed without changing the
   source tree or leaving a resident service.
8. The guide adds zero steady-state wakeups and is unloaded after close.
9. Security-negative tests prove that unsigned sources, architecture mismatch,
   cross-origin credential forwarding, invalid TLS, secret serialization,
   host-level toolchain writes, and unreviewed listening sockets fail closed.

## Vendor-source rule

Linux and ARM availability changes. Catalog maintainers re-check the official
vendor source at every pin rather than copying this document's date into an
eternal support claim: [Claude Code setup](https://code.claude.com/docs/en/setup),
[Gemini CLI](https://github.com/google-gemini/gemini-cli),
[Cursor downloads](https://www.cursor.com/downloads),
[Tailscale for Linux](https://tailscale.com/download/linux), and
[WireGuard installation](https://www.wireguard.com/install/).
