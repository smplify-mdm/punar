# Punar application catalog

`catalog.json` is signed-image input, not a live app-store index. Each native
source names an exact Flatpak commit and the SHA-256 of `flatpak remote-info
--show-metadata` for that commit. `punard` repeats that query immediately
before install, derives permissions and containment from the returned metadata,
and refuses a digest mismatch.

The catalog deliberately contains no static `sandboxed` field. That word is a
runtime result, never publisher copy. It also contains no application payload:
the base image ships only Flatpak itself, this catalog, and Flathub's signed
remote descriptor. Apps and runtimes are fetched on demand into shared `/var`.

The current browseable catalog contains 22 reviewed identities across AI,
Developer, Diagnostics, Writing, Security, Browsers, Communication, and Media.
The developer set includes VSCodium, Dev Toolbox, DBeaver Community, HTTPie,
Postman, Meld, and Podman Desktop. Logs, Mission Center, and Wireshark cover
graphical troubleshooting; Apostrophe covers Markdown editing and preview;
KeePassXC is the first security utility. Each of these additions has separately
pinned x86_64 and ARM64 sources.

Spotify, Slack, and Discord use pinned native Flatpaks on x86_64 and an
explicitly labelled Chromium web-app fallback on ARM64 where their publishers
do not provide a native Linux payload. ChatGPT and Claude have distinct
official web and native preview/beta entries on both architectures. Punar never
labels a web fallback as a native installation.

Search is offline and deterministic. It matches every query term against the
catalog id, display name, summary, category, and curated keywords. That makes
queries such as `Claude`, `ChatGPT`, `AI assistant`, `REST API`, `Markdown`,
`logs`, and `developer` discover the expected entries without turning a search
box into an unbounded package-execution surface. The browse UI also exposes the
same taxonomy as category controls; typing always searches the whole catalog.

Flathub AppStream is the upstream discovery and graphical metadata source, not
the device's trust decision. Punar prefers publisher-verified entries where
available, records community packaging explicitly, admits only reviewed app
ids, and freezes the selected commit and metadata digest into the signed OS
catalog. See `CURATION.md` for admission and refresh policy.

`icons/` contains local identity marks shown by the shell. The schema and
`punard` accept basename-only SVG or PNG names; image staging copies those files
beside the catalog. Installed application icons still come from their
freedesktop desktop entries, not this directory.

Run `tools/verify-app-catalog.sh` during a catalog refresh. It builds a clean
temporary Flatpak user installation from the committed remote descriptor,
queries the pinned commit, and checks its commit, runtime and exact metadata
digest. A refresh changes catalog bytes deliberately and must go through the
normal signed-image review.

Current Flathub descriptor SHA-256:
`3371dd250e61d9e1633630073fefda153cd4426f72f4afa0c3373ae2e8fea03a`.
