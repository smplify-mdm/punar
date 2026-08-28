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

Spotify is native on x86_64 because its upstream Linux payload is x86_64-only.
ARM64/Raspberry Pi selects the official Spotify web player in Chromium. Both
appear as one catalog identity; Punar never labels the ARM path as a native app.

Run `tools/verify-app-catalog.sh` during a catalog refresh. It builds a clean
temporary Flatpak user installation from the committed remote descriptor,
queries the pinned commit, and checks its commit, runtime and exact metadata
digest. A refresh changes catalog bytes deliberately and must go through the
normal signed-image review.

Current Flathub descriptor SHA-256:
`3371dd250e61d9e1633630073fefda153cd4426f72f4afa0c3373ae2e8fea03a`.
