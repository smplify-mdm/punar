# Chromium integration boundary

Punar composes the upstream Chromium package. It does not patch the browser,
inject code into it, or provide a browser daemon.

The integration boundary consists of:

- a closed argv builder in `punarctl`;
- a generic `punar-browser.desktop` plus a hidden vendor-id compatibility entry;
- root-owned web-app and context records in `punard`;
- rebuildable user-owned desktop entries, icons, profiles, and compositor rules;
- a closed managed-policy allowlist; and
- an independent forbidden-token list scanned across every browser entry point.

`policy-allowlist.json` controls what the daemon may write. Security-hardening
keys are one-direction pins and organization policy cannot weaken them.
`forbidden-tokens.txt` controls what must remain absent from launchers, policy
directories, wrapper flag files, configuration, shipped shell code, and live
browser process command lines. The runtime verifier excludes the denylist file
itself from its scan and verifies the file's reviewed digest separately.

All Punar-owned launch paths execute `/usr/lib/chromium/chromium` directly.
The supported Arch and Debian substrates install the upstream binary there;
bypassing their wrappers prevents mutable flag files from silently extending
the reviewed argv. Navigation values are validated and follow a `--` delimiter.

Browser contexts isolate Chromium state inside one Unix account. They are not
separate users, kernel boundaries, or protection from a browser sandbox escape.

On native Ozone/Wayland, Chromium app-mode windows publish an xdg app id
derived from the validated start URL and the `Default` profile basename;
`--class` is not that window identity. `punard` reproduces Chromium's upstream
derivation for `StartupWMClass` and compositor matching, while retaining the
stable `punar-webapp-<id>` class as an X11/compatibility alternative. The M11
runtime gate starts on another workspace and verifies the native client is
actually routed to its assigned workspace.
