#!/usr/bin/env bash
# Prevent regressions in the launcher/application-library lifecycle contract.
# Runtime window focus is still exercised in the VM; this cheap gate ensures
# the shipped QML cannot relabel an installed product as installable or launch
# a duplicate before trying to activate an existing toplevel.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APPS="${REPO_ROOT}/shell/punar-shell/Services/Apps.qml"
COMMAND="${REPO_ROOT}/shell/punar-shell/CommandCenter/CommandCenter.qml"
BROWSER="${REPO_ROOT}/shell/punar-shell/CommandCenter/ApplicationBrowser.qml"
SURFACES="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/surfaces-check.sh"

fail() {
    echo "app-launcher-contract-test: FAIL: $*" >&2
    exit 1
}

contains() {
    local file=$1 text=$2
    grep -Fq -- "${text}" "${file}" \
        || fail "${file#"${REPO_ROOT}/"} is missing contract text: ${text}"
}

# Installed state joins the live desktop index to both catalog identity fields,
# while a just-completed transaction updates synchronously before inotify.
contains "${APPS}" 'function recordCatalogInstallState(id: string, installed: bool): void'
contains "${APPS}" 'function catalogAppInstalled(app: var): bool'
contains "${APPS}" 'var appId = String(sources[i].appId || "").toLowerCase();'
contains "${APPS}" 'var desktopId = String(sources[i].desktopId || "").toLowerCase();'
contains "${BROWSER}" 'if (inCategory && !Apps.catalogAppInstalled(source[i]))'
contains "${COMMAND}" 'Apps.catalogAppInstalled(available[i])'
contains "${COMMAND}" '(installed ? "installed · open"'

# Selecting an installed catalog row opens/focuses; only absent software enters
# the inspection/install path.
contains "${COMMAND}" 'if (item.installed === true)'
contains "${COMMAND}" 'root.openCatalogApp(item.arg, item.catalog);'
contains "${COMMAND}" 'root.askApp(item.arg);'

# Existing windows are activated through the compositor before any desktop
# entry execution. The typed focus dispatcher performs the workspace switch.
contains "${APPS}" 'list[i].activate();'
contains "${APPS}" 'HyprlandActions.focusWindow("class:^" + exactClass + "$");'
contains "${APPS}" 'if (root.focusExisting(root.entryWindowCandidates(entry)))'
contains "${APPS}" 'entry.execute();'

# The canonical desktop gate exercises the user-visible consequence rather
# than relying on the source ordering alone: an existing app is left on a
# different workspace, selected again, and must focus without duplication.
contains "${SURFACES}" 'selecting an open app switched to workspace 8 without launching a duplicate'
# Literal source-contract fragments intentionally contain shell syntax.
# shellcheck disable=SC2016
contains "${SURFACES}" '[ "${active_workspace}" = "8" ]'
# shellcheck disable=SC2016
contains "${SURFACES}" '[ "${client_state}" = "$(printf '\''1\ttrue\ttrue'\'')" ]'

# Bulk update is a visible, bounded catalog action. It checks observed daemon
# state first, shows live progress, and invokes only the typed --all verb.
contains "${BROWSER}" 'signal updateAllRequested()'
contains "${BROWSER}" ': "Update all · " + root.updatesAvailable;'
contains "${BROWSER}" 'visible: root.updateBusy'
contains "${COMMAND}" '["punarctl", "--json", "app", "list"]'
contains "${COMMAND}" '["punarctl", "--json", "app", "update", "--all", "--yes"]'
contains "${COMMAND}" 'root.appUpdateMessage = "Updating " + root.appUpdatesAvailable'

# Package helper launchers are not separate products. Keep the filter exact so
# ordinary third-party applications remain discoverable, and give the useful
# hardware viewer a product name instead of exposing its implementation name.
for helper_id in \
    footclient foot-server thunar-settings thunar-bulk-rename \
    xfce4-about bssh bvnc avahi-discover; do
    contains "${APPS}" "\"${helper_id}\""
done
contains "${APPS}" 'if (root.hiddenProductEntryIds.indexOf(id) !== -1)'
contains "${APPS}" 'if (value === "lstopo")'
contains "${APPS}" 'return "Hardware Information";'
contains "${SURFACES}" '["footclient", "foot-server", "thunar-settings",'
contains "${SURFACES}" '(["footclient", "foot-server", "thunar-settings",'
contains "${SURFACES}" '); .name == "Hardware Information")'

python3 - "${APPS}" <<'PY'
import sys

text = open(sys.argv[1], encoding="utf-8").read()
focus = text.index("if (root.focusExisting(root.entryWindowCandidates(entry)))")
execute = text.index("entry.execute();", focus)
if focus >= execute:
    raise SystemExit("existing-window focus no longer precedes process launch")
PY

echo 'app-launcher-contract-test: PASS'
