#!/usr/bin/env bash
# Recompute the countable claims in Punar's durable documents from the tree.
#
# WHY THIS EXISTS. BUILD-QUEUE.md, HANDOFF.md and IMPLEMENTATION_STATUS.md are
# what the next session starts from, and several of their statements had gone
# quietly false: the app catalog was described as 22 entries when it held 50,
# the shipped wallpaper default was named as one image when the tree shipped
# another, and — worst of all — the recipe for adding an in-VM check pointed at
# a profile directory that has held no checks since 2026-08-27, so the very
# next check written from it would have been staged where nothing starts it.
# None of that could go red. A false status claim is a project defect here, and
# this is the smallest instrument that turns one into a build failure.
#
# WHAT IT DELIBERATELY DOES NOT CHECK. Line counts, assertion totals, and prose
# milestone status. Those have no single unambiguous source — an assertion
# count comes from a RUN, not from reading the tree, and a line count changes
# on every commit. A gate that blocks unrelated work gets weakened the first
# time it does, which is the failure BUILD-QUEUE section 8 forbids. Every check
# below has exactly one answer that the tree alone can give.
set -euo pipefail

cd "$(dirname "$0")/.."
FAILED=0

fail() { printf 'FAIL %s\n' "$*" >&2; FAILED=1; }
pass() { printf 'ok   %s\n' "$*"; }

# --- 1. Every check-script path a document cites must exist ------------------
# This is the one that bit. `<name>` and `m*` are placeholders in the recipe
# and are skipped; anything else naming a concrete script must resolve.
cited=0
while IFS= read -r path; do
    case "${path}" in
        *'<'*|*'*'*) continue ;;
    esac
    cited=$((cited + 1))
    if [ ! -f "${path}" ]; then
        fail "a document cites ${path}, which does not exist"
    fi
done < <(grep -rhoE 'os/images/mkosi\.profiles/[a-z]+/mkosi\.extra/usr/lib/punar/[A-Za-z0-9_*<>-]+\.sh' \
            --include='*.md' . 2>/dev/null | sort -u)
if [ "${cited}" -eq 0 ]; then
    fail "no concrete check-script path was cited anywhere; this check went vacuous"
else
    pass "${cited} cited check-script path(s) all exist"
fi

# --- 2. The app-catalog size --------------------------------------------------
catalog_n="$(python3 -c 'import json,sys; print(len(json.load(open("catalog/catalog.json"))["apps"]))')"
claimed=0
while IFS= read -r n; do
    claimed=$((claimed + 1))
    if [ "${n}" != "${catalog_n}" ]; then
        fail "a document claims ${n} reviewed identities; catalog/catalog.json holds ${catalog_n}"
    fi
done < <(grep -rhoE '[0-9]+ reviewed (app )?identities' --include='*.md' . 2>/dev/null \
            | grep -oE '^[0-9]+' | sort -u)
if [ "${claimed}" -eq 0 ]; then
    fail "no document states the catalog size; this check went vacuous"
else
    pass "every stated catalog size matches catalog.json (${catalog_n} apps)"
fi

# --- 3. The shell's IPC target set vs the list HANDOFF prints ----------------
# `surfaceprobe` belongs to surface-probe.qml, the isolated cost harness, and
# is excluded from the production list on purpose.
tree_targets="$(grep -rhoE 'target: "[a-z]+"' shell/punar-shell/ \
    | sed 's/.*"\(.*\)"/\1/' | grep -v '^surfaceprobe$' | sort -u | tr '\n' ' ' | sed 's/ $//')"
doc_targets="$(python3 tools/doc_freshness_targets.py)"
if [ "${tree_targets}" = "${doc_targets}" ]; then
    pass "HANDOFF names exactly the shell's IPC targets"
else
    fail "HANDOFF's IPC target list disagrees with the shell"
    printf '     tree: %s\n     doc:  %s\n' "${tree_targets}" "${doc_targets}" >&2
fi

# --- 4. The wallpaper catalog the in-VM gate asserts vs the one that ships ---
wall_n="$(grep -c '"id":' shell/punar-shell/Services/WallpaperState.qml)"
gate_n="$(grep -oE '\(\.wallpapers \| length\) == [0-9]+' \
    os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/surfaces-check.sh \
    | grep -oE '[0-9]+$' | head -1)"
if [ "${wall_n}" = "${gate_n}" ]; then
    pass "the wallpaper gate asserts the number of wallpapers that ship (${wall_n})"
else
    fail "WallpaperState ships ${wall_n} wallpapers; surfaces-check.sh asserts ${gate_n}"
fi

wall_default="$(grep -oE 'defaultId: "[a-z-]+"' shell/punar-shell/Services/WallpaperState.qml \
    | sed 's/.*"\(.*\)"/\1/')"
gate_default="$(grep -oE '\.default == "[a-z-]+"' \
    os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/surfaces-check.sh \
    | sed 's/.*"\(.*\)"/\1/' | head -1)"
if [ "${wall_default}" = "${gate_default}" ]; then
    pass "the wallpaper gate asserts the shipped default (${wall_default})"
else
    fail "the shipped default is '${wall_default}'; surfaces-check.sh asserts '${gate_default}'"
fi

# --- 5. The greeter's first frame vs the shipped default --------------------
# The greeter cannot read the desktop's preference: it runs as its own user
# before any session exists and must not take its first frame from a
# user-writable file, so the path is hardcoded and kept in sync BY HAND.
# A hand-sync rule with nothing checking it is a rule that has already drifted.
default_file="$(python3 - <<'PY'
import re, pathlib
src = pathlib.Path("shell/punar-shell/Services/WallpaperState.qml").read_text()
want = re.search(r'defaultId: "([a-z-]+)"', src).group(1)
for block in re.findall(r'\{(.*?)\}', src, re.S):
    m = re.search(r'"id":\s*"([a-z-]+)"', block)
    if m and m.group(1) == want:
        f = re.search(r'"file":\s*"([^"]*)"', block)
        print(f.group(1) if f else "")
        break
PY
)"
if [ -z "${default_file}" ]; then
    pass "the shipped default is a vector plate; the greeter's raster cannot track it"
elif grep -q "assets/${default_file}\"" shell/punar-shell/Greeter/shell.qml; then
    pass "the greeter's first frame is the shipped default (${default_file})"
else
    fail "the greeter's hardcoded first frame is not the shipped default (${default_file})"
    grep -n 'Wallpaper/assets/' shell/punar-shell/Greeter/shell.qml >&2 || true
fi

if [ "${FAILED}" -ne 0 ]; then
    printf '\ndocument freshness: FAILED\n' >&2
    exit 1
fi
printf '\ndocument freshness: all checks passed\n'
