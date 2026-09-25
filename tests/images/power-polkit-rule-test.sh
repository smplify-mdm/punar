#!/usr/bin/env bash
# Evaluates the shipped power rule (50-punar-power.rules) the way polkitd does:
# the file's own JavaScript, run against a stand-in `polkit` object and the
# subjects that matter.
#
# WHAT IT HOLDS (F0-S1; docs/api/ipc.md section 23.2):
#   - the person at the active local seat restarts or shuts down with no
#     password when nobody else is signed in (the WP-01 decision);
#   - with another session open, only a device administrator (group
#     punar-admin) may, and anyone else is told no rather than challenged;
#   - a remote or inactive session, and a subject outside `punar`, get no
#     opinion from this file;
#   - the -ignore-inhibit actions are never granted.
#
# polkitd's JavaScript is ECMAScript; node evaluates the same file. CI's
# runners carry node; locally, `docker run --rm -v "$PWD:/w" -w /w
# node:22-slim ./tests/images/power-polkit-rule-test.sh` needs bash, which that
# image has.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RULE="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/polkit-1/rules.d/50-punar-power.rules"

command -v node >/dev/null 2>&1 || {
    echo "power-polkit-rule-test: FAIL: node is required to evaluate the rule" >&2
    exit 1
}
[ -f "${RULE}" ] || {
    echo "power-polkit-rule-test: FAIL: ${RULE#"${REPO_ROOT}/"} is missing" >&2
    exit 1
}

node - "${RULE}" <<'JS'
const fs = require("fs");
const rulePath = process.argv[2];
const rules = [];
const polkit = {
  Result: { YES: "yes", NO: "no", AUTH_ADMIN: "auth_admin", AUTH_ADMIN_KEEP: "auth_admin_keep",
            AUTH_SELF: "auth_self", AUTH_SELF_KEEP: "auth_self_keep", NOT_HANDLED: null },
  addRule(fn) { rules.push(fn); },
  addAdminRule() {},
  log() {},
};
new Function("polkit", fs.readFileSync(rulePath, "utf8"))(polkit);
if (rules.length === 0) {
  console.error("power-polkit-rule-test: FAIL: the file adds no rule");
  process.exit(1);
}

function subject(groups, { local = true, active = true } = {}) {
  return { local, active, user: "someone", groups, isInGroup(g) { return groups.includes(g); } };
}
function decide(actionId, subj) {
  for (const rule of rules) {
    const answer = rule({ id: actionId, lookup() { return ""; } }, subj);
    if (answer !== null && answer !== undefined) return answer;
  }
  return null;
}

const person = subject(["punar"]);
const admin = subject(["punar", "punar-admin"]);
const failures = [];
const expect = (what, got, want) => {
  if (got !== want) failures.push(`${what}: got ${got}, want ${want}`);
};

for (const action of ["org.freedesktop.login1.reboot", "org.freedesktop.login1.power-off"]) {
  expect(`${action} for the person at the seat`, decide(action, person), "yes");
  expect(`${action} for an administrator`, decide(action, admin), "yes");
}
for (const action of ["org.freedesktop.login1.reboot-multiple-sessions",
                      "org.freedesktop.login1.power-off-multiple-sessions"]) {
  expect(`${action} for an administrator`, decide(action, admin), "yes");
  expect(`${action} for a person who is not an administrator`, decide(action, person), "no");
  expect(`${action} for a remote administrator`,
         decide(action, subject(["punar", "punar-admin"], { local: false })), null);
  expect(`${action} for an inactive administrator`,
         decide(action, subject(["punar", "punar-admin"], { active: false })), null);
  expect(`${action} for punar-admin outside punar`, decide(action, subject(["punar-admin"])), null);
}
for (const action of ["org.freedesktop.login1.reboot-ignore-inhibit",
                      "org.freedesktop.login1.power-off-ignore-inhibit"]) {
  expect(`${action} is never granted, even to an administrator`, decide(action, admin), null);
}
expect("an unrelated action", decide("org.freedesktop.login1.suspend", admin), null);

if (failures.length) {
  for (const f of failures) console.error(`power-polkit-rule-test: FAIL: ${f}`);
  process.exit(1);
}
console.log("power-polkit-rule-test: ok");
JS
