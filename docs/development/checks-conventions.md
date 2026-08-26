# Check-script conventions: assert the invariant, never the placeholder

Scope: every in-VM exercise under
`os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/m*-check.sh`.

Punar's honesty rule (spec 1.22) makes every milestone ship surfaces that
**name what they cannot yet observe**: a `not_yet_observed[]` row with a
milestone on it, a `declared · enforced M12` label, a verb that refuses and
says which milestone owns it. Those strings are *placeholders by design* —
a later milestone is supposed to delete them.

A check script that pins one of those strings is therefore a **scheduled CI
failure**. It goes red not when something breaks, but on the day the thing
it described gets built. This has happened six times. This document exists
so it does not happen a seventh.

> **The rule.** Assert the invariant that survives fulfilment, never the
> placeholder text. If the assertion would have to be edited by the
> milestone that *fulfils* the promise, it is asserting the wrong thing.

---

## 1. The six occurrences

| # | Commit | Pinned | Killed by | Because |
|---|--------|--------|-----------|---------|
| 1 | `f95c9c4` | `m6-check`: `agent stub cites Milestone 7` | M7 | M7 replaced the stub with a real launcher, so the stub's message stopped existing |
| 2 | `f31a8f2` | `m7-check`: `grep_row … "MILESTONE 8"` on the inspect ledger | M8 | M8 shipped the ledger; the dashed placeholder became real rows |
| 3 | `e61f842` | `m7-check`: `grep_row … "MILESTONE 10"` on the agents-list footer | M10 | M10 shipped `punar-agentd-scan.timer`; the deferral sentence became a real cadence |
| 3b | `e61f842` | `m7-check`: `.resource == "foo-agent"` | M10 | the scan audit event's `resource` became the composite `<agent>:<trigger>` |
| 4 | *this change* | `m8-check`: `[…level == 4…] \| sort == ["production_access","sensitive_resource_access","unknown_ai_execution"]` | M10 | M10 gave `unknown_ai_execution` a producer, so its row correctly **left** the list |
| 5 | *this change* | `m8-check`: `grep_row … "MILESTONE 10"` on the privacy `REMOTE QUERY` row | M10 | M10 built the remote-query path, so the row correctly stopped naming a future milestone |
| 6 | *this change* | `m8-check`: `.remote_query.available == false` | M10 | same event, machine surface |

Every single one was a **correct product change breaking a check**. Not one
was a regression. The repair was the same shape all six times, which is the
strongest evidence available that the shape is a rule and not a coincidence.

Occurrence 3b is the same disease in a different organ: pinning an exact
field value that a later milestone legitimately makes richer. The cure is
the same — assert the *relation* (`test("^foo-agent(:|$)")` plus a join on
the detection id) rather than the *snapshot*.

---

## 2. The two canonical forms

### Form A — the biconditional, over a probe of *this device*

Used wherever a surface labels something "not yet observed". The question
"does a producer for this category exist?" is answered by **looking at the
device**, never by a milestone literal:

```sh
unit_installed() { [ -f "/usr/lib/systemd/system/$1" ]; }

producer_present() {
    case "$1" in
        credential_classes|credential_request) unit_installed punar-secrets.service ;;
        network_destinations|production_access) unit_installed punar-netd.service ;;
        unknown_ai_execution)                   unit_installed punar-agentd-scan.timer ;;
        *) return 1 ;;
    esac
}
```

and then, per category, both directions:

```
labelled  <=>  this device has no producer
labelled   =>  the resource array is empty        (no self-contradiction)
labelled   =>  a milestone TOKEN and a reason     (no bare deferral)
labelled   =>  the category is in the shipped enum (closed vocabulary)
```

The **forward** direction is the honesty rule itself: an empty array with no
mediation point must say so, because on a surface an unlabelled empty array
reads as *"this did not happen"*.

The **reverse** direction is what makes it survive fulfilment, and it is the
half everybody forgets. The day `punar-netd` is installed, the assertion
stops accepting the `network_destinations` honesty row and starts *demanding
its deletion* — which is exactly the edit M10 had to make by hand for
`unknown_ai_execution`, and exactly the edit no check asked for.

Milestone tokens are matched as a **shape**, never as a value:

```
test("^(none|M[0-9]+[+]?(/M[0-9]+[+]?)*)$")
```

`none` is the sentinel for a *permanent* limitation (an unmanaged agent has
no repository, ever). Prose — `"arrives in a later milestone"`, `"TBD"` — is
a bare deferral and fails. **Re-milestoning must not break a check**: M9
moved `mcp_servers` from `M9+` to `M11+` because M9 shipped a credential
broker and not a tool gateway. That was the honest move; a check that pinned
`M9+` would have punished it.

Where no device probe is possible, use the closest structural equivalents:
closed vocabulary, disjointness (a category with an observed event may not
also claim nothing observes it), no duplicates, non-vacuity (at least one
category is actually produced), and a **monotone floor** — the categories a
shipped milestone already produces may never re-enter the pending set.

### Form B — the vocabulary regex, over the rendered surface

Used wherever a human-facing row carries an enforcement or deferral label.
Write the column's *whole vocabulary* once, and match every row against it:

```sh
ENFORCE_RE='(applied( \(bind mount\))?|enforced|declared · (M[0-9]+[+]?|enforced( M[0-9]+)?|applied))'
grep_re "network row states where its declaration stands" "${OUT}" \
    "^ +network +[a-z_]+ +(allow|deny) +${ENFORCE_RE}$"
```

Then add the **structural sweep** that is the actual point — that no row
renders bare:

```sh
bare="$(grep -cE '^ +(filesystem|network|credentials) .*declared[[:space:]]*$' "${OUT}")"
[ "${bare}" = "0" ] || { note "FAIL ${bare} row(s) render as a bare 'declared'"; FAILED=1; }
```

A row ending at the bare word `declared` reads on a surface as a *granted*
permission. That is the failure spec 1.22 is about, and it is invisible to
any assertion that merely pins the current label. For a
`NOT YET OBSERVED` row the same sweep checks the milestone sits **beside**
the words rather than buried in the reason prose:

```sh
tr 'a-z' 'A-Z' < "${OUT}" | grep -F 'NOT YET OBSERVED' \
    | sed 's/^.*NOT YET OBSERVED//' | cut -c1-60 | grep -cv 'M[0-9]'
```

`tr` first — `punarctl`'s `fmt::verdict` uppercases rendered words, and GNU
`sed`'s `I` flag is not portable (the M5 lesson).

---

## 3. The mechanical test

Before shipping any assertion in a check script, ask:

> **If milestone N+1 ships exactly what this milestone declared missing,
> does this assertion still pass — and for the right reason?**

Three answers, three verdicts:

- **Still passes, for the right reason.** Ship it. This is Form A's reverse
  direction and Form B's vocabulary regex.
- **Still passes, for the wrong reason** (it went vacuous, or it never
  constrained anything). Worse than red. Add the structural sweep.
- **Fails.** It is pinned to a placeholder. Convert it — unless it is a
  deliberate exception below.

A grep for `MILESTONE 12` in a check script is a **known future failure
sitting in the tree right now**. Treat one the way you would treat a failing
test that is currently skipped.

### Preserving strength

Converting is not loosening. Every converted assertion must still fail on a
document that genuinely violates the honesty rule — and you must **prove
it**, by constructing the violating document and watching the filter reject
it. The violations worth constructing, every time:

1. the honesty row is **deleted** while its producer is still absent
   (the silent empty — the thing the original pin did catch);
2. the honesty row **survives** after its producer shipped (the stale
   promise — the thing the original pin did *not* catch);
3. the milestone is replaced by **prose** (`"soon"`, `"TBD"`);
4. the row **contradicts** the data beside it (labelled, but the array has
   entries);
5. a category **outside the shipped enum** appears;
6. and the **fulfilment** case: the world where N+1 shipped, which must
   pass.

### Replay before you ship

Every `jq` filter must be replayed against a **real document produced by
running the real code** before it lands. Three M9 filters once shipped
exiting `5` — a jq *syntax* error — instead of evaluating, and `jq -e`
reports that as a plain failure. A filter that has never been run against a
real document is not an assertion; it is a wish.

---

## 4. Deliberate exceptions

Not every pinned literal is this bug. Two kinds are legitimate:

**Present-tense design laws.** `m10-check`'s
`grep_row … "nothing was blocked"` asserts law 4 — M10's detection observes
and never enforces. That is not a promise about the future; it is a
guarantee about the present that a later milestone must *deliberately*
re-ratify. If a milestone arms blocking, this check **should** go red, and
somebody should have to say so out loud.

**Permanent limitations.** `m10-check` pins `milestone == "none"` on the
unmanaged ledger's `repositories` and `credential_classes` rows. No
milestone ships those — Punar never reads `/proc/<pid>/cwd`, and
`punar-secrets` mediates managed sessions only. Pinning `none` is how the
check enforces the distinction the surface exists to draw: *permanently
unobservable* and *arriving later* must never render alike.

**Anti-placeholder assertions.** `grep_absent … "no upload path exists"`
asserts a superseded sentence is gone. It can only get stronger with time.

---

## 5. Known residual risk

`producer_present` answers "has a producer shipped?" by looking for a unit
file under a name it knows. **A producer that ships under an unrecognised
name reads here as absent, and the stale honesty row would then still
pass.** Nothing in a shell check can close that hole.

What closes it is `punar_common::ledger::not_yet_observed()` and its unit
tests: the list lives in one place, in Rust, next to the enum it draws from,
and the tests there own its contents. The check scripts assert that the
*rule* holds on a running device; they deliberately contain no milestone
numbers of their own. When you ship a producer, extend the `case` in
`m8-check.sh` (and `mediation_present` in `m10-check.sh`) in the same commit
that deletes the row.

---

## 6. Hard-won constraints these scripts run under

Unrelated to this class, but binding on anything you add here:

- the image has **no diffutils** — compare with `sha256sum`, never `cmp` or
  `diff`;
- check scripts must be committed **0755**; a non-executable check is a
  silently skipped check that passes (`dc2dc47`);
- vendor `/usr/lib/…/.wants` symlinks and assert **symlink plus `Wants=`**,
  never `is-enabled`;
- `qs ipc` needs `-p /usr/share/punar/shell`;
- `punarctl` verdict lines are **uppercased**, so greps over them must be
  case-insensitive (`408b51d`);
- **no polling loops.**
