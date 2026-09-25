# Security policy

Punar has **no release yet**. Nothing has been published for people to install,
so every statement below applies to the `main` branch and to the images CI
builds from it. When the first release ships, this file and
[`security.txt`](os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/punar/security.txt)
change in the same commit.

## Reporting a vulnerability

Report privately. Please do not open a public issue, pull request or
discussion for a security problem.

- **Email:** [security@smplify.com](mailto:security@smplify.com). There is no
  PGP key yet, so email is not encrypted end to end: if the details are
  sensitive, write first without them and we will arrange a private channel.

GitHub private vulnerability reporting is not switched on for this repository
yet. When it is, it becomes a second route, listed here and in `security.txt`
in the same commit.

Include what you can of:

- the commit, or the image's `IMAGE_VERSION` from `/usr/lib/os-release`;
- the architecture lane (x86_64 Arch, x86_64 Debian or ARM64 Debian);
- steps to reproduce, and what an attacker gains;
- whether the problem is already public or being exploited;
- how you would like to be credited, or that you would rather not be.

A running machine carries the same contacts in `/usr/share/punar/security.txt`
([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)).

## What happens next

| Step | Target, counted from the day you report |
| --- | --- |
| We confirm we received the report | 3 business days |
| We tell you our assessment: severity (CVSS 4.0), affected code, and the plan | 10 days |
| A fix is on `main`, for a **critical** issue | 14 days |
| A fix is on `main`, for a **high** issue | 45 days |
| A fix is on `main`, for a **medium** or **low** issue | 90 days |
| Public disclosure | when the fix ships, and no later than 90 days |

Every target runs from the same day, so no fix is due after the day the report
may be disclosed. If a fix cannot ship within 90 days, we tell you before then
and agree with you whether to extend disclosure or to publish the problem with
a workaround.

We update you at least every 14 days until the report is closed. If a problem is
being exploited, we fix and disclose sooner, and we tell you before we do. If we
cannot meet a target, we tell you why and agree a new date with you rather than
let it pass silently. We credit reporters in the advisory unless they ask us not
to.

We will not pursue legal action against research done in good faith that stays
within this policy: test only against machines and accounts you own or have
permission to test, do not read or keep other people's data, do not degrade
anyone's service, and give us the time above before disclosing.

## Supported versions

| Version | Security fixes |
| --- | --- |
| `main` | Yes. Until the first release, this is the only supported version. |
| Any image built from an older commit | No. Rebuild from `main`. |

After the first release:

- The newest release on each update channel (`stable`, `edge`, `dev`) receives
  every security fix.
- The release before it on `stable` receives fixes for critical and high issues
  for 90 days after its successor ships, so an organization can stage the
  update.
- A device running a release older than its channel's signed
  `min_supported_version` is unsupported, and the updater will not update it in
  place: `punarctl update check` reports it as not eligible ("the running
  release is older than the signed channel minimum"). The way back is to
  reinstall from a current image, so back up your files first.

## Scope

In scope: everything in this repository, the images it builds, the signed
update and catalog metadata it verifies, and the Punar side of Smplify
enrollment. Vulnerabilities in upstream packages Punar ships (the kernel,
systemd, Hyprland, Chromium and others) should go to their upstream first; tell
us too if Punar's configuration makes one reachable or worse.

The design this policy protects is in
[`docs/threat-model/THREAT_MODEL.md`](docs/threat-model/THREAT_MODEL.md).
