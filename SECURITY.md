# Security policy

Punar has **no release yet**. Nothing has been published for people to install,
so every statement below applies to the `main` branch and to the images CI
builds from it. When the first release ships, this file and
[`security.txt`](os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/punar/security.txt)
change in the same commit.

## Reporting a vulnerability

Report privately. Please do not open a public issue, pull request or
discussion for a security problem.

- **GitHub:** [report a vulnerability](https://github.com/smplify-mdm/punar/security/advisories/new)
  through private vulnerability reporting. Only you and the maintainers can
  see the report.
- **Email:** [security@smplify.com](mailto:security@smplify.com), if the
  GitHub form is unavailable to you. There is no PGP key yet, so email is not
  encrypted end to end: if the details are sensitive and you cannot use the
  GitHub form, write first without them and we will arrange a private channel.

Include what you can of:

- the commit, or the image's `IMAGE_VERSION` from `/usr/lib/os-release`;
- the architecture lane (x86_64 Arch, x86_64 Debian or ARM64 Debian);
- steps to reproduce, and what an attacker gains;
- whether the problem is already public or being exploited;
- how you would like to be credited, or that you would rather not be.

A running machine carries the same contacts in `/usr/share/punar/security.txt`
([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)).

## What happens next

| Step | Target |
| --- | --- |
| We confirm we received the report | 3 business days |
| We tell you our assessment: severity (CVSS 4.0), affected code, and the plan | 10 days |
| A fix is on `main`, for a **critical** issue | 7 days after assessment |
| A fix is on `main`, for a **high** issue | 30 days after assessment |
| A fix is on `main`, for a **medium** or **low** issue | 90 days after assessment |
| Public disclosure | when the fix ships, and no later than 90 days after your report |

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
  `min_supported_version` is unsupported. The updater says so, and the fix is to
  update.

## Scope

In scope: everything in this repository, the images it builds, the signed
update and catalog metadata it verifies, and the Punar side of Smplify
enrollment. Vulnerabilities in upstream packages Punar ships (the kernel,
systemd, Hyprland, Chromium and others) should go to their upstream first; tell
us too if Punar's configuration makes one reachable or worse.

The design this policy protects is in
[`docs/threat-model/THREAT_MODEL.md`](docs/threat-model/THREAT_MODEL.md).
