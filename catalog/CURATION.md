# Application curation policy

Punar uses [Flathub](https://flathub.org/) AppStream as its cross-distribution
discovery and icon source. Flathub is a strong upstream because it provides one
graphical application format for x86_64 and ARM64, standardized metadata, and
Flatpak permission declarations. Its
[verification system](https://docs.flathub.org/docs/for-users/verification)
also distinguishes packages authorized by an application's developer from
community packaging.

The device does not expose Flathub as an unbounded install surface. A Punar
release contains a finite signed snapshot. Every native entry names an exact
architecture, app id, ref, commit, runtime, and metadata digest. `punard`
re-inspects the signed remote immediately before installation and refuses any
change. The UI derives containment and requested access from that live verified
metadata rather than trusting catalog prose.

## Admission

An application is admitted only when all of these hold:

1. It has a clear workstation use case and a maintained upstream project.
2. It has both x86_64 and ARM64 builds, or a deliberately labelled official
   web fallback for the missing architecture.
3. Its license, publisher relationship, and community-maintained status can be
   stated accurately. Publisher verification is preferred, not fabricated.
4. Its requested filesystem, device, IPC, network, and host access can be
   explained before installation. Broad access is allowed only when it is
   intrinsic to the job, such as system monitoring or packet analysis.
5. Its in-app updater is absent or disabled by packaging so Punar's governed
   update path remains authoritative.
6. Its icon and descriptive metadata are suitable for a clear, searchable
   application library.

Popularity can nominate an application for review; it cannot bypass review.
Enterprise policy may further allow or deny catalog identities, and a personal
device remains free to choose among the entries admitted by the OS release.

## Categories

- **AI:** assistants and native AI clients.
- **Developer:** editors, API clients, databases, diff tools, containers, and
  focused development utilities.
- **Diagnostics:** logs, resource monitoring, and network analysis.
- **Writing:** Markdown and document-focused tools.
- **Files:** local and network file workflows. The lean image currently ships
  Files (Thunar) with GVfs SMB support by default rather than downloading it.
- **Security:** credential, privacy, and defensive utilities.
- **Browsers, Communication, Media, Graphics, Productivity, Utilities:**
  broader workstation applications that meet the same admission rules.

## Refresh

Catalog refreshes are release changes, not live device mutations. A maintainer
reviews upstream ownership and permissions, records new per-architecture pins,
runs `tools/verify-app-catalog.sh`, validates schemas, and boots both desktop
architectures. Permission expansions require human review and a new catalog
version even when the upstream app version is unchanged.
