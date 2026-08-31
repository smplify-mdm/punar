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
7. Any custom URI scheme is present in the upstream package's desktop entry,
   has a narrow product-specific purpose, and does not replace a reserved
   browser, file, mail, script, or network-transfer handler. The review records
   the exact scheme in the signed catalog and tests both registration on
   install and removal on uninstall.

Popularity can nominate an application for review; it cannot bypass review.
Enterprise policy may further allow or deny catalog identities, and a personal
device remains free to choose among the entries admitted by the OS release.

## Snapcraft compatibility gate

[Snapcraft](https://snapcraft.io/) is a useful discovery source, not a default
Punar trust root. Punar does not currently ship `snapd` or expose an unbounded
Snap Store because that would add a second privileged package daemon and a
second application-update authority. Snap's default automatic refresh cadence
([four checks per day](https://snapcraft.io/docs/how-to-guides/manage-snaps/manage-updates/))
would also move application versions independently of the Punar release
channel unless it were explicitly governed.

A future optional compatibility layer must prove all of the following before
admission: only reviewed publisher identities are shown; the exact Snap
revision and assertions are recorded; [strict confinement and every connected
interface](https://snapcraft.io/docs/explanation/security/snap-confinement/)
are displayed before install; classic confinement is never silently accepted;
refreshes obey personal or enrolled-device Punar policy; and idle
CPU, memory, disk, and boot impact remain within the product budgets. Until
then, Punar's signed finite catalog can use Snapcraft to discover candidates
without installing from it directly.

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
