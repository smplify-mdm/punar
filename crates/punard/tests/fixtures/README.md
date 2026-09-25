# nft JSON fixtures

Captured 2026-08-25 by running the real `nft` binary from the pinned builder
container (`punar-image-builder:2026-08-20`, package `nftables 1:1.1.6-3` —
the exact version the desktop image ships) with `--cap-add=NET_ADMIN`:

- `nft-list-punar-base-full.json` — `nft -j list table inet punar-base` after
  applying the vendored `punar-base.nft` ruleset (docs/development/milestone-3.md
  section 4.1) with `nft -f`. Also verified during capture on 1.1.6:
  `destroy table` works both inside `-f` files (idempotent re-apply) and on the
  command line, and listing an absent table exits 1 with
  "Error: No such file or directory".
- `nft-list-punar-base-degraded.json` — same command after applying a
  tampered table (input policy `accept`, no output chain): the observe parser
  must judge this `disabled` (drift), not `enabled`.

# systemctl show fixtures

Captured 2026-09-25 from real systemd 257 (`257.13-1~deb13u1`, Debian
trixie, in a container) with the branch's management units installed from
`os/images/mkosi.profiles/desktop` and the agent running with an identity
(process 139, `/usr/bin/punar-smplifyd`). Each is the verbatim output of the
exact command punard's unit check runs (`crates/punard/src/agent_units.rs`):
`systemctl show --property=Id,LoadState,FragmentPath,DropInPaths,Listen,MainPID`
for the five management units and the pattern `*.socket`.

- `systemctl-show-shipped.txt` — as shipped. The agent's socket appears twice
  (named, and matched by the pattern), and a socket unit with two listeners
  (`systemd-journald.socket`) prints one `Listen=` line for each.
- `systemctl-show-modified.txt` — after `systemctl set-property --runtime
  punar-smplifyd.service CPUWeight=50`, an `/etc` drop-in on `punard.service`
  setting `PUNAR_CONTROL_PLANE_SOCKET`, and `systemctl mask
  punard-reconcile.timer`.
- `systemctl-show-transient-listener.txt` — back as shipped, then the agent's
  socket node removed and `systemd-run --unit=transient-fake
  --socket-property=ListenStream=/run/punar-smplifyd/api.sock` started: a
  second socket unit, created by PID 1, listening at the agent's path while
  the agent's own unit stays loaded, listening and unmodified.
