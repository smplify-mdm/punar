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
