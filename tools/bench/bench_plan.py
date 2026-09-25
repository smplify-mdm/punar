#!/usr/bin/env python3
"""Plan a benchmark dispatch: which cells run, in what order (tools/bench/README.md).

    bench_plan.py --lanes punar --runs 5 --shapes 8192,4096 --workload-shapes 4096 --seed 1234

A cell is one VM shape and one run index. Each cell runs every enabled lane
once, back to back on the same runner, in an order drawn from a seeded
shuffle (the "coin flip" of the paired design), and the cell list itself is
shuffled so shapes and indices do not start in a fixed order. The seed is
the workflow run id, recorded with every result, so the plan can be
reproduced exactly.

Inputs are validated strictly: they reach shell steps only through this
program's JSON output, never by interpolation.
"""

from __future__ import annotations

import argparse
import json
import random
import sys

ALLOWED_SHAPES = (2048, 4096, 8192)
LANES = {"punar": ["punar"], "punar+omarchy": ["punar", "omarchy"]}


def plan(lanes: str, runs: int, shapes: str, workload_shapes: str, seed: int,
         omarchy_approved: bool) -> dict:
    if lanes not in LANES:
        raise ValueError(f"lanes must be one of {', '.join(LANES)}")
    if not 1 <= runs <= 20:
        raise ValueError("runs must be between 1 and 20")
    shape_list = [int(s) for s in shapes.split(",") if s.strip()]
    workload_list = [int(s) for s in workload_shapes.split(",") if s.strip()]
    for shape in shape_list + workload_list:
        if shape not in ALLOWED_SHAPES:
            raise ValueError(f"shape {shape} is not one of {ALLOWED_SHAPES}")
    if not shape_list or len(set(shape_list)) != len(shape_list):
        raise ValueError("shapes must be a non-empty list without repeats")
    enabled = list(LANES[lanes])
    notes = []
    if "omarchy" in enabled and not omarchy_approved:
        enabled.remove("omarchy")
        notes.append("omarchy lane requested but not approved (input omarchy_approved and variable "
                     "OMARCHY_LANE_APPROVED=yes are both required); it did not run")
    if runs < 5:
        notes.append(f"{runs} runs per shape is fewer than 5: the report will make no claim")
    rng = random.Random(seed)
    cells = []
    for shape in shape_list:
        for index in range(1, runs + 1):
            order = list(enabled)
            rng.shuffle(order)
            cells.append({
                "cell": f"s{shape}-r{index}",
                "shape": shape,
                "run": index,
                "order": ",".join(order),
                "workload": shape in workload_list,
            })
    rng.shuffle(cells)
    return {"seed": seed, "lanes": enabled, "cells": cells, "notes": notes,
            "omarchy": "omarchy" in enabled}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lanes", default="punar")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--shapes", default="8192,4096")
    parser.add_argument("--workload-shapes", default="4096")
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--omarchy-approved", choices=("true", "false"), default="false")
    parser.add_argument("--github-output", help="append matrix=... and friends to this file")
    args = parser.parse_args(argv)
    try:
        result = plan(args.lanes, args.runs, args.shapes, args.workload_shapes, args.seed,
                      args.omarchy_approved == "true")
    except ValueError as error:
        print(f"bench_plan: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    if args.github_output:
        with open(args.github_output, "a") as handle:
            handle.write(f"matrix={json.dumps({'include': result['cells']})}\n")
            handle.write(f"omarchy={'true' if result['omarchy'] else 'false'}\n")
            handle.write(f"seed={result['seed']}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
