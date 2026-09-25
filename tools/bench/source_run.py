#!/usr/bin/env python3
"""Decide whether a ci.yml run may supply the benchmark's release image (tools/bench/README.md).

    source_run.py candidates ARTIFACTS.json   newest-first run ids worth checking
    source_run.py check RUN.json JOBS.json    exit 0 if the run is trusted; else 1 and the reasons

The repository is public and ci.yml runs on pull requests, forks included.
A fork's pull request runs the fork's own ci.yml, which can upload any file
under the release image's artifact name, and a fork's branch may itself be
called "main". The SHA256SUMS file inside the artifact comes from the same
upload, so checking against it proves nothing about where the image came
from. What makes an image trustworthy is the run that built it, so a run is
accepted only when all of these hold (from the GitHub API's run and jobs
documents):

- it ran .github/workflows/ci.yml of this repository (head repository ==
  repository), on the branch main;
- it was started by a push to main, or by a dispatch on main (a writer
  running main's own ci.yml); never a pull request or any other event;
- it has finished, and the job that builds the release image
  (debian-amd64-installer) succeeded.

ARTIFACTS.json is the output of
    gh api --paginate "repos/R/actions/artifacts?name=N&per_page=100" --jq '.artifacts[]'
(a stream of JSON values; a whole response object works too). RUN.json is
`gh api repos/R/actions/runs/ID`; JOBS.json is
`gh api --paginate repos/R/actions/runs/ID/jobs?per_page=100 --jq '.jobs[]'`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

WORKFLOW_PATH = ".github/workflows/ci.yml"
BRANCH = "main"
EVENTS = ("push", "workflow_dispatch")
IMAGE_JOB = "debian-amd64-installer"


def json_stream(text: str) -> list:
    """Every JSON value in TEXT, one after another (gh --paginate output)."""
    decoder = json.JSONDecoder()
    values, index = [], 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            return values
        value, index = decoder.raw_decode(text, index)
        values.append(value)


def flatten(values: list, key: str) -> list[dict]:
    out = []
    for value in values:
        if isinstance(value, list):
            out.extend(v for v in value if isinstance(v, dict))
        elif isinstance(value, dict) and isinstance(value.get(key), list):
            out.extend(v for v in value[key] if isinstance(v, dict))
        elif isinstance(value, dict):
            out.append(value)
    return out


def candidates(artifacts: list[dict]) -> list[int]:
    """Unexpired artifacts from this repository's main, newest first (still to be checked)."""
    rows = []
    for artifact in artifacts:
        run = artifact.get("workflow_run") or {}
        if artifact.get("expired") is not False:
            continue
        if run.get("head_branch") != BRANCH:
            continue
        if run.get("head_repository_id") is None or run.get("head_repository_id") != run.get("repository_id"):
            continue
        if isinstance(run.get("id"), int):
            rows.append((str(artifact.get("created_at", "")), run["id"]))
    seen, out = set(), []
    for _created, run_id in sorted(rows, reverse=True):
        if run_id not in seen:
            seen.add(run_id)
            out.append(run_id)
    return out


def check(run: dict, jobs: list[dict]) -> list[str]:
    """Reasons the run cannot supply the image; empty when it can."""
    reasons = []
    repository = (run.get("repository") or {}).get("id")
    head_repository = (run.get("head_repository") or {}).get("id")
    if repository is None or head_repository != repository:
        reasons.append(f"ran code from another repository (head repository {head_repository}, "
                       f"repository {repository})")
    if run.get("path") != WORKFLOW_PATH:
        reasons.append(f"workflow is {run.get('path')!r}, not {WORKFLOW_PATH}")
    if run.get("head_branch") != BRANCH:
        reasons.append(f"branch is {run.get('head_branch')!r}, not {BRANCH}")
    if run.get("event") not in EVENTS:
        reasons.append(f"event is {run.get('event')!r}, not one of {', '.join(EVENTS)}")
    if run.get("status") != "completed":
        reasons.append(f"run status is {run.get('status')!r}, not completed")
    image_jobs = [job for job in jobs if str(job.get("name", "")).split(" ", 1)[0] == IMAGE_JOB]
    if not image_jobs:
        reasons.append(f"no {IMAGE_JOB} job in the run")
    elif any(job.get("conclusion") != "success" for job in image_jobs):
        reasons.append(f"{IMAGE_JOB} did not succeed "
                       f"({', '.join(str(job.get('conclusion')) for job in image_jobs)})")
    return reasons


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "candidates":
        artifacts = flatten(json_stream(Path(argv[1]).read_text()), "artifacts")
        for run_id in candidates(artifacts):
            print(run_id)
        return 0
    if len(argv) == 3 and argv[0] == "check":
        run = json.loads(Path(argv[1]).read_text())
        jobs = flatten(json_stream(Path(argv[2]).read_text()), "jobs")
        reasons = check(run, jobs)
        if reasons:
            print(f"source_run: run {run.get('id')} cannot supply the release image: " + "; ".join(reasons),
                  file=sys.stderr)
            return 1
        print(f"source_run: run {run.get('id')} ({run.get('event')} to {run.get('head_branch')}, "
              f"{run.get('head_sha')}) is trusted")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
