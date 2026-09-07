"""Print the IPC target list HANDOFF.md advertises, space separated and sorted.

Its own line, rather than a sed inside check-doc-freshness.sh: the list is
delimited by backticks, and quoting a backtick-matching expression through a
shell heredoc is exactly the kind of fragility this repository keeps out of
gates.
"""

import pathlib
import re

text = pathlib.Path("HANDOFF.md").read_text()
match = re.search(r"^[A-Z][a-z]+ targets: `([^`]+)`", text, re.M)
print(" ".join(sorted(match.group(1).split())) if match else "")
