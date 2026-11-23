"""Check the migration and release identifiers used in the public guides."""

import re
import sys
import tomllib
from datetime import date
from pathlib import Path

from ales_core.migrations import head_revision

ROOT = Path(__file__).resolve().parents[1]


def main(tag: str | None = None) -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if tag and tag != f"v{version}":
        raise SystemExit(f"Tag {tag} does not match the Python distribution version {version}")
    if tag:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        dated = re.search(
            rf"^## \[{re.escape(version)}\] - (\d{{4}}-\d{{2}}-\d{{2}})$", changelog, re.MULTILINE
        )
        if not dated:
            raise SystemExit(f"Date the {version} changelog entry before tagging {tag}")
        date.fromisoformat(dated[1])
    head = head_revision()
    if not head:
        raise SystemExit("The installed package contains no migration head")
    for file, pattern in [
        ("docs/compatibility.md", rf"^\| Alembic head \| `{head}` \|"),
        ("docs/upgrades.md", rf"^\| Alembic head \| `{head}` \|"),
        ("CHANGELOG.md", rf"^## \[{re.escape(version)}\][^\n]*\n\n[^\n]*Alembic head `{head}`"),
    ]:
        if not re.search(pattern, (ROOT / file).read_text(encoding="utf-8"), re.MULTILINE):
            raise SystemExit(f"{file}: expected migration head {head} for {version}")


if __name__ == "__main__":
    main(*sys.argv[1:])
