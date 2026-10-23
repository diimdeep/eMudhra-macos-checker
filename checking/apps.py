"""Find application bundles, including ones kept in subfolders.

Apps live in /Applications and ~/Applications, but people group them into
folders (``~/Applications/iphone/AnyTrans.app``), so a flat ``*.app`` glob
misses them.  This walks folders up to a fixed depth and never descends into
an ``.app`` itself.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

APP_ROOTS = (Path("/Applications"), Path.home() / "Applications")

# Folder levels below a root; ~/Applications/a/b/X.app is depth 2.
MAX_DEPTH = 3

# Files an app might load as its CA store.
CA_FILE_NAMES = {"cacert.pem", "ca-bundle.crt", "ca-certificates.crt", "curl-ca-bundle.crt"}


@lru_cache(maxsize=None)
def app_bundles(roots=APP_ROOTS, max_depth: int = MAX_DEPTH, pattern: str = "*.app") -> tuple[Path, ...]:
    """App bundles under `roots` whose name matches `pattern`, cached per run."""
    found: list[Path] = []
    seen: set[Path] = set()

    def walk(folder: Path, depth: int) -> None:
        try:
            entries = sorted(folder.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.suffix == ".app":
                if entry.match(pattern):
                    resolved = entry.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        found.append(entry)
            elif depth < max_depth and entry.is_dir() and not entry.is_symlink():
                walk(entry, depth + 1)

    for root in roots:
        if root.is_dir():
            walk(root, 0)
    return tuple(found)


def ca_files(app: Path) -> list[Path]:
    """CA bundle files shipped inside one app bundle."""
    hits: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(app):
        # Nested apps are reported on their own.
        dirnames[:] = [d for d in dirnames if not d.endswith(".app")]
        for name in filenames:
            if name in CA_FILE_NAMES:
                hits.append(Path(dirpath) / name)
    return hits
