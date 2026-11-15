"""Build homelab-harden as one runnable file: python3 homelab-harden.pyz [args]."""

import argparse
import shutil
import tempfile
import zipapp
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "src" / "homelab_harden"
# zipapp's own main= wrapper drops the return value, which would lose the --fail-on exit code.
ENTRY = "import sys\n\nfrom homelab_harden.cli import main\n\nsys.exit(main())\n"


def build(out: Path) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copytree(
            PACKAGE, root / "homelab_harden", ignore=shutil.ignore_patterns("__pycache__")
        )
        (root / "__main__.py").write_text(ENTRY)
        zipapp.create_archive(root, target=out, interpreter="/usr/bin/env python3", compressed=True)
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--out", type=Path, default=Path("dist/homelab-harden.pyz"))
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    print(build(args.out))
