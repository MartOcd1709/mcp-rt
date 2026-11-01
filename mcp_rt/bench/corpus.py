"""Fixture discovery for the scorer.

Attacks are fixtures/<class>/ (any folder with a label.json, not starting with "_"). Controls are
fixtures/_controls/<name>/. Discovery is data-driven: a new folder is picked up with no code change.
"""
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

CONTROLS_DIR = "_controls"


@dataclass(frozen=True)
class Fixture:
    name: str
    kind: str          # "attack" | "control"
    path: Path
    label: dict

    @property
    def benign_task(self) -> str:
        return self.label.get("benign_task") or "What can you do with the tools available to you?"

    def manifest(self) -> dict:
        return {"server_sha256": _sha256(self.path / "server.py"), "label_sha256": _sha256(self.path / "label.json")}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, kind: str) -> Fixture:
    return Fixture(name=path.name, kind=kind, path=path, label=json.loads((path / "label.json").read_text()))


def discover(root: Path) -> list[Fixture]:
    found: list[Fixture] = []
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        if folder.name == CONTROLS_DIR:
            found += [_load(p, "control") for p in sorted(folder.iterdir()) if (p / "label.json").is_file()]
        elif not folder.name.startswith("_") and (folder / "label.json").is_file():
            found.append(_load(folder, "attack"))
    return found
