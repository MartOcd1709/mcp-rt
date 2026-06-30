"""Results store — lets throttled runs ACCUMULATE into a complete matrix.

Verdicts are keyed by (client, attack). A real verdict (VULNERABLE/RESILIENT) is
never overwritten by a later ERROR, so partial runs on a rate-limited free tier
build up to a full matrix over time instead of starting from scratch each run.
"""
import json
from pathlib import Path


def _key(result: dict) -> str:
    return f'{result["client"]}::{result["attack"]}'


def load(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return {_key(r): r for r in json.loads(p.read_text())}


def merge_and_save(path: str, new_results: list[dict]) -> list[dict]:
    store = load(path)
    for r in new_results:
        existing = store.get(_key(r))
        # never clobber a good verdict with a fresh error
        if r.get("error") and existing and not existing.get("error"):
            continue
        store[_key(r)] = r
    results = list(store.values())
    Path(path).write_text(json.dumps(results, indent=2, default=str))
    return results


def settled_attacks(path: str, client_name: str) -> set:
    """Attack names that already have a non-error verdict for this client."""
    return {
        r["attack"]
        for r in load(path).values()
        if r["client"] == client_name and not r.get("error")
    }
