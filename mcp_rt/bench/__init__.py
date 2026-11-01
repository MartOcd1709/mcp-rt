"""Phase B scorer — scorecard A: agent susceptibility (ASR) over the fixture corpus, plus control false alarms.

Runs every fixtures/<class>/ (attacks) and fixtures/_controls/<name>/ (controls) against each configured client,
with a fresh planted HT- token and a fresh loopback canary per run. Offline: only mock clients are wired here.
Live real-agent runs are disabled until explicitly authorized. Results go to bench.db and bench_results/<run_id>/,
never to hunt/findings.db. Detector precision/recall is a separate deliverable and is never merged in here.
"""
