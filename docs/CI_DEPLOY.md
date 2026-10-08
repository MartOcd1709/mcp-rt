# CI Action — deployment plan (MartOcd1709/mcp-rt)

Goal: publish the `mcp-rt` CI action so any repo can scan its MCP servers on every PR. The sandbox has
no git creds, so these are the commands YOU run when you open GitHub.

## Step 1 — commit + push everything
```bash
cd ~/Desktop/mcp-rt
git add -A
git commit -m "Commercial platform: report exec-summary+compliance+PDF, diff, monitor, CI action; \
PyPI/uvx discovery; deserialization class; stats source-of-truth; storefront README"
git push origin main        # (or your default branch)
```
On push, `.github/workflows/ci.yml` runs the test suite on py3.11/3.12 → the README **CI badge goes
green** (the `pyyaml`+`markdown` deps are now declared, so a fresh runner installs them and tests pass).

## Step 2 — the action works immediately (no Marketplace needed)
Any repo can use it by path reference:
```yaml
# .github/workflows/mcp-security.yml  (in the CONSUMING repo)
name: MCP Security
on: [pull_request]
permissions: { security-events: write, contents: read }
jobs:
  mcp-rt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: MartOcd1709/mcp-rt/.github/action@main
        with: { fail-on: critical }
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: mcp-rt.sarif }
```
The action's Docker image `pip install`s mcp-rt from the public repo (`git+https://…@main`).

## Step 3 — tag a stable release + pin
```bash
git tag -a v1 -m "mcp-rt CI action v1"
git push origin v1
```
Then change the Dockerfile pin `@main` → `@v1` (reproducible builds) and tell users `@v1` not `@main`.

## Step 4 (optional, later) — GitHub Marketplace listing
Marketplace requires `action.yml` at the **repo root** (ours is in `.github/action/`). To list:
either (a) move/duplicate `action.yml` + `Dockerfile` to the repo root, or (b) create a dedicated
`mcp-rt-action` repo. Not required for path-reference usage above — do this only when going public.

## Honest checklist before you push
- [ ] `python -m pytest -q` green locally (currently 39/39).
- [ ] README is the storefront version (push includes it → public shopfront goes live).
- [ ] Decide: findings stay PRIVATE — the advisory drafts in `~/Videos/` are NOT in the repo (correct;
      don't commit unpublished findings).
- [ ] After push, watch the Actions tab once to confirm the CI run is green.
