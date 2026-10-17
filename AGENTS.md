# Instructions for coding agents

- Install with `uv venv .venv --python python3.12 && uv pip install --python .venv/bin/python -e '.[test,witness]'`
  and run `.venv/bin/pytest -q` after any change under `src/` or `tests/`. The `witness` extra builds
  `jcs-admit` from a pinned commit and needs a Rust toolchain. After a change under
  `src/probity_observer/witness/`, also run `python scripts/mutate-witness-proofs.py`.
- A change under `interop/<profile>/` runs that profile's own tests from its directory; its workflow
  in `.github/workflows/` shows the exact commands.
- Never widen `witnessScope` beyond `PEER` in a packet the observer itself writes, or remove a
  `doesNotAssert` entry; the verifier rejects stronger claims and the tests pin that refusal.
  `EXTERNAL` comes only from `witness.scope.verify_witnessed_record`, which decides it from a
  2-of-2 co-signature, an inclusion proof and the consumer's own operator pins.
- Keep `README.md` to the first screen. Detail goes in `docs/`, and `scripts/readme-lint.py` fails a
  README over its word limit or with a dead relative link. Never edit `scripts/readme-lint.py`; it is
  shared byte-for-byte with sibling repositories.
- A worked example starts with the practical question, observed outcome, and evidence boundary.
  Put exact commands, source pins, field inventories, and control counts in one linked technical
  reference under `docs/reference/`; avoid repeating command recipes across both pages.
- Link worked examples from `docs/README.md`. Explain terms before using them, and keep missing
  observations, incomplete effects, historical authority, and operator independence explicit.
- Shell recipes use the owning environment and state their starting directory. A failed reader,
  wrong refusal exit, unexpected stdout, or changed retained bytes must stop the recipe. Preserve
  failure output. Check executable examples and relative links before committing a doc change.
