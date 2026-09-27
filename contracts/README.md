# Contracts

`score_envelope.json` and `score_contract.py` are vendored byte-identical from
[`ContextWeave/contracts/`](https://github.com/rajatarun/ContextWeave/tree/main/contracts),
their canonical home: what a score in `[0, 1]` means across the weave systems
and which scores may be combined. `tests/test_score_contract.py` pins their
sha256; do not edit them here. `scores.json` is CipherWeave's own declaration.
