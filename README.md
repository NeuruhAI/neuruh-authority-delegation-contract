# Neuruh Authority Delegation Contract

Public Commons Release 016. A deterministic, fail-closed contract for bounded delegation of authority.

A delegation names the principal, delegate, authority classes, capabilities, domains, optional action IDs, time window, spend ceiling, re-delegation permission, and maximum delegation depth.

Child delegations must be strict subsets of their parent. They may not widen authority, capability, domain, action scope, spend, time, or chain depth.

This package models **contract semantics only**. It does not authenticate identities, create cryptographic signatures, implement production RBAC, or itself grant Neuruh production authority.

## Install

```bash
git clone https://github.com/NeuruhAI/neuruh-authority-delegation-contract.git
cd neuruh-authority-delegation-contract
python -m venv .venv
source .venv/bin/activate
pip install .
```

Or install a pinned release directly:

```bash
pip install "neuruh-authority-delegation-contract @ git+https://github.com/NeuruhAI/neuruh-authority-delegation-contract.git@v0.1.1-alpha"
```

## Sixty-second example

The repository ships synthetic fixtures. Check one with the installed CLI:

```bash
neuruh-authority-delegation validate examples/delegation.synthetic.json
neuruh-authority-delegation digest examples/delegation.synthetic.json
```

Expected output:

```text
{"delegation_id": "del-synthetic", "ok": true, "status": "active"}
sha256:c40bc08eb0cc6d4a8149ece8000e0a52d551671b0375c6db11d061932e154681
```

`inspect` prints the full parsed object as indented JSON.

`examples/build_synthetic.py` regenerates the fixtures from scratch, so the construction path can be read end to end.

`authorize` take further arguments; see `neuruh-authority-delegation <command> --help`.

Bad input is reported, never raised as a traceback: a missing file, unreadable JSON, or a rejected object prints `error: ...` on stderr and exits `2`.

## API

| Name | Notes |
| --- | --- |
| `SCHEMA_VERSION` | Declared vocabulary. |
| `STATUSES` | Declared vocabulary. |
| `AuthorityDelegation` | Fields: `delegation_id`, `principal_id`, `delegate_id`, `authorities`, `capabilities`, `domains`… |
| `DelegationValidationError` | Raised for every rejection. |
| `authorize(delegation, now, delegate_id, authority, capability, domain, action_id, spend)` |  |
| `canonical_json(value)` |  |
| `create_root_delegation(delegation_id, principal_id, delegate_id, authorities, capabilities, dom…` |  |
| `derive_delegation(parent, delegation_id, delegate_id, authorities, capabilities, domains, allow…` |  |
| `revoke_delegation(delegation, revoked_at, reason)` |  |
| `sha256_ref(value)` |  |
| `verify_child(parent, child)` |  |

The published schema is [`schema/authority-delegation-contract.v0.1.schema.json`](schema/authority-delegation-contract.v0.1.schema.json).

## Test

```bash
python -m unittest discover -s tests -v
```

## Safety boundary

This package validates, records, and reports. It holds no credentials, performs no network I/O,
and grants no authority. A valid object means the claims inside it are internally consistent and
content-bound — not that the underlying action was correct, permitted, or actually happened.
Digests and hash links are tamper evidence, not signatures: they detect modification, they do
not establish who wrote an entry.

Only synthetic fixtures ship here: no production data, endpoints, policies, or topology. See
[`ARCHITECTURE.md`](ARCHITECTURE.md), [`PUBLIC_PRIVATE_BOUNDARY.md`](PUBLIC_PRIVATE_BOUNDARY.md), [`SECURITY.md`](SECURITY.md), and the
[Neuruh Public Commons boundary](https://github.com/NeuruhAI/public-commons/blob/main/PUBLIC_PRIVATE_BOUNDARY.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
