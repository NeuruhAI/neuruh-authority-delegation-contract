# Neuruh Authority Delegation Contract

Public Commons Release 016. A deterministic, fail-closed contract for bounded delegation of authority.

A delegation names the principal, delegate, authority classes, capabilities, domains, optional action IDs, time window, spend ceiling, re-delegation permission, and maximum delegation depth.

Child delegations must be strict subsets of their parent. They may not widen authority, capability, domain, action scope, spend, time, or chain depth.

This package models **contract semantics only**. It does not authenticate identities, create cryptographic signatures, implement production RBAC, or itself grant Neuruh production authority.
