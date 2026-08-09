# Architecture

Root delegation:
principal → delegate → bounded authorities/capabilities/domains/actions/time/spend

Optional child delegation:
parent delegate → child delegate

Child verification requires:
- parent is active and allows re-delegation
- child principal equals parent delegate
- exact parent id/digest binding
- authority/capability/domain/action scopes are subsets
- spend ceiling does not increase
- child starts no earlier and expires no later
- delegation depth increments exactly and never exceeds max_depth
- immediate cycles/self-delegation are rejected

`authorize()` then checks exact delegate, authority, capability, domain, action, spend and time against the sealed delegation.
