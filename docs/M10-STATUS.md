# M10 Status — Isolation

M10 adds a Linux Bubblewrap sandbox provider contract that fails closed when the isolation binary is unavailable. The provider unshares namespaces, exposes only read-only system trees, uses a private temporary filesystem and dies with its parent. Callers still need OS-level resource/time limits and a subprocess supervisor; the provider is not a claim that arbitrary host code is safe.
