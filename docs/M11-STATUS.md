# M11 Status — API and SDK Surface

M11 adds a stable request/response API port and a minimal operational CLI entry point. Transport frameworks remain adapters around this contract; authorization and tenant validation stay inside the platform boundary rather than in HTTP routing code.
