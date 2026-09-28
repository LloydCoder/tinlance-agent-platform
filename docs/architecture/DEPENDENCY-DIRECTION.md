# Dependency Direction

The enforced DAG is:

```
contracts -> kernel -> services -> adapters -> apps
```

M0 services are identity, tenancy, authorization and policy. They may depend on contracts and, where required, kernel invariants. Contracts and kernel may not depend on services.

Provider SDKs, FastAPI, database clients and domain products are outside the core boundary. Future adapters translate those technologies into platform ports.

Architecture tests fail when a bounded package imports a package outside its allow-list.
