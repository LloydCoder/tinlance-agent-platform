# OpenTelemetry adapter

Core observability remains provider-neutral. Production deployments should implement ObservabilitySink with OpenTelemetry and export through the organization's collector/backend. OpenTelemetry Python has stable traces and metrics APIs; logs are still evolving. This adapter stays outside the core package graph so a telemetry vendor cannot become an authority dependency.
