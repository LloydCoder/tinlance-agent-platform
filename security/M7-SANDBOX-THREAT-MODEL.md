# M7 Sandbox Threat Model

## Assets
Host filesystem, process namespace, credentials, network and execution resources.

## Threats
- path traversal;
- sensitive host path exposure;
- network escape;
- shell/command substitution;
- sandbox-provider absence;
- workspace escape;
- unbounded process/resource consumption.

## Required controls
Commands and paths are allowlisted, network is denied by default, sensitive paths are rejected, workspace identity is validated, and unavailable isolation fails closed. Production supervisors must enforce CPU, memory, process, disk and output limits.
