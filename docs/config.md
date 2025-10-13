# Seeker Configuration Schema

Note the [config.cue](config.cue) enables slightly more options, however those are those, which are supported now.

An example is in [manual-config.yaml](manual-config.yaml).

# Top-level object:
- `version` (required, number, fixed `0`)
- `service` (required, [Service](#service) section)
- `filesystem` (optional, [Filesystem](#filesystem) section)
- `containers` (optional, [ContainerConfig](#containerconfig))
- `ports` (optional, [Ports](#ports) section)

## Service
Service:
- `mode` (string, required, default "manual")
- `verbose` (bool, optional, default false) Extra logging.
- `dir` (string, optional) Local results directory. Results will be printed to standard output.

## Filesystem:

Configure filesystem scan. Following modules are used

 * (x509) certificates
 * secrets

- `enabled` (bool, default false) Enable filesystem scanning.
- `paths` (list of string, optional, default: if unset current working directory) paths to scan. If path is not accessible Warning is printed to logs.

Notes:
- If `filesystem.enabled` is false (or omitted) no filesystem paths are processed.

## Containers:

This section configures a Docker and other compatible container engine scan.

- `enabled` (bool, default false) Turn containers scanning off.
- `config` list of the engines to scan

## Engine configuration

- `name` (string, optional), friendly human name
- `type`: (empty, "docker", "podman", optional) is an engine type. Defaults to docker
- `host`: (string, required) socket path or endpoint to container engine. May reference an environment variable like `${DOCKER_HOST}`.
- images (list of string, optional) Explicit image names or patterns to include. Empty / omitted means discover all.

## Ports

- `enabled` (bool, optional, default false) Enable local port scanning.
- `binary` (string, optional) Path to nmap binary; falls back to PATH lookup.
- `ports` (string, optional, default "1-65535") Comma/range expression (e.g. `22,80,443,8000-8100`).
- `ipv4` (bool, optional, default true) Scan IPv4.
- `ipv6` (bool, optional, default true) Scan IPv6.

## Environment variables

Following values can contain environment variable name, which is expanded.

 * filesystem.paths
 * containers.config name, host and images
 * ports.binary
 * service.dir
