# Seeker

CLI tool, which scans actual filesystem, containers and ports and detects

 * certificates
 * secrets

Generates BOM in CycloneDX format.

# Usage

You may want to generate a X509 certificate in order to have a cryptographic
material in a current directory.

```sh
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```

# Filesystem scan

```yaml
version: 0

service:
    mode: manual
    verbose: false
    log: stderr
    dir: .

filesystem:
    enabled: true
    paths: []
```

This configuration snippet searches for certificates and secrets inside local directory.


```sh
$ ./seeker run --config seeker.yaml
{"time":"2025-10-10T14:14:04.632066182+02:00","level":"WARN","msg":"command has no timeout","path":"usr/bin/seeker","seeker":{"cmd":"run","pid":2488398}}
{"time":"2025-10-10T14:14:05.410539638+02:00","level":"INFO","msg":"bom saved","path":"seeker-2025-10-10-02:14:05.json","seeker":{"cmd":"run","pid":2488398}}
```

# Container scan

Seeker can scan images stored inside Docker(podman). Those searches for
certificates and secrets exactly like filesystem scan do. Docker host can be
specified via environment variable.

The docker host can be specified via environment variable such as `${DOCKER_HOST}`.


```yaml
version: 0

service:
    mode: manual
    verbose: false
    log: stderr
    dir: .

containers:
    -
        enabled: false
        host: ${DOCKER_HOST}
        images:
            - docker.io/library/alpine:3.22.1
```

```sh
$ time ./seeker run --config seeker.yaml
{"time":"2025-10-11T11:38:54.207199641+02:00","level":"WARN","msg":"command has no timeout","path":"usr/bin/seeker","seeker":{"cmd":"run","pid":2610219}}
{"time":"2025-10-11T11:39:41.257456265+02:00","level":"INFO","msg":"bom saved","path":"seeker-2025-10-11-11-39-41.json","seeker":{"cmd":"run","pid":2610219}}

real    0m47.083s
user    1m33.919s
sys     0m0.442s
```

# Port scan

Port scan is performed via nmap, which must be installed on a target machine
too. It tries to detect TLS and SSH.

```yaml
ports:
    enabled: true
    ipv4: true
    ipv6: false
```

```sh
$ time ./seeker run --config seeker.yaml
{"time":"2025-10-11T11:46:39.889049897+02:00","level":"WARN","msg":"command has no timeout","path":"usr/bin/seeker","seeker":{"cmd":"run","pid":2614823}}
{"time":"2025-10-11T11:46:57.244593739+02:00","level":"INFO","msg":"bom saved","path":"seeker-2025-10-11-11-46-57.json","seeker":{"cmd":"run","pid":2614823}}

real    0m17.389s
user    0m0.838s
sys     0m2.538s
```

# Save and upload the result

By default, seeker prints the BOM to standard output. The `dir` directive
changes this behavior, saving the files as `seeker-$date.json` in the specified
directory. The `.` means the current working directory.

```yaml
service:
    mode: manual
    dir: .
```

The following setup is needed to upload to a [CBOM-Repository](https://github.com/CZERTAINLY/CBOM-Repository): Currently, Seeker does not support making authenticated requests.

```yaml
service:
    mode: manual
    repository:
      enabled: true
      url: "http://localhost:8080"
```

Both the `dir` and the `repository` can be combined in a single configuration
file. Seeker will attempt both methods and log an error if either one fails.

```yaml
service:
    mode: manual
    dir: .
    repository:
      enabled: true
      url: "http://localhost:8080"
```

# File format specification

See [docs/config.cue] for a specification and (manual-config.yaml)[docs/manual-config.yaml] for an example config.
