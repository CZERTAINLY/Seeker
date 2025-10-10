# Seeker

CLI tool, which scans actual filesystem and detects

 * certificates
 * secrets

And generates COM in CycloneDX format.

# Usage

Generate X509 certificate to have something to scan
```sh
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```

Use this minimal config file

```yaml
version: 0
filesystem:
    enabled: true
    paths: []
service:
    mode: manual
    verbose: false
    log: stderr
    dir: .
```

And run

```sh
$ ./seeker run --config seeker.yaml
{"time":"2025-10-10T14:14:04.632066182+02:00","level":"WARN","msg":"command has no timeout","path":"/home/michal/projects/3key/Seeker/seeker","seeker":{"cmd":"run","pid":2488398}}
{"time":"2025-10-10T14:14:05.410539638+02:00","level":"INFO","msg":"bom saved","path":"seeker-2025-10-10-02:14:05.json","seeker":{"cmd":"run","pid":2488398}}
```
