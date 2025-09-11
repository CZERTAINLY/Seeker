# Seeker

Is in alpha phase, no real CLI exists

## Detect x509 certificate

* PEM format
* raw DER format
* or try to detect the chain

1. create one

```sh
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```

2. scan local filesystem

```sh
go run -race cmd/seeker/main.go alpha scan
DETECTED: [{Path:.git/hooks/update.sample Typ:script}]
DETECTED: [{Path:.git/hooks/prepare-commit-msg.sample Typ:script}]
DETECTED: [{Path:cert.pem Typ:X509}]
```

3. scan the docker image

> docker pull must be done before

```sh
go run -race cmd/seeker/main.go a scan --docker gcr.io/distroless/base-debian12
DETECTED: [{Path:/etc/update-motd.d/10-uname Typ:script}]
DETECTED: [{Path:/etc/ssl/certs/ca-certificates.crt Typ:X509}]
```
