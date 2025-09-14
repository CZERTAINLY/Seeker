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
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:a01b1d1f-e7b1-486f-a0d8-37f940ee2980",
  "version": 1,
```

3. scan the docker image

> docker pull must be done before

```sh
go run -race cmd/seeker/main.go a scan --docker gcr.io/distroless/base-debian12
```
