# Seeker

Is in alpha phase, no stable CLI exists

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
./seeker alpha scan
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:a01b1d1f-e7b1-486f-a0d8-37f940ee2980",
  "version": 1,
```

3. scan the docker image

> docker pull must be done before

```sh
./seeker a scan --docker gcr.io/distroless/base-debian12
```

## Environment variables

Those follow the structure of CLI. Use prefix `SEEKER_`.

```sh
./seeker a scan --path /path
```

is an equivalent of

```sh
SEEKER_ALPHA_SCAN_PATH=/path ./seeker a scan
```

## and config file

The same apply for a config file. The config file structure matches the CLI flags.

```yaml
alpha:
  scan:
    path: /path
```

The file `seeker.yaml` is read from

1. current directory
2. default OS config directory
3. via --config file `./seeker --config /path/to/config.yaml`
4. or path can be specified via `SEEKERCONFIG` environment variable
