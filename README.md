# Seeker

CLI tool, which scans actual filesystem, containers and open ports and detects

 * certificates
 * secrets

Generates BOM in CycloneDX format.

# Usage

You may want to generate a X509 certificate in order to have some cryptography
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

# Modes of operation

## Manual

This particular mode is the simplest one. Simply run `seeker run` and the
command will run the scan, upload results and finish. Use it in case
scans are going to be orchestrated by other system.

```yaml
service:
    mode: manual
```

## Timer

More advanced is a timer mode. It uses a standard `cron` 5 field syntax. All interpretation and scheduling is done in the machine's local time zone (`time.Local`).

```yaml
version: 0
service:
    mode: timer
    schedule:
      cron: "* * * * *"
```

[github.com/robfig/cron/](https://pkg.go.dev/github.com/robfig/cron/) library
is used under the hood, so the format supported is defined by this library.

### CRON Expression Format

A cron expression represents a set of times, using 5 or 6 space-separated fields.

	Field name   | Mandatory? | Allowed values  | Allowed special characters
	----------   | ---------- | --------------  | --------------------------
	Seconds      | No         | 0-59            | * / , -
	Minutes      | Yes        | 0-59            | * / , -
	Hours        | Yes        | 0-23            | * / , -
	Day of month | Yes        | 1-31            | * / , - ?
	Month        | Yes        | 1-12 or JAN-DEC | * / , -
	Day of week  | Yes        | 0-6 or SUN-SAT  | * / , - ?

Month and Day-of-week field values are case insensitive.  "SUN", "Sun", and
"sun" are equally accepted.

The specific interpretation of the format is based on the Cron Wikipedia page:
[https://en.wikipedia.org/wiki/Cron](https://en.wikipedia.org/wiki/Cron)

### Special Characters

#### Asterisk ( * )

The asterisk indicates that the cron expression will match for all values of the
field; e.g., using an asterisk in the 5th field (month) would indicate every
month.

#### Slash ( / )

Slashes are used to describe increments of ranges. For example 3-59/15 in the
1st field (minutes) would indicate the 3rd minute of the hour and every 15
minutes thereafter. The form "*\/..." is equivalent to the form "first-last/...",
that is, an increment over the largest possible range of the field.  The form
"N/..." is accepted as meaning "N-MAX/...", that is, starting at N, use the
increment until the end of that specific range.  It does not wrap around.

#### Comma ( , )

Commas are used to separate items of a list. For example, using "MON,WED,FRI" in
the 5th field (day of week) would mean Mondays, Wednesdays and Fridays.

#### Hyphen ( - )

Hyphens are used to define ranges. For example, 9-17 would indicate every
hour between 9am and 5pm inclusive.

#### Question mark ( ? )

Question mark may be used instead of '*' for leaving either day-of-month or
day-of-week blank.

#### Predefined schedules

You may use one of several pre-defined schedules in place of a cron expression.

	Entry                  | Description                                | Equivalent To
	-----                  | -----------                                | -------------
	@yearly (or @annually) | Run once a year, midnight, Jan. 1st        | 0 0 1 1 *
	@monthly               | Run once a month, midnight, first of month | 0 0 1 * *
	@weekly                | Run once a week, midnight between Sat/Sun  | 0 0 * * 0
	@daily (or @midnight)  | Run once a day, midnight                   | 0 0 * * *
	@hourly                | Run once an hour, beginning of hour        | 0 * * * *

#### Intervals

You may also schedule a job to execute at fixed intervals, starting at the time it's added
or cron is run. This is supported by formatting the cron spec like this:

    @every <duration>

where "duration" is a string accepted by time.ParseDuration
(http://golang.org/pkg/time/#ParseDuration).

For example, "@every 1h30m10s" would indicate a schedule that activates after
1 hour, 30 minutes, 10 seconds, and then every interval after that.

Note: The interval does not take the job runtime into account.  For example,
if a job takes 3 minutes to run, and it is scheduled to run every 5 minutes,
it will have only 2 minutes of idle time between each run.

### ISO 8601 Duration

It is possible to specify the syntax based on ISO-8601 duration and
[java.time.Duration](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/time/Duration.html#parse(java.lang.CharSequence)).

Format is `PnDTnHnMn` and day is exactly 24 hours. Fraction numbers are allowed
`P0.5D` and decimal point can be point of comma. Fractional part can be up to 9
digits long. Negative numbers are possible too `PT1H-7M`.

```yaml
version: 0
service:
    mode: timer
    schedule:
      # 1 day 2 hours 3 minutes 4 s
      duration: "P1DT2H3M4S"
```

# Config file format specification

See [docs/config.cue] for a specification and (manual-config.yaml)[docs/manual-config.yaml] for an example config.

# Fast unit test execution

Some tests like nmap scan or a walk.Images, which inspect all docker images
found can run too long when executed.

It is advised to run unit tests with `-short` parameter in order to get the
result as fast as possible for a developer. Github actions runs a full suite
on every PR.

