// HELPER DEFINITIONS

ContainersConfig: {
  // Enable/disable the module
  enabled?: bool | *false
  // Unix socket paths or environment variable placeholders like ${DOCKER_HOST}.
  sockets?: [...string]
}

FSModuleConfig: {
  // Enable/disable the module
  enabled?: bool | *false

  // Paths to scan.
  paths?: [...string]

  // inspect local docker socket(s)
  docker?: ContainersConfig

  // inspect local podman socket(s)
  docker?: ContainersConfig
}

// Protocol config configures the protocol
ProtocolConfig: {
  // disable/enable ipv4
  ipv4?: bool | *true
  // enable/disable ipv6
  ipv6?: bool | *false
  // ports to scan, defaults to 1-65535, ports can be comma separates eg 22,222,230-240
  ports?: string | *"1-65535"
}

// PortsModuleConfig configure (local) port scanning
PortsModuleConfig: {
  // Enable/disable the module
  enabled?: bool | *false
  tls?: ProtocolConfig
  ssh?: ProtocolConfig
}

OutputConfig: {
  dir?: string
  repository_url?: string
}

ModeManual: {
  mode: "manual"
  output: OutputConfig
}

ModeCron: {
  mode: "cron"
  schedule: string
  output: OutputConfig
}

ModeDiscovery: {
  mode: "discovery"
  core_url: string
  output: OutputConfig
}

// SCHEMA DEFINITION

// schema version is 1
version: 1
// Module definitions
modules: {
  // certificates scans for x509 and other certificates
  certificates?: FSModuleConfig
  // secrets uses gitleaks to detect various leaks
  secrets?: FSModuleConfig
  // ports perform a local port scan
  ports?: PortsModuleConfig
}
// How the service will operate
service: (ModeManual | ModeCron | ModeDiscovery)
