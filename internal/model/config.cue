package config
// SCHEMA DEFINITION
#Config

// Seeker top-level configuration object.
#Config: {
version: 0
filesystem?: #Filesystem
containers?: #Containers
ports?: #Ports
service: #Service
}

// Set of filesystem scanning settings; when disabled no filesystem paths are processed.
// If paths unset, current working directory is assumed.
#Filesystem: {
  enabled?: *false | bool
  paths?: [...string]
}

// List of container daemon configurations to inspect (Docker/Podman).
#Containers: {
  enabled?: bool | *false
  config: [...#ContainerConfig]
}

// Supported container daemon types.
#ContainerDaemon: ("" | "docker" | "podman")

// Configuration for a single container daemon integration.
// enabled: when false this entry is ignored.
// name: optional identifier (defaults to daemon type if absent).
// type: daemon implementation, defaults to docker.
// host: path or endpoint for the daemon (e.g. /var/run/docker.sock). Can be specified as environment variable, like ${DOCKER_HOST}
// images: explicit image names/patterns to include (empty => discover all).
#ContainerConfig: {
  enabled?: bool | *false
  name?: string
  type?: #ContainerDaemon
  host: string
  images?: [...string]
}

// Local port scanning module configuration.
// enabled: when false this entry is ignored.
// binary: optional path to nmap binary, $PATH is used by default
// ports: comma/range expression (e.g. "22,80,443,8000-8100") default full range.
// ipv4 / ipv6: protocol selection flags. Both default to true.
#Ports: {
  enabled?: bool | *false
  binary?: string
  ports?: string | *"1-65535"
  ipv4?: bool | *true
  ipv6?: bool | *true
}

// Manual service execution configuration.
#Service: {
  #ServiceFields
  mode: *"manual" | "timer"
  every?: string
  if mode == "timer" { every: string & !="" }
}

// OutputFields specify common output for a scanner
// verbose: extra logging output when true.
// log: destination ("stderr","stdout","discard" or file path).
// dir: local results directory.
// repository: remote repository configuration.
#ServiceFields: {
  verbose?: bool | *false
  log?: *"stderr" | "stdout" | "discard" | string
  dir?: string
  repository?: #Repository
}

#Repository: {
  enabled?: bool | *false
  url: string
  auth: #Auth
}

#Auth: {
  type: *"" | "token"
  token?: string
  if type == "token" { token: string & !="" }
}
