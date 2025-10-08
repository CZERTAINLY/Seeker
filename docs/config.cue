// SCHEMA DEFINITION
#Config

#Config: {
version: *0 | int
filesystem?: #Filesystem
containers?: #Containers
ports?: #Ports

service: #Service
}

// CUE definitions

// Filesystem specify paths for scan using filesystem modules
// if paths are missing, then the current CWD is examined
#Filesystem: {
  enabled?: *false | bool
  paths?: [...string]
}

// Containers specify a list of container daemons
// to inspect
#Containers: [...#ContainerConfig]

#ContainerDaemon: ("docker" | "podman")

#ContainerConfig: {
  enabled?: bool | *false
  name?: string
  type: #ContainerDaemon
  socket?: string
  images?: [...string]
}

#Ports: {
  enabled?: bool | *false
  binary?: string
  ports?: string | *"1-65535"
  ipv4?: bool | *true
  ipv6?: bool | *false
}

#Service: (#ServiceManual)

#ServiceManual: {
  #OutputFields
  mode: "manual"
  verbose?: bool | *false
  log?: *"stderr" | "stdout" | "discard" | string
}

#OutputFields: {
  dir?: string
  repository?: #Repository
}

#Repository: {
  enabled?: bool | *false
  url: string
  auth: (#AuthNone|#AuthStaticToken)
}

#AuthNone: {
  type: "none"
}

#AuthStaticToken: {
  type: "static_token"
  token: string
}
