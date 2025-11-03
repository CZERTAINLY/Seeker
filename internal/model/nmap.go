package model

// Nmap is a result of nmap scan on a given host/ip address
type Nmap struct {
	Address string
	Status  string
	Ports   []NmapPort
}

// NmapPort contains nmap output for a given port
type NmapPort struct {
	ID          int
	State       string
	Protocol    string
	Service     NmapService
	Ciphers     []SSLEnumCiphers
	TLSCerts    []Finding
	SSHHostKeys []SSHHostKey
	Scripts     []NmapScript
}

type NmapService struct {
	Name    string
	Product string
	Version string
}

// SSHHostKey is an output of `ssh-hostkey` script of nmap
type SSHHostKey struct {
	Key         string
	Type        string
	Bits        string
	Fingerprint string
}

// SSLEnumCiphers is an ouptut of `ssl-enum-ciphers` script of nmap
type SSLEnumCiphers struct {
	Name    string
	Ciphers []string
}

// NmapScript is a raw output of nmap script, which is not
// handled
type NmapScript struct {
	ID    string
	Value string
}
