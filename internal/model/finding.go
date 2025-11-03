package model

type Finding struct {
	Raw      []byte // raw data for a detectors to parse
	Location string // path or port or image name or any similar identifier
	Source   string // how it was obtained nmap/zip file/docker or anything
}
