package model

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
)

type Detection struct {
	Path       string
	Components []cdx.Component
}
