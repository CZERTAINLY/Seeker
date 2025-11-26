package dscvr

import (
	"net/http"
)

const (
	// constants related to czertainly core attribute for passing seeker configuration
	seekerConfigurationAttrUUID        = "eb87e85b-297c-44f9-8f69-eebc86bf7c65"
	seekerConfigurationAttrName        = "seeker_scan_configuration"
	seekerConfigurationAttrType        = "data"
	seekerConfigurationAttrContentType = "codeblock"

	// constants related to czertainly core meta attribute for passing upload key
	seekerResultMetadataUploadKeyAttrUUID = "33081f5a-afcb-4c23-9ba5-5436d41bc847"
	seekerResultMetadataUploadKeyAttrName = "seeker_result_upload_key"

	// constants related to czertainly core meta attribute for passing result
	seekerResultMetadataFailureReasonAttrUUID = "429d078c-73d1-445a-bf48-606509a3619e"
	seekerResultMetadataFailureReasonAttrName = "seeker_result_string"

	// constants related to czertainly core meta attribute for cbom repository get url
	seekerResultMetadataKeyURLAttrUUID = "c000c778-fe69-4622-9269-33f98d8e6dac"
	seekerResultMetadataKeyURLAttrName = "seeker_result_key_url"

	functionalGroupCode = "discoveryProvider"
)

type EndpointDefinition struct {
	Path   string
	Method string
}

func DiscoveryRegisterEndpoint() EndpointDefinition {
	return EndpointDefinition{
		Path:   "/v1/connector/register",
		Method: http.MethodPost,
	}
}

func DiscoveryProviderEndpoints() map[string]EndpointDefinition {
	return map[string]EndpointDefinition{
		"checkHealth": {
			Path:   "/v1/health",
			Method: http.MethodGet,
		},
		"listSupportedFunctions": {
			Path:   "/v1",
			Method: http.MethodGet,
		},
		"listAttributeDefinitions": {
			Path:   "/v1/{functionalGroup}/{kind}/attributes",
			Method: http.MethodGet,
		},
		"validateAttributes": {
			Path:   "/v1/{functionalGroup}/{kind}/attributes/validate",
			Method: http.MethodPost,
		},
		"deleteDiscovery": {
			Path:   "/v1/{functionalGroup}/discover/{uuid}",
			Method: http.MethodDelete,
		},
		"discoverCertificate": {
			Path:   "/v1/{functionalGroup}/discover",
			Method: http.MethodPost,
		},
		"getDiscovery": {
			Path:   "/v1/{functionalGroup}/discover/{uuid}",
			Method: http.MethodPost,
		},
	}
}
