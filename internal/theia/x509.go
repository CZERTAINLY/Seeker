package theia

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	theiaPem "github.com/IBM/cbomkit-theia/scanner/pem"
	theia "github.com/IBM/cbomkit-theia/scanner/x509"
)

func ParseX509(b []byte, path string) ([]*theia.CertificateWithMetadata, error) {
	blocks := theiaPem.ParsePEMToBlocksWithTypeFilter(
		b,
		theiaPem.Filter{
			FilterType: theiaPem.TypeAllowlist,
			List:       []theiaPem.BlockType{theiaPem.BlockTypeCertificate},
		})

	ret := make([]*theia.CertificateWithMetadata, 0, len(blocks))
	var err error
	if blocks == nil {
		ret, err = theia.ParseCertificatesToX509CertificateWithMetadata(b, path)
		if err != nil {
			return nil, err
		}
	} else {
		for block := range blocks {
			more, err := theia.ParseCertificatesToX509CertificateWithMetadata(block.Bytes, path)
			if err != nil {
				return nil, err
			}
			ret = append(ret, more...)
		}
	}

	if len(ret) == 0 {
		return nil, fmt.Errorf("ParseX509: %w", ErrNoCertificatesFound)
	}

	return ret, nil
}

func X509ToComponents(cert *theia.CertificateWithMetadata) ([]cdx.Component, map[cdx.BOMReference][]string, error) {
	slicep, mapp, err := theia.GenerateCdxComponents(cert)
	if err != nil {
		return nil, nil, err
	}
	return *slicep, *mapp, nil
}
