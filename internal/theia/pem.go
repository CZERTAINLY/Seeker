package theia

import (
	"encoding/pem"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	theia "github.com/IBM/cbomkit-theia/scanner/pem"
)

// ParsePEM parses the []byte and try to detect
// * PRIVATE KEY - x509.ParsePKCS8PrivateKey
// * EC PRIVATE KEY - x509.ParseECPrivateKey
// * RSA PRIVATE KEY - x509.ParsePKCS1PrivateKey
// * PUBLIC KEY - x509.ParsePKIXPublicKey
// * RSA PUBLIC KEY - x509.ParsePKCS1PublicKey
// * OPENSSH PRIVATE KEY - (golang.org/x/crypto/ssh).ParseRawPrivateKey
//
// TODO: ENCRYPTED PRIVATE KEY
func ParsePEM(b []byte) ([]pem.Block, error) {
	filter := theia.Filter{
		FilterType: theia.TypeAllowlist,
		List: []theia.BlockType{
			theia.BlockTypePrivateKey,
			theia.BlockTypeECPrivateKey,
			theia.BlockTypeRSAPrivateKey,
			theia.BlockTypePublicKey,
			theia.BlockTypeRSAPublicKey,
			theia.BlockTypeOPENSSHPrivateKey,
		},
	}

	blockMap := theia.ParsePEMToBlocksWithTypeFilter(
		b,
		filter,
	)

	blocks := make([]pem.Block, 0, len(blockMap))
	for blockp := range blockMap {
		blocks = append(blocks, *blockp)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("ParsePEM: %s", ErrNoCertificatesFound)
	}
	return blocks, nil
}

func PEMToComponents(block pem.Block) ([]cdx.Component, error) {
	return theia.GenerateCdxComponents(&block)
}
