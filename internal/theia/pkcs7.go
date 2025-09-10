package theia

import (
	"encoding/pem"
	"fmt"

	theia "github.com/IBM/cbomkit-theia/scanner/x509"
	"github.com/smallstep/pkcs7"
)

func ParsePKCS7(b []byte, path string) ([]*theia.CertificateWithMetadata, error) {
	block, _ := pem.Decode(b)
	pkcs7Data, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		return nil, err
	}
	if pkcs7Data == nil {
		return nil, fmt.Errorf("ParsePKCS7: %s", ErrNoCertificatesFound)
	}

	ret := make([]*theia.CertificateWithMetadata, 0, len(pkcs7Data.Certificates))
	for _, cert := range pkcs7Data.Certificates {
		thCert, err := theia.NewX509CertificateWithMetadata(cert, path)
		if err != nil {
			return nil, err
		}
		ret = append(ret, thCert)
	}
	return ret, nil
}
