package cdxprops

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // seeker is going to recognize even obsoleted crypto
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ---------- constants & shared lookups ----------

const (
	refUnknownKey       cdx.BOMReference = "crypto/key/unknown@unknown"
	refUnknownAlgorithm cdx.BOMReference = "crypto/algorithm/unknown@unknown"
)

// ---------- ASN.1 helpers (declared once) ----------

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type certOuter struct {
	TBSCert   asn1.RawValue
	SigAlg    algorithmIdentifier
	Signature asn1.BitString
}

type spki struct {
	Algorithm     algorithmIdentifier
	SubjectPubKey asn1.BitString
}

func sigAlgOID(cert *x509.Certificate) (string, bool) {
	var outer certOuter
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		return "", false
	}
	return outer.SigAlg.Algorithm.String(), true
}

func spkiOID(cert *x509.Certificate) (string, bool) {
	var info spki
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err != nil {
		return "", false
	}
	return info.Algorithm.Algorithm.String(), true
}

func ReadSignatureAlgorithmRef(ctx context.Context, cert *x509.Certificate) cdx.BOMReference {
	// Prefer Go’s typed enum first (covers all classic algs cleanly).
	if ref, ok := sigAlgRef[cert.SignatureAlgorithm]; ok {
		return ref
	}

	// Fall back to OID (PQC / unknown to stdlib).
	oid, ok := sigAlgOID(cert)
	if !ok {
		slog.DebugContext(ctx, "Failed to parse signatureAlgorithm OID")
		return refUnknownAlgorithm
	}
	if ref, ok := pqcSigOIDRef[oid]; ok {
		return ref
	}

	slog.DebugContext(ctx, "Unknown signature algorithm OID", "oid", oid)
	return refUnknownAlgorithm
}

// certHitToComponents converts an X.509 certificate to a CycloneDX component
func (c Converter) certHitToComponents(ctx context.Context, hit model.CertHit) ([]cdx.Component, []cdx.Dependency, error) {
	if hit.Cert == nil {
		return nil, nil, errors.New("x509.Certificate is nil")
	}

	certCompo := c.certComponent(ctx, hit)
	signatureCompo := c.certHitToSignatureAlgComponent(ctx, hit)
	publicKeyAlgCompo, publicKeyCompo := publicKeyComponents(ctx, hit.Cert.PublicKeyAlgorithm, hit.Cert.PublicKey)
	certificateRelatedProperties(&publicKeyCompo, hit.Cert)

	compos := []cdx.Component{
		certCompo, // Main certificate
		signatureCompo,
		publicKeyAlgCompo,
		// TODO!!!! the hashAlgComponent
		/*
			hashAlgComponent,          // e.g., "SHA-256" (optional, could be part of signature)
		*/
	}

	deps := []cdx.Dependency{
		{
			Ref: certCompo.BOMRef,
			Dependencies: &[]string{
				signatureCompo.BOMRef,
				publicKeyAlgCompo.BOMRef,
			},
		},
		{
			Ref: publicKeyAlgCompo.BOMRef,
			Dependencies: &[]string{
				publicKeyAlgCompo.BOMRef,
			},
		},
	}

	/*
		dependencies := []cdx.Dependency{
		    // Certificate depends on its cryptographic components
		    {
		        Ref: certBOMRef,
		        Dependencies: []string{
		            signatureAlgBOMRef,   // Used to verify certificate signature
		            publicKeyAlgBOMRef,   // Public key contained in cert
		        },
		    },

		    // Signature algorithm may depend on hash algorithm
		    {
		        Ref: signatureAlgBOMRef,
		        Dependencies: []string{
		            hashAlgBOMRef,  // If SHA256WithRSA, depends on SHA256
		        },
		    },

		    // If certificate chain is available
		    {
		        Ref: certBOMRef,
		        Dependencies: []string{
		            issuerCertBOMRef,  // Depends on issuer cert for trust
		        },
		    },
		}
	*/

	return compos, deps, nil
}

func (c Converter) certComponent(ctx context.Context, hit model.CertHit) cdx.Component {
	cert := hit.Cert

	certHash := c.bomRefHasher(cert.Raw)

	// Extract fingerprints
	fingerprints := extractFingerprints(cert)

	// Extract subject alternative names
	subjectAltNames := extractSubjectAlternativeNames(cert)

	// Extract key usage and extended key usage
	keyUsage := extractKeyUsage(cert.KeyUsage)
	extKeyUsage := extractExtendedKeyUsage(cert.ExtKeyUsage)

	// Generate algorithm BOM references (for dependencies)
	sigAlgBOMRef := ReadSignatureAlgorithmRef(ctx, cert)
	pubKeyAlgBOMRef := ReadSubjectPublicKeyRef(ctx, cert)

	// Build certificate properties
	certProps := &cdx.CertificateProperties{
		SubjectName:           cert.Subject.String(),
		IssuerName:            cert.Issuer.String(),
		NotValidBefore:        cert.NotBefore.Format(time.RFC3339),
		NotValidAfter:         cert.NotAfter.Format(time.RFC3339),
		SignatureAlgorithmRef: sigAlgBOMRef,
		SubjectPublicKeyRef:   pubKeyAlgBOMRef,
		CertificateFormat:     "X.509",
		CertificateExtension:  filepath.Ext(hit.Location),
	}

	name := formatCertificateName(cert)

	// Build the certificate component
	certComponent := cdx.Component{
		BOMRef:  "crypto/certificate/" + name + "@" + certHash,
		Type:    cdx.ComponentTypeCryptographicAsset,
		Name:    name,
		Version: cert.SerialNumber.String(),
		Hashes:  fingerprints,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:             cdx.CryptoAssetTypeCertificate,
			CertificateProperties: certProps,
		},
		Properties: buildCertificateProperties(cert, hit.Location, hit.Source, keyUsage, extKeyUsage, subjectAltNames),
	}

	if c.czertainly {
		SetComponentProp(&certComponent, CzertainlyComponentCertificateSourceFormat, hit.Source)
		SetComponentBase64Prop(&certComponent, CzertainlyComponentCertificateBase64Content, cert.Raw)
	}

	return certComponent
}

func (c Converter) certHitToSignatureAlgComponent(ctx context.Context, hit model.CertHit) cdx.Component {
	sigAlg := hit.Cert.SignatureAlgorithm
	algName := sigAlg.String()
	bomRef := ReadSignatureAlgorithmRef(ctx, hit.Cert)
	oid, ok := sigAlgOID(hit.Cert)
	if !ok {
		oid = "unknown"
	}
	cryptoProps := cdx.CryptoAlgorithmProperties{
		Primitive:              cdx.CryptoPrimitiveSignature,
		ParameterSetIdentifier: oid,
	}

	// Add curve information for ECDSA algorithms
	if curve := curveInformation(ctx, sigAlg); curve != "" {
		cryptoProps.Curve = curve
	}

	props := buildSignatureAlgorithmProperties(sigAlg)

	return cdx.Component{
		BOMRef:  string(bomRef),
		Type:    cdx.ComponentTypeCryptographicAsset,
		Name:    algName,
		Version: oid,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cryptoProps,
		},
		Properties: &props,
	}

}

func certificateRelatedProperties(compo *cdx.Component, cert *x509.Certificate) {
	// Use certificate serial number as ID if available
	if compo == nil || cert == nil {
		return
	}
	if compo.CryptoProperties == nil {
		compo.CryptoProperties = &cdx.CryptoProperties{}
	}
	if compo.CryptoProperties.RelatedCryptoMaterialProperties == nil {
		compo.CryptoProperties.RelatedCryptoMaterialProperties = &cdx.RelatedCryptoMaterialProperties{}
	}
	relatedProps := compo.CryptoProperties.RelatedCryptoMaterialProperties
	relatedProps.ID = cert.SerialNumber.String()

	// Set state based on validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		relatedProps.State = cdx.CryptoKeyStatePreActivation
	} else if now.After(cert.NotAfter) {
		relatedProps.State = cdx.CryptoKeyStateDeactivated
	} else {
		relatedProps.State = cdx.CryptoKeyStateActive
	}

	relatedProps.CreationDate = cert.NotBefore.Format(time.RFC3339)
	relatedProps.ActivationDate = cert.NotBefore.Format(time.RFC3339)
	relatedProps.ExpirationDate = cert.NotAfter.Format(time.RFC3339)
}

// curveInformation returns the curve name for ECDSA signature algorithms
func curveInformation(ctx context.Context, sigAlg x509.SignatureAlgorithm) string {
	switch sigAlg {
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256:
		return "secp256r1" // P-256
	case x509.ECDSAWithSHA384:
		return "secp384r1" // P-384
	case x509.ECDSAWithSHA512:
		return "secp521r1" // P-521
	default:
		return ""
	}
}

// formatCertificateName creates a human-readable name for the certificate
func formatCertificateName(cert *x509.Certificate) string {
	// Try to use CN (Common Name) if available
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Fallback to full subject DN
	subject := cert.Subject.String()
	if subject != "" {
		return subject
	}

	// Last resort: use serial number
	return fmt.Sprintf("Certificate %s", cert.SerialNumber.String())
}

// extractFingerprints calculates certificate fingerprints
func extractFingerprints(cert *x509.Certificate) *[]cdx.Hash {
	hashes := []cdx.Hash{
		{
			Algorithm: cdx.HashAlgoSHA256,
			Value:     hex.EncodeToString(sha256Hash(cert.Raw)),
		},
		{
			Algorithm: cdx.HashAlgoSHA1,
			Value:     hex.EncodeToString(sha1Hash(cert.Raw)),
		},
	}
	return &hashes
}

// sha256Hash computes SHA-256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// sha1Hash computes SHA-1 hash
func sha1Hash(data []byte) []byte {
	hash := sha1.Sum(data)
	return hash[:]
}

// extractSubjectAlternativeNames extracts SANs from certificate
func extractSubjectAlternativeNames(cert *x509.Certificate) []string {
	sans := []string{}

	for _, dns := range cert.DNSNames {
		sans = append(sans, fmt.Sprintf("DNS:%s", dns))
	}

	for _, email := range cert.EmailAddresses {
		sans = append(sans, fmt.Sprintf("EMAIL:%s", email))
	}

	for _, ip := range cert.IPAddresses {
		sans = append(sans, fmt.Sprintf("IP:%s", ip.String()))
	}

	for _, uri := range cert.URIs {
		sans = append(sans, fmt.Sprintf("URI:%s", uri.String()))
	}

	return sans
}

// extractKeyUsage extracts key usage flags
func extractKeyUsage(usage x509.KeyUsage) []string {
	ret := []string{}

	if usage&x509.KeyUsageDigitalSignature != 0 {
		ret = append(ret, "DigitalSignature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		ret = append(ret, "ContentCommitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		ret = append(ret, "KeyEncipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		ret = append(ret, "DataEncipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		ret = append(ret, "KeyAgreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		ret = append(ret, "CertSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		ret = append(ret, "CRLSign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		ret = append(ret, "EncipherOnly")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		ret = append(ret, "DecipherOnly")
	}

	return ret
}

// extractExtendedKeyUsage extracts extended key usage
func extractExtendedKeyUsage(extKeyUsage []x509.ExtKeyUsage) []string {
	ret := []string{}

	ekuMap := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "ServerAuth",
		x509.ExtKeyUsageClientAuth:                     "ClientAuth",
		x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
		x509.ExtKeyUsageEmailProtection:                "EmailProtection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
		x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MicrosoftKernelCodeSigning",
	}

	for _, eku := range extKeyUsage {
		if name, ok := ekuMap[eku]; ok {
			ret = append(ret, name)
		}
	}

	return ret
}

// buildCertificateProperties creates additional properties for the certificate
func buildCertificateProperties(cert *x509.Certificate, path, source string, keyUsage, extKeyUsage, sans []string) *[]cdx.Property {
	var props []cdx.Property
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		props = append(props, cdx.Property{
			Name:  "cert:maxPathLen",
			Value: strconv.Itoa(cert.MaxPathLen),
		})
	}

	if len(keyUsage) > 0 {
		props = append(props, cdx.Property{
			Name:  "cert:keyUsage",
			Value: strings.Join(keyUsage, ","),
		})
	}

	if len(extKeyUsage) > 0 {
		props = append(props, cdx.Property{
			Name:  "cert:extendedKeyUsage",
			Value: strings.Join(extKeyUsage, ","),
		})
	}

	if len(sans) > 0 {
		props = append(props, cdx.Property{
			Name:  "cert:subjectAlternativeNames",
			Value: strings.Join(sans, ","),
		})
	}

	if len(cert.OCSPServer) > 0 {
		props = append(props, cdx.Property{
			Name:  "cert:ocspServers",
			Value: strings.Join(cert.OCSPServer, ","),
		})
	}

	if len(cert.IssuingCertificateURL) > 0 {
		props = append(props, cdx.Property{
			Name:  "cert:issuingCertificateURLs",
			Value: strings.Join(cert.IssuingCertificateURL, ","),
		})
	}

	if len(cert.CRLDistributionPoints) > 0 {
		props = append(props, cdx.Property{
			Name:  "cert:crlDistributionPoints",
			Value: strings.Join(cert.CRLDistributionPoints, ","),
		})
	}

	return &props
}

// getKeySize returns the key size in bits
func getKeySize(pubKey interface{}) int {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	case *dsa.PublicKey:
		return key.Y.BitLen()
	default:
		return 0
	}
}

func ReadSubjectPublicKeyRef(ctx context.Context, cert *x509.Certificate) cdx.BOMReference {
	// First try concrete key types the stdlib understands.
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return cdx.BOMReference(fmt.Sprintf("crypto/key/rsa-%d@1.2.840.113549.1.1.1", pub.N.BitLen()))
	case *ecdsa.PublicKey:
		switch pub.Params().BitSize {
		case 256:
			return "crypto/key/ecdsa-p256@1.2.840.10045.3.1.7"
		case 384:
			return "crypto/key/ecdsa-p384@1.3.132.0.34"
		case 521:
			return "crypto/key/ecdsa-p521@1.3.132.0.35"
		default:
			return "crypto/key/ecdsa-unknown@1.2.840.10045.2.1"
		}
	case ed25519.PublicKey:
		return "crypto/key/ed25519-256@1.3.101.112"
	case *dsa.PublicKey:
		return cdx.BOMReference(fmt.Sprintf("crypto/key/dsa-%d@1.2.840.10040.4.1", pub.P.BitLen()))
	}

	// Otherwise parse SPKI.algorithm OID (PQC & other non-stdlib types).
	oid, ok := spkiOID(cert)
	if !ok {
		slog.DebugContext(ctx, "Failed to parse SPKI OID")
		return refUnknownKey
	}
	if ref, ok := spkiOIDRef[oid]; ok {
		return ref
	}

	slog.DebugContext(ctx, "Unknown public key algorithm OID", "oid", oid)
	return refUnknownKey
}
