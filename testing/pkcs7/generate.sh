#!/usr/bin/env bash
set -euo pipefail

DAYS="${DAYS:-365}"

# --- helpers ---------------------------------------------------------------

mk_key_cert() {
  # $1 = prefix, $2 = CN, $3 = alg (rsa|ec|ed25519)
  local PFX="$1" CN="$2" ALG="${3:-rsa}"
  case "$ALG" in
    rsa)     openssl genpkey -algorithm RSA     -pkeyopt rsa_keygen_bits:2048 -out "${PFX}.key" >/dev/null 2>&1 ;;
    ec)      openssl genpkey -algorithm EC      -pkeyopt ec_paramgen_curve:P-256 -out "${PFX}.key" >/dev/null 2>&1 ;;
    ed25519) openssl genpkey -algorithm ED25519                          -out "${PFX}.key" >/dev/null 2>&1 ;;
    *) echo "Unsupported alg: $ALG" ; exit 1 ;;
  esac
  openssl req -new -x509 -key "${PFX}.key" -out "${PFX}.crt" -days "$DAYS" \
    -subj "/CN=${CN}" >/dev/null 2>&1
}

rewrap_to_pkcs7_header() {
  # Some OpenSSL builds emit BEGIN CMS; rewrap to BEGIN PKCS7 if you want that header.
  # $1 in (PEM CMS), $2 out (PEM PKCS7)
  openssl pkcs7 -in "$1" -out "$2" >/dev/null 2>&1 || true
}

to_der_if_pem() {
  # $1 in (PEM), $2 out (DER)
  openssl pkcs7 -in "$1" -outform DER -out "$2" >/dev/null 2>&1 || true
}

to_headerless_b64() {
  # $1 in (PEM), $2 out (.b64)
  awk 'BEGIN{p=0}/^-----BEGIN/{p=1;next}/^-----END/{p=0;next} p{print}' "$1" > "$2"
}

# --- keys & certs ---------------------------------------------------------

# Signer (for SignedData)
mk_key_cert signer "signer.pkcs7.sample" rsa
# Recipient (for EnvelopedData)
mk_key_cert recip  "recipient.pkcs7.sample" ec
# Bonus extra cert to create a multi-cert bundle
mk_key_cert extra  "extra.bundle.sample" ed25519

# Tiny payloads
echo "hello pkcs7"      > data.txt
echo "another payload"  > data2.txt

# --- A) Degenerate SignedData (cert bundles only) -------------------------

# 1) Simple bundle with 1 cert (PEM, PKCS7 header)
openssl crl2pkcs7 -nocrl -certfile signer.crt  -out bundle1-pkcs7.pem  >/dev/null 2>&1
# 2) Bundle with multiple certs (PEM, PKCS7 header)
cat signer.crt extra.crt > chain.pem
openssl crl2pkcs7 -nocrl -certfile chain.pem   -out bundle2-pkcs7.pem  >/dev/null 2>&1
# 3) Same bundles in DER (.p7b)
to_der_if_pem bundle1-pkcs7.pem bundle1.p7b
to_der_if_pem bundle2-pkcs7.pem bundle2.p7b
# 4) Headerless base64 versions (useful to test detectors)
to_headerless_b64 bundle1-pkcs7.pem bundle1.b64
to_headerless_b64 bundle2-pkcs7.pem bundle2.b64

# --- B) SignedData over content ------------------------------------------

# Attached (encapsulated) – CMS header (PEM) + DER .p7m
openssl cms -sign -in data.txt -signer signer.crt -inkey signer.key \
  -outform PEM -out signed-attached-cms.pem >/dev/null 2>&1
rewrap_to_pkcs7_header signed-attached-cms.pem signed-attached-pkcs7.pem
to_der_if_pem signed-attached-cms.pem signed-attached.p7m

# Detached – CMS header (PEM) + DER .p7s
openssl cms -sign -in data.txt -signer signer.crt -inkey signer.key \
  -outform PEM -out signed-detached-cms.pem -nodetach >/dev/null 2>&1
rewrap_to_pkcs7_header signed-detached-cms.pem signed-detached-pkcs7.pem
to_der_if_pem signed-detached-cms.pem signed-detached.p7s

# Another payload for variety
openssl cms -sign -in data2.txt -signer signer.crt -inkey signer.key \
  -outform PEM -out signed2-cms.pem >/dev/null 2>&1
rewrap_to_pkcs7_header signed2-cms.pem signed2-pkcs7.pem
to_der_if_pem signed2-cms.pem signed2.p7m

# Headerless base64 variants (detector edge cases)
to_headerless_b64 signed-attached-cms.pem signed-attached.b64
to_headerless_b64 signed-detached-cms.pem signed-detached.b64

# --- C) EnvelopedData (encrypted to recipient) ---------------------------

# PEM CMS (BEGIN CMS), DER .p7m
openssl cms -encrypt -in data.txt -recip recip.crt -aes256 \
  -outform PEM -out enveloped-cms.pem >/dev/null 2>&1
to_der_if_pem enveloped-cms.pem enveloped.p7m
rewrap_to_pkcs7_header enveloped-cms.pem enveloped-pkcs7.pem || true

# --- D) CompressedData (if supported by your OpenSSL) ---------------------

if openssl cms -help 2>/dev/null | grep -qi compress; then
  openssl cms -compress -in data.txt -outform PEM -out compressed-cms.pem >/dev/null 2>&1 || true
  to_der_if_pem compressed-cms.pem compressed.p7m || true
  rewrap_to_pkcs7_header compressed-cms.pem compressed-pkcs7.pem || true
fi

# --- Cleanup temps; keep only pkcs7/cms artifacts ------------------------

rm -f signer.key signer.crt recip.key recip.crt extra.key extra.crt chain.pem data.txt data2.txt

echo "[*] Done!"
