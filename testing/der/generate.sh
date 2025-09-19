#!/usr/bin/env bash
set -euo pipefail

DAYS=365

gen_cert() {
  ALG="$1"
  KEYFILE="tmp-${ALG}.key"
  CRTFILE="tmp-${ALG}.crt"
  DERKEY="${ALG}-key.der"
  DERCERT="${ALG}-cert.der"

  echo "[*] Generating ${ALG} key..."
  case "$ALG" in
    rsa)
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEYFILE" >/dev/null 2>&1
      ;;
    ec)
      openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$KEYFILE" >/dev/null 2>&1
      ;;
    ed25519)
      openssl genpkey -algorithm ED25519 -out "$KEYFILE" >/dev/null 2>&1
      ;;
    *)
      echo "Unsupported ALG=$ALG"; exit 1
      ;;
  esac

  echo "[*] Creating ${ALG} self-signed certificate..."
  openssl req -new -x509 -key "$KEYFILE" -out "$CRTFILE" -days "$DAYS" \
    -subj "/CN=${ALG}.der.sample" >/dev/null 2>&1

  echo "[*] Converting ${ALG} to DER..."
  # Certificate → DER
  openssl x509 -in "$CRTFILE" -outform DER -out "$DERCERT"
  # Private key → PKCS#8 DER (unencrypted)
  openssl pkcs8 -topk8 -nocrypt -in "$KEYFILE" -outform DER -out "$DERKEY"

  rm -f "$KEYFILE" "$CRTFILE"
  echo "    -> $DERCERT, $DERKEY"
}

# Generate all variants
gen_cert rsa
gen_cert ec
gen_cert ed25519

echo "[*] Done!"
