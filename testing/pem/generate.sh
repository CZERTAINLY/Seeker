#!/usr/bin/env bash
set -euo pipefail

DAYS="${DAYS:-365}"

gen_all_for_alg() {
  local ALG="$1" CN="$2"

  local KEY_PEM="tmp-${ALG}.key"       # OpenSSL "pkey" PKCS#8 (PEM)
  local CERT_PEM="tmp-${ALG}.crt"      # self-signed cert (PEM)

  echo "[*] ${ALG}: generating key"
  case "$ALG" in
    rsa)
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY_PEM" >/dev/null 2>&1
      ;;
    ec)
      openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$KEY_PEM" >/dev/null 2>&1
      ;;
    ed25519)
      openssl genpkey -algorithm ED25519 -out "$KEY_PEM" >/dev/null 2>&1
      ;;
    *)
      echo "Unsupported ALG=$ALG"; exit 1
      ;;
  esac

  echo "[*] ${ALG}: self-signed certificate"
  openssl req -new -x509 -key "$KEY_PEM" -out "$CERT_PEM" -days "$DAYS" \
    -subj "/CN=${CN}" >/dev/null 2>&1

  # -------- Certificates (PEM) --------
  cp "$CERT_PEM"            "${ALG}-cert.pem"                   # BEGIN CERTIFICATE
  openssl x509 -in "$CERT_PEM" -trustout -out "${ALG}-trusted-cert.pem" >/dev/null 2>&1
  # (↑ BEGIN TRUSTED CERTIFICATE)

  # -------- Private keys (PEM) --------
  # PKCS#8 (BEGIN PRIVATE KEY)
  cp "$KEY_PEM"             "${ALG}-key-pkcs8.pem"

  # Algorithm-specific legacy/traditional forms
  if [[ "$ALG" == "rsa" ]]; then
    # PKCS#1 (BEGIN RSA PRIVATE KEY)
    openssl rsa -in "$KEY_PEM" -out "${ALG}-key-pkcs1.pem" >/dev/null 2>&1
  fi

  if [[ "$ALG" == "ec" ]]; then
    # SEC1 (BEGIN EC PRIVATE KEY)
    openssl ec -in "$KEY_PEM" -out "${ALG}-key-ec.pem" >/dev/null 2>&1
  fi

  # For Ed25519, OpenSSL only emits PKCS#8 "PRIVATE KEY" (no "ED25519 PRIVATE KEY" header).

  # -------- PKCS#7 / CMS (PEM) --------
  # a) PKCS7 certificate bundle (BEGIN PKCS7)
  openssl crl2pkcs7 -nocrl -certfile "$CERT_PEM" -out "${ALG}-bundle-pkcs7.pem" >/dev/null 2>&1

  # b) CMS SignedData producing BEGIN CMS (attach a tiny payload to avoid oddities)
  printf "sample\n" | \
    openssl cms -sign -signer "$CERT_PEM" -inkey "$KEY_PEM" -outform PEM \
      -out "${ALG}-sample-cms.pem" -nodetach >/dev/null 2>&1

  # Optional: if you want the same CMS content rewrapped with a PKCS7 header:
  # openssl pkcs7 -in "${ALG}-sample-cms.pem" -out "${ALG}-cms-rewrapped-as-pkcs7.pem" >/dev/null 2>&1

  # Cleanup temporaries
  rm -f "$KEY_PEM" "$CERT_PEM"
  echo "    -> ${ALG}-cert.pem"
  echo "    -> ${ALG}-trusted-cert.pem"
  echo "    -> ${ALG}-key-pkcs8.pem"
  [[ "$ALG" == "rsa" ]] && echo "    -> ${ALG}-key-pkcs1.pem"
  [[ "$ALG" == "ec"  ]] && echo "    -> ${ALG}-key-ec.pem"
  echo "    -> ${ALG}-bundle-pkcs7.pem"
  echo "    -> ${ALG}-sample-cms.pem"
}

# Generate for all three algs with predictable CNs
gen_all_for_alg rsa      "rsa.pem.sample"
gen_all_for_alg ec       "ec.pem.sample"
gen_all_for_alg ed25519  "ed25519.pem.sample"

echo "[*] Done!"
