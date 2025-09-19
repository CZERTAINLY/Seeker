#!/usr/bin/env bash
set -euo pipefail

# ========== Config ==========
DAYS="${DAYS:-365}"
PASS="${PASS:-changeit}"   # password for most .p12 files
EPASS="${EPASS:-}"         # empty-password variant (default: empty)

# ========== Helpers ==========
mk_key_cert() {
  # $1=prefix  $2=CN  $3=alg (rsa|ec)
  local PFX="$1" CN="$2" ALG="${3:-rsa}"
  case "$ALG" in
    rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${PFX}.key" >/dev/null 2>&1 ;;
    ec)  openssl genpkey -algorithm EC  -pkeyopt ec_paramgen_curve:P-256 -out "${PFX}.key" >/dev/null 2>&1 ;;
    *)   echo "Unsupported alg: $ALG" >&2; exit 1 ;;
  esac
  openssl req -new -x509 -key "${PFX}.key" -out "${PFX}.crt" -days "$DAYS" \
    -subj "/CN=${CN}" >/dev/null 2>&1
}

# ========== Material ==========
mk_key_cert rsa   "rsa.pkcs12.sample" rsa
mk_key_cert ec    "ec.pkcs12.sample"  ec
mk_key_cert extra "extra.ca.sample"   rsa

# Build chain files
cat rsa.crt extra.crt > rsa-chain.pem
cat ec.crt  extra.crt > ec-chain.pem
cat rsa.crt ec.crt extra.crt > trust-bundle.pem

# ========== PKCS#12 variants ==========
echo "[*] Exporting PKCS#12 variants..."

openssl pkcs12 -export -inkey rsa.key -in rsa.crt \
  -name "RSA Basic" -passout "pass:$PASS" -out rsa-basic.p12

openssl pkcs12 -export -inkey ec.key -in ec.crt \
  -name "EC Basic" -passout "pass:$PASS" -out ec-basic.p12

openssl pkcs12 -export -inkey rsa.key -in rsa.crt \
  -name "RSA EmptyPass" -passout "pass:$EPASS" -out rsa-empty-pass.p12

openssl pkcs12 -export -inkey rsa.key -in rsa.crt -certfile rsa-chain.pem \
  -name "RSA With Chain" -caname "Extra CA" -passout "pass:$PASS" \
  -out rsa-with-chain.p12

openssl pkcs12 -export -inkey ec.key -in ec.crt -certfile ec-chain.pem \
  -name "EC With Chain" -caname "Extra CA" -passout "pass:$PASS" \
  -out ec-with-chain.p12

openssl pkcs12 -export -inkey rsa.key -in rsa.crt \
  -name "RSA Weak MAC" -macalg sha1 -iter 1 -passout "pass:$PASS" \
  -out rsa-weak-mac-iter1.p12

openssl pkcs12 -export -inkey rsa.key -in rsa.crt -certfile rsa-chain.pem \
  -name "RSA AES PBE" -caname "Extra CA" \
  -keypbe AES-256-CBC -certpbe AES-256-CBC \
  -macalg sha512 -iter 10000 -passout "pass:$PASS" \
  -out rsa-aes-pbe-iter10000.p12

openssl pkcs12 -export -inkey ec.key -in ec.crt \
  -name "EC No MAC" -nomac -passout "pass:$PASS" \
  -out ec-nomac.p12

openssl pkcs12 -export -nokeys -in trust-bundle.pem \
  -name "Trust Bundle" -passout "pass:$PASS" \
  -out truststore-multi.p12

openssl pkcs12 -export -inkey rsa.key -in rsa.crt \
  -name "Friendly A ★" -passout "pass:$PASS" \
  -out rsa-friendly-A.p12

openssl pkcs12 -export -inkey rsa.key -in rsa.crt \
  -name "Another Name" -passout "pass:$PASS" \
  -out rsa-friendly-B.p12

# ========== PFX copies ==========
for f in *.p12; do cp -f "$f" "${f%.p12}.pfx"; done

# ========== Cleanup ==========
rm -f *.key *.crt *.pem

echo "[*] Done!"
