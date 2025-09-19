#!/usr/bin/env bash
set -euo pipefail

DAYS="${DAYS:-365}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: need $1" >&2; exit 1; }; }
need openssl
need zip

# --- helpers ---
mk_key_cert() {
  local PFX="$1" CN="$2" ALG="${3:-rsa}"
  case "$ALG" in
    rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${PFX}.key" ;;
    ec)  openssl genpkey -algorithm EC  -pkeyopt ec_paramgen_curve:P-256 -out "${PFX}.key" ;;
    ed25519) openssl genpkey -algorithm ED25519 -out "${PFX}.key" ;;
  esac
  openssl req -new -x509 -key "${PFX}.key" -out "${PFX}.crt" -days "$DAYS" -subj "/CN=${CN}"
}

strip_pem_headers() { # $1=in, $2=out
  awk 'BEGIN{p=0}/^-----BEGIN/{p=1;next}/^-----END/{p=0;next} p{print}' "$1" > "$2"
}

zip_dir_as() { (cd "$1" && zip -q -r "../$2" META-INF); }

# --- material ---
mk_key_cert signer "signer.zip.test" rsa
mk_key_cert extra  "extra.zip.test"  ec
echo "hello zip pkcs7" > data.txt

# --- PKCS#7/CMS test files ---
# PEM PKCS7 bundles
cat signer.crt > signer-only.pem
openssl crl2pkcs7 -nocrl -certfile signer-only.pem -out bundle1.pem

cat signer.crt extra.crt > signer-extra.pem
openssl crl2pkcs7 -nocrl -certfile signer-extra.pem -out bundle2.pem

# DER PKCS7
openssl pkcs7 -in bundle1.pem -outform DER -out bundle1.der

# CMS signed data
openssl cms -sign -in data.txt -signer signer.crt -inkey signer.key -outform PEM -out signed-attached.pem
openssl cms -sign -in data.txt -signer signer.crt -inkey signer.key -outform PEM -out signed-detached.pem -nodetach

# Headerless base64 (edge case)
strip_pem_headers bundle1.pem bundle1.b64

# --- build ZIP archives ---
# 1) JAR style (META-INF/CERT.RSA, PEM PKCS7)
mkdir -p build-jar/META-INF
cp bundle1.pem build-jar/META-INF/CERT.RSA
zip_dir_as build-jar jar-meta-cert-rsa.jar

# 2) APK style (META-INF/CERT.RSA, DER PKCS7)
mkdir -p build-apk/META-INF
cp bundle1.der build-apk/META-INF/CERT.RSA
zip_dir_as build-apk apk-meta-cert-rsa.apk

# 3) PK7/P7B entries
mkdir -p build-pk7/META-INF
cp bundle1.der build-pk7/META-INF/FOO.PK7
cp bundle2.pem build-pk7/META-INF/FOO.P7B
zip_dir_as build-pk7 zip-meta-foo-pk7-p7b.zip

# 4) Mixed extensions
mkdir -p build-mixed/META-INF
cp bundle1.pem        build-mixed/META-INF/ALPHA.RSA
cp signed-attached.pem build-mixed/META-INF/BETA.DSA
cp bundle2.pem        build-mixed/META-INF/GAMMA.EC
zip_dir_as build-mixed zip-meta-mixed-entries.zip

# 5) Headerless base64
mkdir -p build-b64/META-INF
cp bundle1.b64 build-b64/META-INF/RAW.RSA
zip_dir_as build-b64 zip-meta-headerless.zip

# 6) Signed (attached & detached)
mkdir -p build-signed/META-INF
cp signed-attached.pem build-signed/META-INF/SIGNED-ATTACHED.RSA
cp signed-detached.pem build-signed/META-INF/SIGNED-DETACHED.RSA
zip_dir_as build-signed zip-meta-signedcms.zip

# 7) Non-META-INF (ignored by detector)
mkdir -p build-nonmeta/OTHER
cp bundle1.pem build-nonmeta/OTHER/CERT.RSA
(cd build-nonmeta && zip -q -r ../zip-nonmeta-ignored.zip OTHER)

# 8) Bad/garbage
mkdir -p build-bad/META-INF
head -c 128 /dev/urandom > build-bad/META-INF/BAD.RSA
zip_dir_as build-bad zip-meta-bad-entry.zip

# --- cleanup temps ---
rm -f signer.key signer.crt extra.key extra.crt data.txt *.pem *.der *.b64 || true
rm -rf build-*

echo "[*] Done!"
