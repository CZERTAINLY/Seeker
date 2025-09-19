#!/usr/bin/env bash
set -euo pipefail

# ===== Config ===============================================================
DAYS="${DAYS:-365}"
PASS="${PASS:-changeit}"                 # default store/key password
EPASS="${EPASS:-}"                       # empty password variant
DIFF_KEYPASS="${DIFF_KEYPASS:-keysecret}"
CN_BASE="${CN_BASE:-example.test}"

# ===== Helpers ==============================================================

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found"; exit 1; }; }
need keytool

# Write a password to a temp file and echo the filename (used by keytool ...:file)
passfile() { local f; f="$(mktemp)"; printf "%s" "${1-}" >"$f"; echo "$f"; }

warn() { echo "  [warn] $*"; }

# Convenience wrappers to pass passwords via files (supports empty)
kt_genkeypair() { # alias, dname, store, storepass, keypass, type(JKS|JCEKS), alg, size
  local alias="$1" dname="$2" ks="$3" sp="$4" kp="$5" stype="$6" alg="$7" size="$8"
  local spf kpfile; spf="$(passfile "$sp")"; kpfile="$(passfile "$kp")"
  keytool -genkeypair -alias "$alias" -dname "$dname" -validity "$DAYS" \
    -keyalg "$alg" -keysize "$size" \
    -storetype "$stype" -keystore "$ks" \
    -storepass:file "$spf" -keypass:file "$kpfile" -noprompt
  rm -f "$spf" "$kpfile"
}

kt_exportcert_rfc() { # alias, store, storepass, outfile
  local alias="$1" ks="$2" sp="$3" out="$4"
  local spf; spf="$(passfile "$sp")"
  keytool -exportcert -rfc -alias "$alias" -keystore "$ks" \
    -storepass:file "$spf" -file "$out"
  rm -f "$spf"
}

kt_certreq() { # alias, store, storepass, outfile
  local alias="$1" ks="$2" sp="$3" out="$4"
  local spf; spf="$(passfile "$sp")"
  keytool -certreq -alias "$alias" -keystore "$ks" \
    -storepass:file "$spf" -file "$out"
  rm -f "$spf"
}

kt_gencert() { # signer-alias, signer-store, signer-pass, csr, out
  local alias="$1" ks="$2" sp="$3" csr="$4" out="$5"
  local spf; spf="$(passfile "$sp")"
  keytool -gencert -alias "$alias" -keystore "$ks" \
    -storepass:file "$spf" -infile "$csr" -outfile "$out" \
    -rfc -validity "$DAYS" \
    -ext bc=ca:false -ext ku=digitalSignature,keyEncipherment -ext eku=serverAuth,clientAuth
  rm -f "$spf"
}

kt_importcert() { # alias, store, storepass, file
  local alias="$1" ks="$2" sp="$3" file="$4"
  local spf; spf="$(passfile "$sp")"
  keytool -importcert -alias "$alias" -file "$file" -keystore "$ks" \
    -storepass:file "$spf" -noprompt
  rm -f "$spf"
}

kt_delete_alias() { # alias, store, pass
  local alias="$1" ks="$2" sp="$3"
  local spf; spf="$(passfile "$sp")"
  keytool -delete -alias "$alias" -keystore "$ks" -storepass:file "$spf"
  rm -f "$spf"
}

kt_importkeystore() { # src, srctype, srcpass, dst, dsttype, dstpass
  local src="$1" srctype="$2" srcp="$3" dst="$4" dsttype="$5" dstp="$6"
  local sp1 sp2; sp1="$(passfile "$srcp")"; sp2="$(passfile "$dstp")"
  keytool -importkeystore \
    -srckeystore "$src" -srcstoretype "$srctype" -srcstorepass:file "$sp1" \
    -destkeystore "$dst" -deststoretype "$dsttype" -deststorepass:file "$sp2"
  rm -f "$sp1" "$sp2"
}

# ===== Start fresh ==========================================================
rm -f *.jks *.jceks *.cer *.csr *.p12 2>/dev/null || true

created=()

# ===== 1) BASIC JKS keystores ==============================================

echo "[*] JKS: basic RSA self-signed"
kt_genkeypair "rsa" "CN=rsa.${CN_BASE}" "jks-basic-rsa.jks" "$PASS" "$PASS" "JKS" "RSA" 2048
created+=("jks-basic-rsa.jks")

echo "[*] JKS: basic EC (P-256) self-signed"
kt_genkeypair "ec" "CN=ec.${CN_BASE}" "jks-basic-ec.jks" "$PASS" "$PASS" "JKS" "EC" 256
created+=("jks-basic-ec.jks")

# Optional legacy DSA (don’t fail the run if unsupported)
if keytool -help 2>/dev/null | grep -qi DSA; then
  echo "[*] JKS: legacy DSA self-signed (if supported)"
  if kt_genkeypair "dsa" "CN=dsa.${CN_BASE}" "jks-legacy-dsa.jks" "$PASS" "$PASS" "JKS" "DSA" 1024 2>/dev/null; then
    created+=("jks-legacy-dsa.jks")
  else
    warn "DSA generation failed (expected on modern JDKs)"
  fi
fi

echo "[*] JKS: keypass different from storepass"
kt_genkeypair "diffpass" "CN=diffpass.${CN_BASE}" "jks-different-keypass.jks" "$PASS" "$DIFF_KEYPASS" "JKS" "RSA" 2048
created+=("jks-different-keypass.jks")

echo "[*] JKS: empty store password"
if kt_genkeypair "emptypass" "CN=emptypass.${CN_BASE}" "jks-empty-storepass.jks" "$EPASS" "$EPASS" "JKS" "RSA" 2048 2>/dev/null; then
  created+=("jks-empty-storepass.jks")
else
  warn "Empty-password JKS not supported by your keytool/provider"
fi

# ===== 2) JKS with chain (CA -> Leaf) ======================================

echo "[*] JKS: CA -> Leaf chain"
# CA with CA extensions
kt_genkeypair "ca" "CN=Test CA, O=Demo, C=US" "tmp-ca.jks" "$PASS" "$PASS" "JKS" "RSA" 2048
# Mark as CA by self-signing with BC/KeyUsage extensions via -gencert self-CSR trick:
# Export CA cert (self-signed is fine for demo)
kt_exportcert_rfc "ca" "tmp-ca.jks" "$PASS" "tmp-ca.cer"

# Leaf
kt_genkeypair "leaf" "CN=leaf.${CN_BASE}" "tmp-leaf.jks" "$PASS" "$PASS" "JKS" "RSA" 2048
kt_certreq "leaf" "tmp-leaf.jks" "$PASS" "tmp-leaf.csr"

# CA signs CSR -> leaf-signed.cer
if kt_gencert "ca" "tmp-ca.jks" "$PASS" "tmp-leaf.csr" "tmp-leaf-signed.cer" 2>/dev/null; then
  # Import CA and leaf into leaf store to form a chain
  kt_importcert "ca" "tmp-leaf.jks" "$PASS" "tmp-ca.cer"
  kt_importcert "leaf" "tmp-leaf.jks" "$PASS" "tmp-leaf-signed.cer"

  # Round-trip through PKCS12 to consolidate chain cleanly
  kt_importkeystore "tmp-leaf.jks" "JKS" "$PASS" "tmp-leaf.p12" "PKCS12" "$PASS"
  kt_importkeystore "tmp-leaf.p12" "PKCS12" "$PASS" "jks-with-chain.jks" "JKS" "$PASS"
  created+=("jks-with-chain.jks")
else
  warn "Chain signing (gencert) failed on this JDK; skipping chained JKS"
fi

# ===== 3) JKS truststore (TrustedCertificateEntry) =========================

echo "[*] JKS: truststore with multiple TrustedCertificateEntry"
if [ -f "jks-basic-rsa.jks" ] && [ -f "jks-basic-ec.jks" ]; then
  kt_exportcert_rfc "rsa" "jks-basic-rsa.jks" "$PASS" "tmp-rsa.cer"
  kt_exportcert_rfc "ec"  "jks-basic-ec.jks"  "$PASS" "tmp-ec.cer"
  # Create empty JKS and import trusted certs
  kt_genkeypair "placeholder" "CN=placeholder" "jks-truststore.jks" "$PASS" "$PASS" "JKS" "RSA" 1024
  kt_delete_alias "placeholder" "jks-truststore.jks" "$PASS"
  kt_importcert "trusted-rsa"           "jks-truststore.jks" "$PASS" "tmp-rsa.cer"
  kt_importcert "trusted-unicode-★"     "jks-truststore.jks" "$PASS" "tmp-ec.cer"
  if [ -f "tmp-ca.cer" ]; then
    kt_importcert "trusted-ca"          "jks-truststore.jks" "$PASS" "tmp-ca.cer"
  fi
  created+=("jks-truststore.jks")
else
  warn "Skipping truststore: prereq keystores missing"
fi

# ===== 4) JCEKS variants ===================================================

echo "[*] JCEKS: basic RSA PrivateKeyEntry"
kt_genkeypair "rsa" "CN=jceks-rsa.${CN_BASE}" "jceks-basic-rsa.jceks" "$PASS" "$PASS" "JCEKS" "RSA" 2048
created+=("jceks-basic-rsa.jceks")

echo "[*] JCEKS: EC PrivateKeyEntry + AES SecretKeyEntry"
kt_genkeypair "ec" "CN=jceks-ec.${CN_BASE}" "jceks-ec-with-secret.jceks" "$PASS" "$PASS" "JCEKS" "EC" 256
# Add a SecretKeyEntry (ignore failure if provider restricts)
if keytool -genseckey -alias secret-aes128 -keyalg AES -keysize 128 \
    -storetype JCEKS -keystore jceks-ec-with-secret.jceks \
    -storepass "$PASS" -keypass "$PASS" -noprompt >/dev/null 2>&1; then
  :
else
  warn "SecretKeyEntry generation failed (provider restrictions?)"
fi
created+=("jceks-ec-with-secret.jceks")

echo "[*] JCEKS: empty store password"
if kt_genkeypair "emptypass" "CN=jceks-emptypass.${CN_BASE}" "jceks-empty-storepass.jceks" "$EPASS" "$EPASS" "JCEKS" "RSA" 2048 2>/dev/null; then
  created+=("jceks-empty-storepass.jceks")
else
  warn "Empty-password JCEKS not supported by your keytool/provider"
fi

echo "[*] JCEKS: different key password"
kt_genkeypair "diffpass" "CN=jceks-diffpass.${CN_BASE}" "jceks-different-keypass.jceks" "$PASS" "$DIFF_KEYPASS" "JCEKS" "RSA" 2048
created+=("jceks-different-keypass.jceks")

# ===== Cleanup temps; keep only keystores ==================================
rm -f tmp-*.cer tmp-*.csr tmp-*.p12 tmp-*.jks 2>/dev/null || true

echo
echo "[*] Done!"
