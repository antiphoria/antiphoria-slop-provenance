#!/usr/bin/env bash
# C2PA key generation for Antiphoria Slop Provenance (Linux/macOS)
# Bash equivalent of gen-c2pa-keys.ps1; same OpenSSL workflow.

set -e

cd "$(dirname "$0")/.."
mkdir -p keys

# 1) Root CA config (create if missing)
root_cnf="keys/c2pa-root-ca.cnf"
if [[ ! -f "$root_cnf" ]]; then
  cat > "$root_cnf" << 'ROOTCNF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = Antiphoria C2PA Root CA
O = Antiphoria

[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
ROOTCNF
fi

# 2) Leaf cert extensions (C2PA EKU)
leaf_ext="keys/c2pa-leaf.ext"
if [[ ! -f "$leaf_ext" ]]; then
  cat > "$leaf_ext" << 'LEAFEXT'
[v3_leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.36
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
LEAFEXT
fi

openssl_conf="$(cd keys && pwd)/c2pa-root-ca.cnf"
export OPENSSL_CONF="$openssl_conf"

# 3) Generate root CA key + cert
openssl ecparam -name prime256v1 -genkey -noout -out keys/c2pa-root-ca.key.pem
openssl req -x509 -new -sha256 -days 3650 \
  -key keys/c2pa-root-ca.key.pem \
  -out keys/c2pa-root-ca.cert.pem \
  -config "$openssl_conf"

# 4) Generate leaf key + CSR
openssl ecparam -name prime256v1 -genkey -noout -out keys/c2pa-leaf.key.pem
openssl req -new -sha256 \
  -key keys/c2pa-leaf.key.pem \
  -out keys/c2pa-leaf.csr.pem \
  -subj "/CN=Antiphoria Slop Provenance C2PA Signer/O=Antiphoria" \
  -config "$openssl_conf"

# 5) Sign leaf with root CA
openssl x509 -req \
  -in keys/c2pa-leaf.csr.pem \
  -CA keys/c2pa-root-ca.cert.pem \
  -CAkey keys/c2pa-root-ca.key.pem \
  -CAcreateserial \
  -out keys/c2pa-leaf.cert.pem \
  -days 825 -sha256 \
  -extfile keys/c2pa-leaf.ext \
  -extensions v3_leaf

# 6) Build chain (leaf first, then root) + private key in PKCS#8
cat keys/c2pa-leaf.cert.pem keys/c2pa-root-ca.cert.pem > keys/c2pa-cert-chain.pem
openssl pkcs8 -topk8 -nocrypt -in keys/c2pa-leaf.key.pem -out keys/c2pa-private-key.pem

# 7) Quick validation checks
openssl verify -CAfile keys/c2pa-root-ca.cert.pem keys/c2pa-leaf.cert.pem
openssl x509 -in keys/c2pa-leaf.cert.pem -text -noout

echo ""
echo "C2PA keys generated successfully."
echo ""
echo "Next steps (BYOV):"
echo "  1. Move c2pa-root-ca.key.pem to offline USB"
echo "  2. Move c2pa-private-key.pem into the vault (with private.key)"
echo "  3. Keep c2pa-cert-chain.pem on disk; set C2PA_SIGN_CERT_CHAIN_PATH=./keys/c2pa-cert-chain.pem in .env"
echo "  4. SECURE CLEANUP: Delete keys/private.key and keys/c2pa-private-key.pem from disk!"
