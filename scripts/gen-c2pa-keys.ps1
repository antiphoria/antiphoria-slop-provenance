# C2PA key generation for Antiphoria Slop Provenance
# Works around Anaconda/conda OpenSSL having a hardcoded config path from its build env.
# Set OPENSSL_CONF so openssl req can find a valid config when creating the CSR.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

New-Item -ItemType Directory -Path ".\keys" -Force | Out-Null

# 1) Root CA config (create if missing)
$rootCnf = ".\keys\c2pa-root-ca.cnf"
if (-not (Test-Path $rootCnf)) {
    @'
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
'@ | Set-Content -Path $rootCnf -Encoding ascii
}

# Work around Anaconda OpenSSL's hardcoded config path (C:\ci\...\_h_env\...)
$opensslConf = (Resolve-Path $rootCnf).Path
$env:OPENSSL_CONF = $opensslConf

# 2) Leaf cert extensions (C2PA EKU)
@'
[v3_leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.36
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
'@ | Set-Content -Path ".\keys\c2pa-leaf.ext" -Encoding ascii

# 3) Generate root CA key + cert
openssl ecparam -name prime256v1 -genkey -noout -out ".\keys\c2pa-root-ca.key.pem"
openssl req -x509 -new -sha256 -days 3650 `
  -key ".\keys\c2pa-root-ca.key.pem" `
  -out ".\keys\c2pa-root-ca.cert.pem" `
  -config $opensslConf

# 4) Generate leaf key + CSR (OPENSSL_CONF set above; -config also passed for robustness)
openssl ecparam -name prime256v1 -genkey -noout -out ".\keys\c2pa-leaf.key.pem"
openssl req -new -sha256 `
  -key ".\keys\c2pa-leaf.key.pem" `
  -out ".\keys\c2pa-leaf.csr.pem" `
  -subj "/CN=Antiphoria Slop Provenance C2PA Signer/O=Antiphoria" `
  -config $opensslConf

# 5) Sign leaf with root CA
openssl x509 -req `
  -in ".\keys\c2pa-leaf.csr.pem" `
  -CA ".\keys\c2pa-root-ca.cert.pem" `
  -CAkey ".\keys\c2pa-root-ca.key.pem" `
  -CAcreateserial `
  -out ".\keys\c2pa-leaf.cert.pem" `
  -days 825 -sha256 `
  -extfile ".\keys\c2pa-leaf.ext" `
  -extensions v3_leaf

# 6) Build chain (leaf first, then root) + private key in PKCS#8 (c2pa-python expects this)
Get-Content ".\keys\c2pa-leaf.cert.pem", ".\keys\c2pa-root-ca.cert.pem" |
  Set-Content ".\keys\c2pa-cert-chain.pem" -Encoding ascii
openssl pkcs8 -topk8 -nocrypt -in ".\keys\c2pa-leaf.key.pem" -out ".\keys\c2pa-private-key.pem"

# 7) Quick validation checks
openssl verify -CAfile ".\keys\c2pa-root-ca.cert.pem" ".\keys\c2pa-leaf.cert.pem"
openssl x509 -in ".\keys\c2pa-leaf.cert.pem" -text -noout

Write-Host "`nC2PA keys generated successfully."
Write-Host ""
Write-Host "Next steps (BYOV):"
Write-Host "  1. Move c2pa-root-ca.key.pem to offline USB"
Write-Host "  2. Move c2pa-private-key.pem into the vault (with private.key)"
Write-Host "  3. Keep c2pa-cert-chain.pem on disk; set C2PA_SIGN_CERT_CHAIN_PATH=./keys/c2pa-cert-chain.pem in .env"
Write-Host "  4. SECURE CLEANUP: Delete keys/private.key and keys/c2pa-private-key.pem from your SSD!"
