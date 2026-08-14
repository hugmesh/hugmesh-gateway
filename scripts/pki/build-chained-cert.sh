#!/usr/bin/env sh
# Build a chained cert hierarchy for a HugMesh stack:
#
#   hugmesh.net Root CA  (input — `--root-ca` / `--root-key`)
#      └── <stack-name> Intermediate CA      (generated here)
#             └── server leaf cert
#             └── mTLS client leaf cert
#
# All openssl + keytool work happens inside short-lived Docker
# containers so the host never needs openssl or a JDK installed.
#
# Outputs (under $OUT_DIR, default `./pki-out/`):
#   intermediate.crt      — the new intermediate (signed by the input root)
#   intermediate.key      — the new intermediate's private key
#   server.crt            — leaf server cert (CN=$LEAF_CN)
#   server.key            — leaf server key
#   client.crt            — mTLS client leaf cert
#   client.key            — mTLS client key
#   fullchain.pem         — leaf + intermediate concatenated (RFC 5246)
#   truststore.p12        — PKCS12 truststore (root + intermediate) for JVMs
#
# Usage:
#   scripts/pki/build-chained-cert.sh \
#     --root-ca   /path/to/systems-root.crt \
#     --root-key  /path/to/systems-root.key \
#     --stack     hugmesh-games \
#     --leaf-cn   hugmesh-games-gateway \
#     --san       DNS:hugmesh.games,DNS:*.hugmesh.games \
#     [--out-dir  ./pki-out]
#
# Idempotent — if $OUT_DIR/intermediate.crt already exists, the script
# skips generation. Delete the dir to force a regenerate.

set -eu

OUT_DIR="${OUT_DIR:-$(pwd)/pki-out}"
STACK_NAME=""
LEAF_CN=""
SAN_LIST=""
ROOT_CA=""
ROOT_KEY=""
PASSWORD="${KEYSTORE_PASSWORD:-hugmesh}"

while [ $# -gt 0 ]; do
  case "$1" in
    --root-ca)   ROOT_CA="$2"; shift 2 ;;
    --root-key)  ROOT_KEY="$2"; shift 2 ;;
    --stack)     STACK_NAME="$2"; shift 2 ;;
    --leaf-cn)   LEAF_CN="$2"; shift 2 ;;
    --san)       SAN_LIST="$2"; shift 2 ;;
    --out-dir)   OUT_DIR="$2"; shift 2 ;;
    *) echo "[pki] unknown flag: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$ROOT_CA" ] || [ -z "$ROOT_KEY" ] || [ -z "$STACK_NAME" ] || [ -z "$LEAF_CN" ]; then
  echo "[pki] usage: $0 --root-ca <path> --root-key <path> --stack <name> --leaf-cn <cn> [--san <list>] [--out-dir <dir>]" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

if [ -f "$OUT_DIR/intermediate.crt" ] && [ -f "$OUT_DIR/truststore.p12" ]; then
  echo "[pki] $OUT_DIR already populated — skipping (delete to regenerate)"
  exit 0
fi

ROOT_CA_ABS=$(realpath "$ROOT_CA")
ROOT_KEY_ABS=$(realpath "$ROOT_KEY")
ROOT_CA_DIR=$(dirname "$ROOT_CA_ABS")
ROOT_CA_NAME=$(basename "$ROOT_CA_ABS")
ROOT_KEY_NAME=$(basename "$ROOT_KEY_ABS")

echo "[pki] generating chained certs for stack=$STACK_NAME leaf=$LEAF_CN"
echo "[pki]   root CA  : $ROOT_CA_ABS"
echo "[pki]   out dir  : $OUT_DIR"

# ---- 1: intermediate CA signed by the hugmesh.net root ----
docker run --rm \
  -v "$ROOT_CA_DIR:/root-ca:ro" \
  -v "$OUT_DIR:/out" \
  -e STACK_NAME="$STACK_NAME" \
  -e ROOT_CA_NAME="$ROOT_CA_NAME" \
  -e ROOT_KEY_NAME="$ROOT_KEY_NAME" \
  alpine:3.20 sh -c '
    apk add --no-cache openssl >/dev/null
    cd /out
    cat > intermediate.cnf <<EOF
[ req ]
distinguished_name = req
prompt             = no
[ req_distinguished_name ]
CN = ${STACK_NAME} Intermediate CA
O  = HugMesh Systems
[ v3_intermediate ]
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always, issuer
EOF
    openssl genrsa -out intermediate.key 4096 2>/dev/null
    openssl req -new -key intermediate.key -config intermediate.cnf -out intermediate.csr 2>/dev/null
    openssl x509 -req \
      -in intermediate.csr \
      -CA "/root-ca/${ROOT_CA_NAME}" \
      -CAkey "/root-ca/${ROOT_KEY_NAME}" \
      -CAcreateserial \
      -out intermediate.crt \
      -days 1825 \
      -sha256 \
      -extfile intermediate.cnf -extensions v3_intermediate \
      2>/dev/null
    chmod 644 intermediate.crt intermediate.key
    chown $(stat -c %u .):$(stat -c %g .) intermediate.* 2>/dev/null || true
  '

# ---- 2: server + mTLS client leaves signed by the intermediate ----
docker run --rm \
  -v "$OUT_DIR:/out" \
  -e LEAF_CN="$LEAF_CN" \
  -e SAN_LIST="${SAN_LIST:-DNS:localhost}" \
  alpine:3.20 sh -c '
    apk add --no-cache openssl >/dev/null
    cd /out
    cat > leaf.cnf <<EOF
[ req ]
distinguished_name = req
prompt             = no
req_extensions     = v3_req
[ req_distinguished_name ]
CN = ${LEAF_CN}
O  = HugMesh Systems
[ v3_req ]
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName   = ${SAN_LIST}
EOF
    # server leaf
    openssl genrsa -out server.key 2048 2>/dev/null
    openssl req -new -key server.key -config leaf.cnf -out server.csr 2>/dev/null
    openssl x509 -req -in server.csr \
      -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
      -out server.crt -days 825 -sha256 \
      -extfile leaf.cnf -extensions v3_req 2>/dev/null

    # mTLS client leaf — same v3_req extensions, different CN.
    cat > client.cnf <<EOF2
[ req ]
distinguished_name = req
prompt             = no
req_extensions     = v3_req
[ req_distinguished_name ]
CN = ${LEAF_CN}-mtls-client
O  = HugMesh Systems
[ v3_req ]
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName   = DNS:client
EOF2
    openssl genrsa -out client.key 2048 2>/dev/null
    openssl req -new -key client.key -config client.cnf -out client.csr 2>/dev/null
    openssl x509 -req -in client.csr \
      -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
      -out client.crt -days 825 -sha256 \
      -extfile client.cnf -extensions v3_req 2>/dev/null

    # fullchain = leaf + intermediate; root deliberately excluded so
    # the TLS handshake stays within RFC 5246 (the client trusts the
    # root, the server shouldn'\''t serve it).
    cat server.crt intermediate.crt > fullchain.pem
    rm -f *.csr *.srl leaf.cnf client.cnf
    chmod 644 *.crt *.key fullchain.pem
    chown $(stat -c %u .):$(stat -c %g .) *.crt *.key fullchain.pem 2>/dev/null || true
  '

# ---- 3: Java truststore containing root + intermediate ----
docker run --rm \
  -v "$ROOT_CA_DIR:/root-ca:ro" \
  -v "$OUT_DIR:/out" \
  -e ROOT_CA_NAME="$ROOT_CA_NAME" \
  -e PASSWORD="$PASSWORD" \
  eclipse-temurin:21-jre sh -c '
    cd /out
    rm -f truststore.p12
    keytool -importcert -trustcacerts -noprompt \
      -alias hugmesh-systems-root \
      -file "/root-ca/${ROOT_CA_NAME}" \
      -keystore truststore.p12 -storetype PKCS12 \
      -storepass "$PASSWORD" >/dev/null
    keytool -importcert -trustcacerts -noprompt \
      -alias hugmesh-stack-intermediate \
      -file intermediate.crt \
      -keystore truststore.p12 -storetype PKCS12 \
      -storepass "$PASSWORD" >/dev/null
    chmod 644 truststore.p12
    chown $(stat -c %u .):$(stat -c %g .) truststore.p12 2>/dev/null || true
  '

echo "[pki] done. fullchain at $OUT_DIR/fullchain.pem ; truststore at $OUT_DIR/truststore.p12"
