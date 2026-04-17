#!/bin/bash
# TEE-Judge Client Installer for Ubuntu (Intel SGX)
# Usage: curl -fsSL https://raw.githubusercontent.com/GonGe1018/tee-judge/main/install-client.sh | bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[TEE-Judge]${NC} $1"; }
warn()  { echo -e "${YELLOW}[TEE-Judge]${NC} $1"; }
error() { echo -e "${RED}[TEE-Judge]${NC} $1"; exit 1; }

# --- Pre-checks ---
info "TEE-Judge Client Installer"
echo ""

if [ "$(uname -s)" != "Linux" ]; then
    error "This installer only supports Linux."
fi

if [ "$(uname -m)" != "x86_64" ]; then
    error "This installer only supports x86_64 (Intel/AMD)."
fi

if ! command -v docker &>/dev/null; then
    warn "Docker not found. Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER"
    info "Docker installed. You may need to log out and back in for group changes."
fi

# --- Check SGX ---
if [ -e /dev/sgx_enclave ]; then
    info "SGX device found: /dev/sgx_enclave"
    SGX_AVAILABLE=true
else
    warn "SGX device not found (/dev/sgx_enclave)."
    warn "Running in mock mode (no hardware attestation)."
    SGX_AVAILABLE=false
fi

# --- Pull or build image ---
IMAGE="ghcr.io/gonge1018/tee-judge-client:latest"
info "Pulling TEE-Judge Client image..."

if ! docker pull "$IMAGE" 2>/dev/null; then
    warn "Pre-built image not available. Building locally..."
    TMPDIR=$(mktemp -d)
    git clone --depth 1 https://github.com/GonGe1018/tee-judge.git "$TMPDIR/tee-judge"
    docker build -t tee-judge-client -f "$TMPDIR/tee-judge/Dockerfile.client" "$TMPDIR/tee-judge"
    rm -rf "$TMPDIR"
    IMAGE="tee-judge-client"
fi

# --- Create run script ---
INSTALL_DIR="$HOME/.tee-judge"
mkdir -p "$INSTALL_DIR"

if [ "$SGX_AVAILABLE" = true ]; then
    cat > "$INSTALL_DIR/run.sh" << 'SCRIPT'
#!/bin/bash
# TEE-Judge Client Runner (SGX Mode)
SERVER="${TEE_JUDGE_SERVER:-http://localhost:8000}"
echo "[TEE-Judge] Server: $SERVER"
echo "[TEE-Judge] Mode: SGX Hardware"

docker run --rm -it \
    --device /dev/sgx_enclave:/dev/sgx_enclave \
    --device /dev/sgx_provision:/dev/sgx_provision \
    -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
    -e TEE_JUDGE_SERVER="$SERVER" \
    IMAGE_PLACEHOLDER "$@"
SCRIPT
    sed -i "s|IMAGE_PLACEHOLDER|$IMAGE|g" "$INSTALL_DIR/run.sh"
else
    cat > "$INSTALL_DIR/run.sh" << 'SCRIPT'
#!/bin/bash
# TEE-Judge Client Runner (Mock Mode)
SERVER="${TEE_JUDGE_SERVER:-http://localhost:8000}"
echo "[TEE-Judge] Server: $SERVER"
echo "[TEE-Judge] Mode: Mock (no SGX)"

docker run --rm -it \
    -e TEE_JUDGE_SERVER="$SERVER" \
    IMAGE_PLACEHOLDER "$@"
SCRIPT
    sed -i "s|IMAGE_PLACEHOLDER|$IMAGE|g" "$INSTALL_DIR/run.sh"
fi

chmod +x "$INSTALL_DIR/run.sh"

# --- Create symlink ---
sudo ln -sf "$INSTALL_DIR/run.sh" /usr/local/bin/tee-judge

echo ""
info "Installation complete!"
echo ""
echo "  Usage:"
echo "    tee-judge                          # Connect to default server (localhost:8000)"
echo "    TEE_JUDGE_SERVER=http://IP:8000 tee-judge  # Connect to remote server"
echo ""
if [ "$SGX_AVAILABLE" = true ]; then
    info "SGX hardware detected. Running in SGX mode with DCAP attestation."
else
    warn "No SGX hardware. Running in mock mode."
fi
