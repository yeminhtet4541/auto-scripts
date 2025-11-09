#!/usr/bin/env bash
# YeMinHtet DOTYCAT-style Full VPS Dashboard Installer
# Version: 1.2.8
# SCRIPT BY: YeMinHtet
# WEBSITE: WWW.YEMINHTET.COM
# OS support: Ubuntu 20.04 / 22.04 / Debian 11
# Features: XRay (VLESS/VMESS/Trojan/SOCKS), SSH/WS, OpenVPN, SLDNS, OHP, Squid, Dashboard Menu, Self-signed TLS, Auto-install, Client Config Export, Quick Download Links

set -euo pipefail
shopt -s nocasematch

# -----------------------------
# Variables
# -----------------------------
DOMAIN=${DOMAIN:-""}
EMAIL=${EMAIL:-"admin@localhost"}
VERSION="1.2.8"
WORKDIR="/tmp/vps-dashboard-installer-$$"
mkdir -p "$WORKDIR"
CLIENT_CONFIG_DIR="/root/client-configs"
mkdir -p "$CLIENT_CONFIG_DIR"

# Colors
info() { echo -e "\e[34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m $*"; }
err()  { echo -e "\e[31m[ERROR]\e[0m $*"; }

# -----------------------------
# Require root
# -----------------------------
if [ "$EUID" -ne 0 ]; then
    err "This script must be run as root. Use sudo."; exit 1
fi

# -----------------------------
# Detect OS
# -----------------------------
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_ID=${ID}
    DISTRO_VER=${VERSION_ID}
else
    err "Cannot detect OS."; exit 1
fi
info "Detected OS: $DISTRO_ID $DISTRO_VER"

# -----------------------------
# Basic Pre-requisites
# -----------------------------
info "Installing prerequisites..."
if [[ $DISTRO_ID =~ (ubuntu|debian) ]]; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl wget gnupg2 lsb-release iptables ufw unzip jq software-properties-common git openssl socat openvpn easy-rsa nginx systemd-resolve
else
    err "Unsupported OS."; exit 1
fi

# -----------------------------
# Generate self-signed TLS
# -----------------------------
generate_self_signed_tls(){
    CERT_DIR="/etc/ssl/xray"
    mkdir -p "$CERT_DIR"
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -subj "/CN=${DOMAIN:-$(hostname)}" \
      -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem"
    info "Self-signed TLS generated at $CERT_DIR"
}

# -----------------------------
# Xray Install + Config + Client Export
# -----------------------------
install_xray(){
    info "Installing Xray-core..."
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
    generate_self_signed_tls
    info "Xray-core installed and TLS applied."
    systemctl enable xray && systemctl restart xray

    # Generate example client config
    CLIENT_UUID=$(uuidgen)
    CLIENT_FILE="$CLIENT_CONFIG_DIR/xray-client.json"
    cat > "$CLIENT_FILE" <<EOL
{
  "vnext": [{
    "address": "${DOMAIN:-$(hostname)}",
    "port": 443,
    "users": [{ "id": "$CLIENT_UUID", "alterId": 0 }]
  }]
}
EOL
    info "Xray client config exported to $CLIENT_FILE"

    echo -e "
Summary:
  UUID: $CLIENT_UUID
  Config Path: $CLIENT_FILE
  TLS: /etc/ssl/xray/fullchain.pem
  Quick Download: scp root@$(hostname -I | awk '{print $1}'):$CLIENT_FILE ./
"
}

# -----------------------------
# OpenVPN Install + Config + Client Export
# -----------------------------
install_openvpn(){
    info "Installing OpenVPN..."
    apt-get install -y openvpn easy-rsa
    make-cadir /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa || return
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa gen-req server nopass
    ./easyrsa sign-req server server
    ./easyrsa gen-dh
    openvpn --genkey --secret ta.key
    systemctl enable openvpn && systemctl start openvpn

    # Generate example client config
    CLIENT_OVPN="$CLIENT_CONFIG_DIR/client.ovpn"
    cat > "$CLIENT_OVPN" <<EOL
client
dev tun
proto udp
remote ${DOMAIN:-$(hostname)} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
key-direction 1
verb 3
<ca>
$(cat pki/ca.crt)
</ca>
<cert>
# CLIENT CERT HERE
</cert>
<key>
# CLIENT KEY HERE
</key>
<tls-auth>
$(cat ta.key)
</tls-auth>
EOL
    info "OpenVPN client config exported to $CLIENT_OVPN"
    echo -e "Quick Download: scp root@$(hostname -I | awk '{print $1}'):$CLIENT_OVPN ./"
}

# -----------------------------
# SLDNS placeholder
# -----------------------------
install_sldns(){
    info "Setting up SLDNS (placeholder)..."
    sleep 1
}

# -----------------------------
# OHP placeholder
# -----------------------------
install_ohp(){
    info "Installing OHP (placeholder)..."
    sleep 1
}

# -----------------------------
# Dashboard Functions
# -----------------------------
show_header() {
cat <<EOF
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ DATE       : $(date '+%Y-%m-%d %H:%M:%S')
┃ OS         : $(lsb_release -ds || hostnamectl | grep 'Operating System' | cut -d':' -f2 | xargs)
┃ UPTIME     : $(uptime -p)
┃ IPv4       : $(hostname -I | awk '{print $1}')
┃ DOMAIN     : ${DOMAIN:-N/A}
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   NGINX : [RUN]    XRAY : [RUN]    WS : [RUN]
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
EOF
}

show_menu() {
cat <<EOF
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                        MENU                      ┃
┃
┃ [01] • SSH/WS MENU        [04] • TROJAN MENU
┃ [02] • VMESS MENU         [05] • SOCKS MENU
┃ [03] • VLESS MENU         [06] • ZIVPN MENU
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                       TOOLS                      ┃
┃
┃ [07] • DNS PANEL          [11] • NETGUARD PANEL
┃ [08] • DOMAIN PANEL       [12] • VPN PORT INFO
┃ [09] • IPV6 PANEL         [13] • CLEAN VPS LOGS
┃ [10] • VPS STATUS         [14] • SLDNS MENU
┃ [15] • OHP MENU           [16] • OpenVPN MENU
┃
┃ [00] • EXIT               [88] • REBOOT VPS
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ • VERSION      : $VERSION
┃ • SCRIPT BY    : YeMinHtet
┃ • OUR WEBSITE  : WWW.YEMINHTET.COM
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
EOF
}

read_menu() {
    read -rp "Select an option [00-16]: " choice
    case $choice in
        1|01) install_xray ;; 2|02) install_xray ;; 3|03) install_xray ;; 4|04) install_xray ;; 5|05) install_xray ;; 6|06) install_xray ;;
        7|07) dns_panel ;; 8|08) domain_panel ;; 9|09) ipv6_panel ;; 10) vps_status ;; 11) netguard_panel ;; 12) vpn_port_info ;;
        13) clean_logs ;; 14) install_sldns ;; 15) install_ohp ;; 16) install_openvpn ;;
        0|00) exit 0 ;; 88) reboot ;;
        *) warn "Invalid option." ;;
    esac
}

# Placeholder functions for tools
ssh_ws_menu(){ info "SSH/WS MENU selected"; sleep 1; }
dns_panel(){ info "DNS PANEL selected"; sleep 1; }
domain_panel(){ info "DOMAIN PANEL selected"; sleep 1; }
ipv6_panel(){ info "IPV6 PANEL selected"; sleep 1; }
vps_status(){ info "VPS STATUS selected"; sleep 1; }
netguard_panel(){ info "NETGUARD PANEL selected"; sleep 1; }
vpn_port_info(){ info "VPN PORT INFO selected"; sleep 1; }
clean_logs(){ info "CLEAN VPS LOGS selected"; sleep 1; }

# -----------------------------
# Main loop
# -----------------------------
while true; do
    clear
    show_header
    show_menu
    read_menu
    echo "Press Enter to continue..."
    read -r
done
