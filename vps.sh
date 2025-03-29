#!/bin/bash
# =============================================================================
# Secure VPS Setup Script - Debian 12
# WireGuard VPN + System Hardening + Monitoring
# =============================================================================
# Terminal colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
# Configuration Variables
CONFIG_FILE="vpn_setup.conf"
LOG_FILE="/var/log/secure_vpn_setup.log"
WG_PORT=51820
WG_NETWORK="10.10.10.0/24"
WG_SERVER_IP="10.10.10.1/24"
SSH_PORT=22
INSTALL_NETDATA=true
ENABLE_SSL=true
# Logging functions
log() { echo -e "${GREEN}[+] $1${NC}"; echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"; }
error() { echo -e "${RED}[-] $1${NC}"; echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $1" >> "$LOG_FILE"; exit 1; }
warning() { echo -e "${YELLOW}[!] $1${NC}"; echo "$(date '+%Y-%m-%d %H:%M:%S') - WARNING: $1" >> "$LOG_FILE"; }
section() { echo -e "\n${BLUE}========= $1 =========${NC}\n"; echo "$(date '+%Y-%m-%d %H:%M:%S') - SECTION: $1" >> "$LOG_FILE"; }
# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}
# Load configuration if exists
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        log "Loading configuration from $CONFIG_FILE"
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
}
# Create log file
init_log() {
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    log "Starting VPS hardening and WireGuard setup..."
    log "Logging to $LOG_FILE"
}
# Install required packages
install_packages() {
    section "Installing Required Packages"
    log "Updating system packages..."
    apt update || error "Failed to update package database"
    apt upgrade -y || warning "Some packages could not be upgraded"
    
    log "Installing required packages..."
    apt install -y sudo curl wget gnupg2 software-properties-common apt-transport-https \
        ca-certificates lsb-release unattended-upgrades fail2ban ufw git \
        python3 python3-pip python3-venv qrencode wireguard nginx \
        certbot python3-certbot-nginx zlib1g-dev uuid-dev libuv1-dev \
        liblz4-dev libssl-dev libmnl-dev || error "Failed to install required packages"
    
    log "All required packages have been installed"
}
# Configure unattended upgrades
setup_unattended_upgrades() {
    section "Setting Up Automatic Updates"
    
    log "Configuring unattended-upgrades"
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
    log "Unattended upgrades configured successfully"
}
# Harden system with sysctl settings
harden_sysctl() {
    section "Hardening System Network Settings"
    
    log "Configuring secure sysctl parameters"
    cat > /etc/sysctl.d/99-security.conf << EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Enable IP forwarding (required for WireGuard)
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Increase system file descriptor limit
fs.file-max = 65535
# Protect Against TCP Time-Wait
net.ipv4.tcp_rfc1337 = 1
# Decrease the time default value for connections
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
EOF
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-security.conf || warning "Some sysctl parameters might not have been applied"
    
    log "System network hardening completed"
}
# Secure SSH configuration
secure_ssh() {
    section "Securing SSH Configuration"
    
    # Backup existing config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Generate strong SSH keys if needed
    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
        log "Generating ED25519 SSH host key"
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    fi
    
    log "Applying secure SSH configuration"
    cat > /etc/ssh/sshd_config << EOF
Port ${SSH_PORT}
AddressFamily inet
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
MaxAuthTries 3
MaxSessions 5
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
Subsystem sftp  /usr/lib/openssh/sftp-server
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF
    # Determine the sudo user
    SUDO_USER=$(logname 2>/dev/null || echo "$SUDO_USER")
    if [ -z "$SUDO_USER" ] || [ "$SUDO_USER" = "root" ]; then
        warning "Could not determine sudo user, using 'admin'"
        SUDO_USER="admin"
    fi
    log "Using sudo user: $SUDO_USER"
    
    # Add the user to the sshd_config
    echo "AllowUsers $SUDO_USER" >> /etc/ssh/sshd_config
    
    # Create sudo user if it doesn't exist
    if ! id "$SUDO_USER" &>/dev/null; then
        log "Creating user: $SUDO_USER"
        useradd -m -s /bin/bash "$SUDO_USER"
        
        # Generate a strong random password
        USER_PASSWORD=$(tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' </dev/urandom | head -c 16)
        echo "$SUDO_USER:$USER_PASSWORD" | chpasswd
        
        # Add user to sudo group
        usermod -aG sudo "$SUDO_USER"
        
        # Set up SSH key authentication for the new user
        mkdir -p "/home/$SUDO_USER/.ssh"
        chmod 700 "/home/$SUDO_USER/.ssh"
        touch "/home/$SUDO_USER/.ssh/authorized_keys"
        chmod 600 "/home/$SUDO_USER/.ssh/authorized_keys"
        chown -R "$SUDO_USER:$SUDO_USER" "/home/$SUDO_USER/.ssh"
        
        log "Created user '$SUDO_USER' with password: $USER_PASSWORD"
        log "IMPORTANT: Add your SSH public key to: /home/$SUDO_USER/.ssh/authorized_keys"
    fi
    
    # Restart SSH service
    systemctl restart sshd || error "Failed to restart SSH service"
    
    log "SSH secured successfully"
}
# Configure firewall
setup_firewall() {
    section "Configuring Firewall"
    
    log "Setting up UFW firewall"
    ufw default deny incoming
    ufw default allow outgoing
    
    # Add firewall rules
    ufw allow "$SSH_PORT"/tcp comment 'SSH'
    ufw allow "$WG_PORT"/udp comment 'WireGuard VPN'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw allow 10086/tcp comment 'WGDashboard'
    
    if [ "$INSTALL_NETDATA" = true ]; then
        ufw allow 19999/tcp comment 'Netdata'
    fi
    
    # Enable UFW
    log "Enabling UFW firewall"
    echo "y" | ufw enable
    
    # Configure Fail2Ban
    log "Setting up Fail2Ban"
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    cat > /etc/fail2ban/jail.d/custom.conf << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = iptables-multiport
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log "Firewall and Fail2Ban configured successfully"
}
# Install WireGuard
install_wireguard() {
    section "Installing WireGuard VPN"
    
    # Create WireGuard directory
    mkdir -p /etc/wireguard/clients
    chmod 700 /etc/wireguard
    
    # Generate WireGuard keys
    log "Generating WireGuard server keys"
    wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
    chmod 600 /etc/wireguard/server.key
    
    SERVER_PRIVATE_KEY=$(cat /etc/wireguard/server.key)
    SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server.pub)
    
    # Determine public IP if not set
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP=$(curl -s https://api.ipify.org)
        if [ -z "$PUBLIC_IP" ]; then
            warning "Could not determine public IP automatically"
            read -rp "Please enter your server's public IP address: " PUBLIC_IP
            if [ -z "$PUBLIC_IP" ]; then
                error "Public IP is required for VPN setup"
            fi
        fi
        log "Using public IP: $PUBLIC_IP"
    fi
    
    # Determine default interface
    DEFAULT_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    if [ -z "$DEFAULT_INTERFACE" ]; then
        warning "Could not determine default interface, using eth0"
        DEFAULT_INTERFACE="eth0"
    fi
    log "Using $DEFAULT_INTERFACE as the external interface"
    
    # Create WireGuard server config
    log "Creating WireGuard server configuration"
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = $WG_SERVER_IP
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE_KEY
SaveConfig = true
# NAT forwarding
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
EOF
    # Generate first client configuration
    log "Creating first client configuration"
    
    # Generate client keys
    wg genkey | tee /etc/wireguard/clients/client1.key | wg pubkey > /etc/wireguard/clients/client1.pub
    chmod 600 /etc/wireguard/clients/client1.key
    
    CLIENT1_PRIVATE_KEY=$(cat /etc/wireguard/clients/client1.key)
    CLIENT1_PUBLIC_KEY=$(cat /etc/wireguard/clients/client1.pub)
    
    # Client IP is the second address in our subnet
    CLIENT1_IP="10.10.10.2/32"
    
    # Create client configuration
    cat > /etc/wireguard/clients/client1.conf << EOF
[Interface]
PrivateKey = $CLIENT1_PRIVATE_KEY
Address = ${CLIENT1_IP%/*}/24
DNS = 1.1.1.1, 8.8.8.8
[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $PUBLIC_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    # Add client to server configuration
    cat >> /etc/wireguard/wg0.conf << EOF
[Peer]
PublicKey = $CLIENT1_PUBLIC_KEY
AllowedIPs = $CLIENT1_IP
EOF
    # Enable and start WireGuard
    log "Enabling and starting WireGuard service"
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    # Generate QR code for client configuration
    qrencode -t ansiutf8 < /etc/wireguard/clients/client1.conf > /etc/wireguard/clients/client1_qr.txt
    
    log "WireGuard VPN installation completed"
}
# Install WGDashboard
install_wgdashboard() {
    section "Installing WireGuard Dashboard"
    
    # Remove any previous installation
    rm -rf /opt/WGDashboard
    
    # Clone the repository
    cd /opt || error "Failed to change directory to /opt"
    git clone https://github.com/donaldzou/WGDashboard.git
    cd WGDashboard/src || error "Failed to change directory to WGDashboard/src"
    
    # Create required directories
    mkdir -p log
    mkdir -p db
    
    # Set permissions
    chmod +x wgd.sh
    
    # Run installation
    ./wgd.sh install
    
    # Create systemd service
    cat > /etc/systemd/system/wgdashboard.service << EOF
[Unit]
Description=WireGuard Dashboard
After=network.target
Wants=wg-quick@wg0.service
[Service]
Type=simple
WorkingDirectory=/opt/WGDashboard/src
ExecStart=/bin/bash -c '/opt/WGDashboard/src/wgd.sh start && while true; do sleep 3600; done'
Restart=on-failure
KillMode=process
[Install]
WantedBy=multi-user.target
EOF
    # Enable and start service
    systemctl daemon-reload
    systemctl enable wgdashboard
    systemctl start wgdashboard
    
    # Configure NGINX if SSL is enabled
    if [ "$ENABLE_SSL" = true ] && [ -n "$DASHBOARD_HOST" ]; then
        log "Setting up NGINX with SSL for WGDashboard"
        
        cat > /etc/nginx/sites-available/wgdashboard << EOF
server {
    listen 80;
    server_name $DASHBOARD_HOST;
    
    location / {
        proxy_pass http://127.0.0.1:10086;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        
        # Security headers
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header X-Frame-Options SAMEORIGIN;
        add_header Referrer-Policy strict-origin-when-cross-origin;
    }
}
EOF
        
        # Enable site
        ln -sf /etc/nginx/sites-available/wgdashboard /etc/nginx/sites-enabled/
        
        # Test and restart NGINX
        nginx -t
        systemctl restart nginx
        
        # Get SSL certificate
        log "Getting SSL certificate from Let's Encrypt"
        certbot --nginx -d "$DASHBOARD_HOST" --non-interactive --agree-tos --email "admin@$DASHBOARD_HOST" || warning "SSL certificate setup failed"
    fi
    
    log "WGDashboard installation completed"
}
# Install Netdata monitoring
install_netdata() {
    section "Installing Netdata Monitoring"
    
    if [ "$INSTALL_NETDATA" != true ]; then
        log "Skipping Netdata installation"
        return
    fi
    
    log "Installing Netdata dependencies"
    apt install -y zlib1g-dev uuid-dev libuv1-dev liblz4-dev libssl-dev libmnl-dev
    
    log "Installing Netdata in local-only mode"
    bash <(curl -Ss https://get.netdata.cloud/kickstart.sh) \
        --stable-channel \
        --disable-telemetry \
        --disable-cloud \
        --dont-wait \
        --no-updates || error "Failed to install Netdata"
    
    # Configure Netdata
    log "Configuring Netdata"
    if [ -f "/etc/netdata/netdata.conf" ]; then
        cp /etc/netdata/netdata.conf /etc/netdata/netdata.conf.bak
        
        # Proper web interface configuration
        cat > /etc/netdata/netdata.conf << EOF
[global]
    run as user = netdata
    web files owner = root
    web files group = root
[web]
    default port = 19999
    allow connections from = localhost *
EOF
    fi
    
    # Disable cloud connection
    if [ -f "/etc/netdata/cloud.conf" ]; then
        log "Disabling Netdata cloud connection"
        cp /etc/netdata/cloud.conf /etc/netdata/cloud.conf.bak
        cat > /etc/netdata/cloud.conf << EOF
[global]
    enabled = no
    cloud base url = 
EOF
    fi
    
    # Configure NGINX for Netdata if SSL is enabled
    if [ "$ENABLE_SSL" = true ] && [ -n "$NETDATA_HOST" ]; then
        log "Setting up NGINX with SSL for Netdata"
        
        cat > /etc/nginx/sites-available/netdata << EOF
server {
    listen 80;
    server_name $NETDATA_HOST;
    
    access_log /var/log/nginx/netdata.access.log;
    error_log /var/log/nginx/netdata.error.log;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Frame-Options SAMEORIGIN;
    add_header Referrer-Policy strict-origin-when-cross-origin;
    
    location / {
        proxy_pass http://127.0.0.1:19999;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_cache_bypass \$http_upgrade;
        proxy_buffering off;
        
        # Timeout settings
        proxy_connect_timeout 300s;
        proxy_read_timeout 300s;
    }
}
EOF
        
        # Enable site
        ln -sf /etc/nginx/sites-available/netdata /etc/nginx/sites-enabled/
        
        # Test and restart NGINX
        nginx -t
        systemctl restart nginx
        
        # Get SSL certificate
        log "Getting SSL certificate from Let's Encrypt for Netdata"
        certbot --nginx -d "$NETDATA_HOST" --non-interactive --agree-tos --email "admin@$NETDATA_HOST" || warning "SSL certificate setup for Netdata failed"
        
        # Add strong SSL configuration
        if ! grep -q "ssl_protocols" /etc/nginx/sites-available/netdata; then
            # Add strong SSL configuration to the server block
            sed -i '/server_name/a \
    # SSL configuration\
    ssl_protocols TLSv1.2 TLSv1.3;\
    ssl_prefer_server_ciphers on;\
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;\
    ssl_session_timeout 1d;\
    ssl_session_cache shared:SSL:10m;\
    ssl_session_tickets off;\
    ssl_stapling on;\
    ssl_stapling_verify on;\
    resolver 1.1.1.1 8.8.8.8 valid=300s;\
    resolver_timeout 5s;\
    # Add HSTS header with a 1 year max-age\
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' /etc/nginx/sites-available/netdata
            
            # Test and reload nginx
            nginx -t && systemctl reload nginx
        fi
    fi
    
    # Restart Netdata
    systemctl restart netdata
    
    log "Netdata installation completed"
}
# Create credentials file
create_credentials() {
    section "Creating Credentials File"
    
    log "Saving credentials and setup information"
    mkdir -p /root/vpn_credentials
    cat > /root/vpn_credentials/vpn_info.txt << EOF
========================================================
VPS SECURITY & WIREGUARD SETUP INFORMATION
========================================================
Setup Date: $(date)
Public IP: $PUBLIC_IP
--------------------------------------------------------
SSH ACCESS
--------------------------------------------------------
SSH Port: $SSH_PORT
Username: $SUDO_USER
$(if [ -n "$USER_PASSWORD" ]; then echo "Initial Password: $USER_PASSWORD (CHANGE IMMEDIATELY!)"; fi)
--------------------------------------------------------
WIREGUARD SERVER
--------------------------------------------------------
Server Public Key: $SERVER_PUBLIC_KEY
Server IP: ${WG_SERVER_IP%/*}
Server Port: $WG_PORT
Listening Interface: wg0
--------------------------------------------------------
WIREGUARD CLIENT 1
--------------------------------------------------------
Client Public Key: $CLIENT1_PUBLIC_KEY
Client IP: ${CLIENT1_IP%/*}
Configuration File: /etc/wireguard/clients/client1.conf
QR Code: /etc/wireguard/clients/client1_qr.txt
--------------------------------------------------------
WGDASHBOARD ACCESS
--------------------------------------------------------
$(if [ "$ENABLE_SSL" = true ] && [ -n "$DASHBOARD_HOST" ]; then
    echo "URL: https://$DASHBOARD_HOST"
else
    echo "URL: http://$PUBLIC_IP:10086"
fi)
Default Username: admin
Default Password: admin (CHANGE IMMEDIATELY!)
$(if [ "$INSTALL_NETDATA" = true ]; then
echo "--------------------------------------------------------
NETDATA MONITORING
--------------------------------------------------------"
if [ "$ENABLE_SSL" = true ] && [ -n "$NETDATA_HOST" ]; then
    echo "URL: https://$NETDATA_HOST"
else
    echo "URL: http://$PUBLIC_IP:19999"
fi
fi)
--------------------------------------------------------
SECURITY INFORMATION
--------------------------------------------------------
Firewalls: UFW enabled, Fail2Ban active
SSH root login: Disabled
Password authentication: Disabled
Automatic updates: Enabled
========================================================
IMPORTANT: Store this information securely!
========================================================
EOF
    # Secure the credentials file
    chmod 600 /root/vpn_credentials/vpn_info.txt
    
    log "Credentials saved to /root/vpn_credentials/vpn_info.txt"
}
# Display final message
show_completion() {
    cat << EOF
========================================================
SETUP COMPLETED SUCCESSFULLY!
========================================================
Your Debian VPS has been secured and configured with:
- Comprehensive security hardening
- WireGuard VPN server
- WGDashboard for client management
$(if [ "$INSTALL_NETDATA" = true ]; then echo "- Netdata system monitoring"; fi)
All credentials and setup information have been saved to:
/root/vpn_credentials/vpn_info.txt
WireGuard client configuration can be found at:
/etc/wireguard/clients/client1.conf
You can access WGDashboard at:
$(if [ "$ENABLE_SSL" = true ] && [ -n "$DASHBOARD_HOST" ]; then
    echo "https://$DASHBOARD_HOST"
else
    echo "http://$PUBLIC_IP:10086"
fi)
$(if [ "$INSTALL_NETDATA" = true ]; then
echo "You can access Netdata monitoring at:"
if [ "$ENABLE_SSL" = true ] && [ -n "$NETDATA_HOST" ]; then
    echo "https://$NETDATA_HOST"
else
    echo "http://$PUBLIC_IP:19999"
fi
fi)
IMPORTANT SECURITY NOTES:
- Change the default WGDashboard password immediately
- Store the client configuration securely
- Keep the credentials file in a safe place
Thank you for using this script!
========================================================
EOF
}
# Get domain names
get_domains() {
    section "Domain Configuration"
    
    if [ "$ENABLE_SSL" = true ] && [ -z "$DASHBOARD_HOST" ]; then
        read -rp "Enter domain name for WGDashboard (leave empty to skip SSL): " DASHBOARD_HOST
        if [ -n "$DASHBOARD_HOST" ]; then
            log "Using domain for WGDashboard: $DASHBOARD_HOST"
            if [ "$INSTALL_NETDATA" = true ]; then
                read -rp "Enter domain name for Netdata (leave empty to use default subdomain): " NETDATA_HOST
                if [ -z "$NETDATA_HOST" ]; then
                    NETDATA_HOST="netdata.$DASHBOARD_HOST"
                fi
                log "Using domain for Netdata: $NETDATA_HOST"
            fi
        else
            ENABLE_SSL=false
            warning "SSL setup skipped - no domain provided"
        fi
    fi
}
# Main execution
main() {
    check_root
    init_log
    load_config
    get_domains
    install_packages
    setup_unattended_upgrades
    harden_sysctl
    secure_ssh
    setup_firewall
    install_wireguard
    install_wgdashboard
    
    if [ "$INSTALL_NETDATA" = true ]; then
        install_netdata
    fi
    
    create_credentials
    show_completion
    log "Installation completed successfully"
}
# Run the script
main
