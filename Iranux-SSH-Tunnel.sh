#!/bin/bash

# ==============================================================================
# Iranux Ultimate Setup: PORT 22 EDITION (Stability First)
# Domain: iranux.nz
# Features: Node.js 22, BadVPN (Compiled), Telegram Bot, SSH Port 22
# Status: GUARANTEED STABLE
# ==============================================================================

# Exit on critical errors
set -e

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# --- CONSTANTS ---
APP_DIR="/opt/iranux-tunnel"
SECRET_PATH="/ssh-wss-tunnel"
CONFIG_FILE="${APP_DIR}/config.env"
BADVPN_PORT="7300"
FIXED_SSH_PORT=22  # <-- FIXED TO 22 TO PREVENT ERRORS

# ------------------------------------------------------------------------------
# PHASE 0: INITIAL CHECKS & INPUTS (INTERACTIVE)
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[X] Error: Run as root.${RESET}"
   exit 1
fi

clear
echo -e "${CYAN}===================================================${RESET}"
echo -e "${CYAN}      IRANUX INSTALLER (SSH PORT 22 EDITION)       ${RESET}"
echo -e "${CYAN}===================================================${RESET}"

# 1. Get Domain (Always Ask)
echo -e "${YELLOW}[?] Please enter your Domain (e.g. sub.iranux.nz):${RESET}"
read -p ">> " DOMAIN

while [[ -z "$DOMAIN" ]]; do
    echo -e "${RED}[!] Domain cannot be empty.${RESET}"
    read -p ">> " DOMAIN
done

# 2. Get Bot Token (Ask if not set in script)
BOT_TOKEN="" 

if [[ -z "$BOT_TOKEN" || "$BOT_TOKEN" == "YOUR_TELEGRAM_BOT_TOKEN" ]]; then
    echo -e "\n${YELLOW}[?] Enter Telegram Bot Token:${RESET}"
    read -p ">> " BOT_TOKEN
fi

# 3. Get Admin ID (Ask if not set in script)
ADMIN_ID=""

if [[ -z "$ADMIN_ID" || "$ADMIN_ID" == "YOUR_TELEGRAM_USER_ID" ]]; then
    echo -e "\n${YELLOW}[?] Enter Your Numeric Admin ID:${RESET}"
    read -p ">> " ADMIN_ID
fi

echo -e "\n${GREEN}[+] Config Loaded:${RESET}"
echo -e "    Domain: $DOMAIN"
echo -e "    SSH   : Port 22 (Fixed)"
echo -e "${CYAN}Starting Installation in 3 seconds...${RESET}"
sleep 3

# ------------------------------------------------------------------------------
# PHASE 1: NUCLEAR CLEAN (PREPARATION)
# ------------------------------------------------------------------------------
echo -e "\n${RED}>>> INITIATING SYSTEM PREP...${RESET}"

# Install Essential Tools
echo -e "${YELLOW}[!] Installing Dependencies...${RESET}"
apt-get update -yqq > /dev/null
apt-get install -yqq psmisc lsof net-tools curl wget ufw openssl coreutils jq git whiptail cmake make gcc g++ > /dev/null

# Kill Conflicts
echo -e "${YELLOW}[!] Clearing Ports...${RESET}"
fuser -k 443/tcp > /dev/null 2>&1 || true
fuser -k 80/tcp > /dev/null 2>&1 || true
fuser -k ${BADVPN_PORT}/udp > /dev/null 2>&1 || true
systemctl stop nginx apache2 caddy badvpn badvpn-udpgw > /dev/null 2>&1 || true
systemctl disable nginx apache2 caddy badvpn badvpn-udpgw > /dev/null 2>&1 || true

# System Upgrade
echo -e "${CYAN}[i] Updating System...${RESET}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -yqq
apt-get upgrade -yqq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

# ------------------------------------------------------------------------------
# PHASE 2: NODE.JS & KERNEL OPTIMIZATION
# ------------------------------------------------------------------------------
echo -e "${CYAN}[i] Installing Node.js 22...${RESET}"
curl -fsSL https://deb.nodesource.com/setup_22.x | bash - > /dev/null 2>&1
apt-get install -yqq nodejs

echo -e "${CYAN}[i] Enabling TCP BBR...${RESET}"
if ! grep -q "tcp_bbr" /etc/modules-load.d/modules.conf 2>/dev/null; then
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
fi
sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p > /dev/null

# ------------------------------------------------------------------------------
# PHASE 3: SSH CONFIGURATION (FORCED TO 22)
# ------------------------------------------------------------------------------
echo -e "${CYAN}[i] Configuring Security...${RESET}"

# Force SSH to Port 22
sed -i 's/^#\?Port .*/Port 22/' /etc/ssh/sshd_config
# If Port line doesn't exist, append it
grep -q "^Port 22" /etc/ssh/sshd_config || echo "Port 22" >> /etc/ssh/sshd_config

# Restart SSH
systemctl restart ssh 2>/dev/null || systemctl restart sshd

# Firewall
ufw --force reset > /dev/null
ufw allow 22/tcp
ufw allow 443/tcp
ufw allow ${BADVPN_PORT}/udp
ufw --force enable > /dev/null

# ------------------------------------------------------------------------------
# PHASE 4: BADVPN (UDPGW) - COMPILE FROM SOURCE
# ------------------------------------------------------------------------------
echo -e "${CYAN}[i] Compiling BadVPN (UDPGW)...${RESET}"

rm -rf /tmp/badvpn
rm -f /usr/bin/badvpn-udpgw

git clone https://github.com/ambrop72/badvpn.git /tmp/badvpn > /dev/null 2>&1
mkdir -p /tmp/badvpn/build
cd /tmp/badvpn/build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
make install > /dev/null 2>&1

if [ -f /usr/local/bin/badvpn-udpgw ]; then
    cp /usr/local/bin/badvpn-udpgw /usr/bin/
elif [ -f ./udpgw/badvpn-udpgw ]; then
    cp ./udpgw/badvpn-udpgw /usr/bin/
fi

chmod +x /usr/bin/badvpn-udpgw
cd /root
rm -rf /tmp/badvpn

cat << EOF > /etc/systemd/system/badvpn.service
[Unit]
Description=BadVPN UDPGW
After=network.target
[Service]
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:${BADVPN_PORT} --max-clients 1000
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable badvpn --now
echo -e "${GREEN}[+] BadVPN Running on port ${BADVPN_PORT}${RESET}"

# ------------------------------------------------------------------------------
# PHASE 5: PROXY SETUP
# ------------------------------------------------------------------------------
mkdir -p ${APP_DIR}/ssl
mkdir -p ${APP_DIR}/logs

# Save Config
echo "DOMAIN=${DOMAIN}" > ${CONFIG_FILE}
echo "SECRET_PATH=${SECRET_PATH}" >> ${CONFIG_FILE}
echo "SSH_PORT=${FIXED_SSH_PORT}" >> ${CONFIG_FILE}
echo "BADVPN_PORT=${BADVPN_PORT}" >> ${CONFIG_FILE}

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout ${APP_DIR}/ssl/server.key \
  -out ${APP_DIR}/ssl/server.crt \
  -subj "/C=NZ/O=Iranux/CN=${DOMAIN}" 2>/dev/null

cat << EOF > ${APP_DIR}/server.js
const https = require('https');
const fs = require('fs');
const net = require('net');
const CONFIG = { LISTEN_PORT: 443, SSH_PORT: ${FIXED_SSH_PORT}, SSH_HOST: '127.0.0.1', SECRET_PATH: '${SECRET_PATH}' };
const serverOptions = { key: fs.readFileSync('${APP_DIR}/ssl/server.key'), cert: fs.readFileSync('${APP_DIR}/ssl/server.crt') };
const server = https.createServer(serverOptions, (req, res) => { res.writeHead(404); res.end('Not Found'); });
server.on('upgrade', (req, socket, head) => {
    if (req.url !== CONFIG.SECRET_PATH) { socket.destroy(); return; }
    const sshSocket = net.createConnection(CONFIG.SSH_PORT, CONFIG.SSH_HOST);
    sshSocket.on('connect', () => {
        socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
        if (head && head.length > 0) sshSocket.write(head);
        socket.pipe(sshSocket); sshSocket.pipe(socket);
    });
    sshSocket.on('error', () => socket.destroy()); socket.on('error', () => sshSocket.destroy());
});
server.listen(CONFIG.LISTEN_PORT, '0.0.0.0');
EOF

# ------------------------------------------------------------------------------
# PHASE 6: TELEGRAM BOT
# ------------------------------------------------------------------------------
cat << EOF > ${APP_DIR}/bot.sh
#!/bin/bash
BOT_TOKEN="${BOT_TOKEN}"
ADMIN_ID="${ADMIN_ID}"
DOMAIN="${DOMAIN}"
SECRET_PATH="${SECRET_PATH}"
BADVPN="${BADVPN_PORT}"

send_msg() {
    curl -s -X POST "https://api.telegram.org/bot\$BOT_TOKEN/sendMessage" \
        -d "chat_id=\$ADMIN_ID" \
        -d "text=\$1" \
        -d "parse_mode=HTML" > /dev/null
}

send_msg "🚀 <b>Iranux Server Online!</b>%0A------------------%0AType /menu to start."

last_id=0
while true; do
    updates=\$(curl -s --max-time 50 "https://api.telegram.org/bot\$BOT_TOKEN/getUpdates?offset=\$((last_id + 1))&timeout=40")
    if [[ -z "\$updates" ]]; then sleep 5; continue; fi

    msg=\$(echo "\$updates" | jq -r '.result[-1].message.text // empty')
    update_id=\$(echo "\$updates" | jq -r '.result[-1].update_id // empty')
    chat_id=\$(echo "\$updates" | jq -r '.result[-1].message.chat.id // empty')

    if [[ "\$chat_id" == "\$ADMIN_ID" && -n "\$update_id" && "\$update_id" != "\$last_id" ]]; then
        last_id=\$update_id
        
        if [[ "\$msg" == "/menu" || "\$msg" == "/start" || "\$msg" == "/help" ]]; then
            help_text="🔰 <b>Iranux Manager</b>%0A%0A"
            help_text+="<b>Create User:</b>%0A<code>/add user pass days limit</code>%0A"
            help_text+="<i>Example: /add ali 1234 30 2</i>"
            send_msg "\$help_text"
        
        elif [[ "\$msg" == /add* ]]; then
            read -r cmd user pass days limit <<< "\$msg"
            if [[ -z "\$user" || -z "\$pass" ]]; then
                send_msg "❌ Error. Use: <code>/add user pass days limit</code>"
            else
                if id "\$user" &>/dev/null; then
                     send_msg "⚠️ User exists."
                else
                    useradd -m -s /usr/sbin/nologin "\$user"
                    echo "\$user:\$pass" | chpasswd
                    
                    if [[ -n "\$days" ]]; then
                        exp_date=\$(date -d "+\$days days" +%Y-%m-%d)
                        chage -E "\$exp_date" "\$user"
                    else exp_date="Never"; fi
                    
                    if [[ -n "\$limit" ]]; then
                        sed -i "/^\$user/d" /etc/security/limits.conf
                        echo "\$user hard maxlogins \$limit" >> /etc/security/limits.conf
                    else limit="Unlimited"; fi

                    payload="GET \$SECRET_PATH HTTP/1.1[crlf]Host: \$DOMAIN[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]"
                    
                    resp="✅ <b>Iranux Config Created</b>%0A"
                    resp+="--------------------------------%0A"
                    resp+="<b>Protocol:</b> <code>SSH-TLS-Payload</code>%0A%0A"
                    resp+="<b>Remarks:</b> <code>\$user</code>%0A"
                    resp+="<b>SSH Host:</b> <code>\$DOMAIN</code>%0A"
                    resp+="<b>SSH Port:</b> <code>443</code>%0A"
                    resp+="<b>UDPGW Port:</b> <code>\$BADVPN</code>%0A"
                    resp+="<b>SSH Username:</b> <code>\$user</code>%0A"
                    resp+="<b>SSH Password:</b> <code>\$pass</code>%0A"
                    resp+="<b>SNI:</b> <code>\$DOMAIN</code>%0A"
                    resp+="--------------------------------%0A"
                    resp+="👇 <b>Payload (Copy Exact):</b>%0A<code>\$payload</code>"
                    
                    send_msg "\$resp"
                fi
            fi
        fi
    fi
    sleep 1
done
EOF
chmod +x ${APP_DIR}/bot.sh

# ------------------------------------------------------------------------------
# PHASE 7: CLI MENU
# ------------------------------------------------------------------------------
cat << 'EOF' > /usr/local/bin/iranux
#!/bin/bash
CONFIG_FILE="/opt/iranux-tunnel/config.env"
if [ -f "$CONFIG_FILE" ]; then source "$CONFIG_FILE"; fi
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

while true; do
    clear
    echo -e "${CYAN}=== IRANUX TERMINAL MANAGER ===${NC}"
    echo -e " 1) Create User (App Format)"
    echo -e " 2) Delete User"
    echo -e " 3) Show Online Users"
    echo -e " 0) Exit"
    echo -e "-------------------------------"
    read -p " Select: " choice
    case $choice in
        1)
            read -p "Username: " u_name
            read -p "Password: " u_pass
            useradd -m -s /usr/sbin/nologin "$u_name"
            echo "$u_name:$u_pass" | chpasswd
            
            payload="GET ${SECRET_PATH} HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]"
            
            echo -e "\n${GREEN}=== HTTP CUSTOM CONFIG ===${NC}"
            echo -e "Protocol    : SSH-TLS-Payload"
            echo -e "Remarks     : ${u_name}"
            echo -e "SSH Host    : ${DOMAIN}"
            echo -e "SSH Port    : 443"
            echo -e "UDPGW Port  : ${BADVPN_PORT}"
            echo -e "SSH Username: ${u_name}"
            echo -e "SSH Password: ${u_pass}"
            echo -e "SNI         : ${DOMAIN}"
            echo -e "---------------------------------"
            echo -e "PAYLOAD:"
            echo -e "${payload}"
            echo -e "---------------------------------"
            read -p "Press Enter..."
            ;;
        2)
            read -p "Username to DELETE: " u_del
            if id "$u_del" &>/dev/null; then
                userdel -r "$u_del"
                sed -i "/^$u_del/d" /etc/security/limits.conf
                echo -e "${RED}User deleted.${NC}"
            else echo "User not found."; fi
            read -p "Press Enter..."
            ;;
        3)
            echo -e "${GREEN}Users:${NC}"
            awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd
            read -p "Press Enter..."
            ;;
        0) exit 0 ;;
        *) echo "Invalid";;
    esac
done
EOF
chmod +x /usr/local/bin/iranux

# ------------------------------------------------------------------------------
# PHASE 8: FINALIZING SERVICES
# ------------------------------------------------------------------------------
cat << EOF > /etc/systemd/system/iranux-tunnel.service
[Unit]
Description=Iranux Tunnel
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/node ${APP_DIR}/server.js
Restart=always
RestartSec=3
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/iranux-bot.service
[Unit]
Description=Iranux Bot
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
ExecStart=/bin/bash ${APP_DIR}/bot.sh
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable iranux-tunnel --now
systemctl enable iranux-bot --now

# Final Check
sleep 2
if lsof -i :443 > /dev/null; then PROXY_STATUS="${GREEN}ONLINE${RESET}"; else PROXY_STATUS="${RED}ERROR${RESET}"; fi
if lsof -i :7300 > /dev/null; then BADVPN_STATUS="${GREEN}ONLINE${RESET}"; else BADVPN_STATUS="${RED}ERROR${RESET}"; fi

# ------------------------------------------------------------------------------
# PHASE 9: FULL INSTALLATION REPORT
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}==========================================${RESET}"
echo -e "${GREEN}   IRANUX SYSTEM INSTALL COMPLETE         ${RESET}"
echo -e "${GREEN}==========================================${RESET}"
echo -e "   SSH Port   : ${YELLOW}${FIXED_SSH_PORT}${RESET}"
echo -e "   Proxy 443  : ${PROXY_STATUS}"
echo -e "   UDPGW 7300 : ${BADVPN_STATUS}"
echo -e "   Domain     : ${YELLOW}${DOMAIN}${RESET}"
echo -e "   Secret Path: ${YELLOW}${SECRET_PATH}${RESET}"
echo -e "------------------------------------------"
echo -e "   MANAGEMENT OPTIONS:"
echo -e "   1. Telegram: Send ${CYAN}/menu${RESET} to your bot"
echo -e "   2. Terminal: Type ${CYAN}iranux${RESET} to open menu"
echo -e "=========================================="