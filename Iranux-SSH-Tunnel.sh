#!/bin/bash

# ==============================================================================
# Iranux Ultimate Setup: PORT 22 EDITION (Stability First)
# Domain: iranux.nz
# Features: Node.js 22, BadVPN (Compiled), Telegram Bot, SSH Port 22
# Version: 1.4.0
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

# Enable password authentication
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config || echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Enable TCP forwarding for tunneling
sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config
grep -q "^AllowTcpForwarding yes" /etc/ssh/sshd_config || echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config

# Ensure UsePAM is on
sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
grep -q "^UsePAM yes" /etc/ssh/sshd_config || echo "UsePAM yes" >> /etc/ssh/sshd_config

# Ensure PAM limits module is loaded for SSH sessions
grep -q "pam_limits.so" /etc/pam.d/sshd || echo "session required pam_limits.so" >> /etc/pam.d/sshd

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

set +e
git clone https://github.com/ambrop72/badvpn.git /tmp/badvpn > /dev/null 2>&1
mkdir -p /tmp/badvpn/build
cd /tmp/badvpn/build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
make install > /dev/null 2>&1
set -e

if [ ! -f /usr/bin/badvpn-udpgw ]; then
    if [ -f /usr/local/bin/badvpn-udpgw ]; then
        cp /usr/local/bin/badvpn-udpgw /usr/bin/
    elif [ -f ./udpgw/badvpn-udpgw ]; then
        cp ./udpgw/badvpn-udpgw /usr/bin/
    else
        echo -e "${RED}[X] BadVPN compile failed! Continuing without UDPGW...${RESET}"
    fi
fi

if [ -f /usr/bin/badvpn-udpgw ]; then
    chmod +x /usr/bin/badvpn-udpgw
    echo -e "${GREEN}[+] BadVPN binary ready.${RESET}"
else
    echo -e "${RED}[!] BadVPN binary not found. Service will not start.${RESET}"
fi
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

echo -e "${CYAN}[i] Generating SSL Certificate for ${DOMAIN}...${RESET}"
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout ${APP_DIR}/ssl/server.key \
  -out ${APP_DIR}/ssl/server.crt \
  -subj "/C=NZ/O=Iranux/CN=${DOMAIN}" || { echo -e "${RED}[X] SSL certificate generation failed!${RESET}"; exit 1; }

if [[ -f "${APP_DIR}/ssl/server.crt" && -f "${APP_DIR}/ssl/server.key" ]]; then
    echo -e "${GREEN}[+] SSL Certificate generated successfully.${RESET}"
else
    echo -e "${RED}[X] SSL files missing after generation!${RESET}"
    exit 1
fi

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
exec >> /opt/iranux-tunnel/logs/bot.log 2>&1
BOT_TOKEN="${BOT_TOKEN}"
ADMIN_ID="${ADMIN_ID}"
DOMAIN="${DOMAIN}"
SECRET_PATH="${SECRET_PATH}"
BADVPN="${BADVPN_PORT}"

send_msg() {
    local text="\$1"
    local escaped=\$(printf '%s' "\$text" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' | tr -d '\n')
    curl -s -X POST "https://api.telegram.org/bot\$BOT_TOKEN/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{\"chat_id\":\"\$ADMIN_ID\",\"text\":\"\$escaped\",\"parse_mode\":\"HTML\"}" \
        >> /opt/iranux-tunnel/logs/bot.log 2>&1
}

# Validate bot token
test_resp=\$(curl -s "https://api.telegram.org/bot\$BOT_TOKEN/getMe")
if ! echo "\$test_resp" | grep -q '"ok":true'; then
    echo "[ERROR] Invalid BOT_TOKEN or Telegram unreachable. Response: \$test_resp"
    exit 1
fi
echo "[INFO] Bot token validated. Starting polling..."

send_msg "🚀 <b>Iranux Server Online!</b>\n------------------\nType /menu to start."

last_id=0
while true; do
    updates=\$(curl -s --max-time 50 "https://api.telegram.org/bot\$BOT_TOKEN/getUpdates?offset=\$((last_id + 1))&timeout=40")
    if [[ -z "\$updates" ]]; then sleep 5; continue; fi
    result_count=\$(echo "\$updates" | jq -r '.result | length')
    if [[ "\$result_count" == "0" ]]; then sleep 2; continue; fi

    msg=\$(echo "\$updates" | jq -r '.result[-1].message.text // empty')
    update_id=\$(echo "\$updates" | jq -r '.result[-1].update_id // empty')
    chat_id=\$(echo "\$updates" | jq -r '.result[-1].message.chat.id // empty')

    if [[ "\$chat_id" == "\$ADMIN_ID" && -n "\$update_id" && "\$update_id" != "\$last_id" ]]; then
        last_id=\$update_id
        
        if [[ "\$msg" == "/menu" || "\$msg" == "/start" || "\$msg" == "/help" ]]; then
            help_text="🔰 <b>Iranux Manager</b>\n\n"
            help_text+="<b>Commands:</b>\n"
            help_text+="<code>/add user pass [days] [limit]</code> — Create user\n"
            help_text+="<code>/del user</code> — Delete user\n"
            help_text+="<code>/list</code> — List all users\n"
            help_text+="<code>/status</code> — Server status\n"
            help_text+="<code>/info user</code> — User info\n\n"
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
                    if useradd -m -s /bin/false "\$user"; then
                        echo "\$user:\$pass" | chpasswd
                        
                        if [[ -n "\$days" ]]; then
                            exp_date=\$(date -d "+\$days days" +%Y-%m-%d)
                            chage -E "\$exp_date" "\$user"
                        else exp_date="Never"; fi
                        
                        if [[ -n "\$limit" ]]; then
                            sed -i "/^\$user[[:space:]]/d" /etc/security/limits.conf
                            echo "\$user soft maxlogins \$limit" >> /etc/security/limits.conf
                        else limit="Unlimited"; fi

                        payload="GET \$SECRET_PATH HTTP/1.1[crlf]Host: \$DOMAIN[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]"
                        
                        resp="✅ <b>Iranux Config Created</b>\n"
                        resp+="--------------------------------\n"
                        resp+="<b>Protocol:</b> <code>SSH-TLS-Payload</code>\n\n"
                        resp+="<b>Remarks:</b> <code>\$user</code>\n"
                        resp+="<b>SSH Host:</b> <code>\$DOMAIN</code>\n"
                        resp+="<b>SSH Port:</b> <code>443</code>\n"
                        resp+="<b>UDPGW Port:</b> <code>\$BADVPN</code>\n"
                        resp+="<b>SSH Username:</b> <code>\$user</code>\n"
                        resp+="<b>SSH Password:</b> <code>\$pass</code>\n"
                        resp+="<b>SNI:</b> <code>\$DOMAIN</code>\n"
                        resp+="--------------------------------\n"
                        resp+="👇 <b>Payload (Copy Exact):</b>\n<code>\$payload</code>"
                        
                        send_msg "\$resp"
                    else
                        send_msg "❌ System error creating user."
                    fi
                fi
            fi

        elif [[ "\$msg" == /del* ]]; then
            read -r cmd u_del <<< "\$msg"
            if [[ -z "\$u_del" ]]; then
                send_msg "❌ Usage: <code>/del username</code>"
            elif ! id "\$u_del" &>/dev/null; then
                send_msg "❌ User <code>\$u_del</code> not found."
            else
                userdel -r "\$u_del" 2>/dev/null
                sed -i "/^\$u_del[[:space:]]/d" /etc/security/limits.conf
                send_msg "✅ User <code>\$u_del</code> deleted successfully."
            fi

        elif [[ "\$msg" == "/list" ]]; then
            user_list=""
            while IFS=: read -r uname _ uid _; do
                if [[ "\$uid" -ge 1000 && "\$uname" != "nobody" ]]; then
                    u_exp=\$(chage -l "\$uname" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs || echo "Never")
                    u_lim=\$(grep "^\$uname soft maxlogins" /etc/security/limits.conf 2>/dev/null | awk '{print \$4}' || echo "Unlimited")
                    user_list+="\n• <code>\$uname</code> | Exp: \$u_exp | Logins: \$u_lim"
                fi
            done < /etc/passwd
            if [[ -z "\$user_list" ]]; then
                send_msg "📋 No users found."
            else
                send_msg "📋 <b>User List:</b>\$user_list"
            fi

        elif [[ "\$msg" == "/status" ]]; then
            PROXY_ST=\$(systemctl is-active iranux-tunnel 2>/dev/null || echo "inactive")
            BADVPN_ST=\$(systemctl is-active badvpn 2>/dev/null || echo "inactive")
            UPTIME=\$(uptime -p 2>/dev/null || echo "unknown")
            status_text="📊 <b>Server Status</b>\n"
            status_text+="Domain: <code>\$DOMAIN</code>\n"
            status_text+="SSH Port: <code>22</code>\n"
            status_text+="Proxy (443): <code>\$PROXY_ST</code>\n"
            status_text+="UDPGW (\$BADVPN): <code>\$BADVPN_ST</code>\n"
            status_text+="Uptime: <code>\$UPTIME</code>"
            send_msg "\$status_text"

        elif [[ "\$msg" == /info* ]]; then
            read -r cmd u_info <<< "\$msg"
            if [[ -z "\$u_info" ]]; then
                send_msg "❌ Usage: <code>/info username</code>"
            elif ! id "\$u_info" &>/dev/null; then
                send_msg "❌ User <code>\$u_info</code> not found."
            else
                u_exp=\$(chage -l "\$u_info" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs || echo "Never")
                u_lim=\$(grep "^\$u_info soft maxlogins" /etc/security/limits.conf 2>/dev/null | awk '{print \$4}' || echo "Unlimited")
                info_text="👤 <b>User Info: \$u_info</b>\n"
                info_text+="Expiry: <code>\$u_exp</code>\n"
                info_text+="Max Logins: <code>\$u_lim</code>"
                send_msg "\$info_text"
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

# JSON output helpers
json_success() {
    local cmd="$1"
    local data="$2"
    printf '{"status":"success","command":"%s","data":%s}\n' "$cmd" "$data"
}

json_error() {
    local cmd="$1"
    local code="$2"
    local msg="$3"
    printf '{"status":"error","command":"%s","code":%s,"message":"%s"}\n' "$cmd" "$code" "$msg"
    exit "$code"
}

has_json() {
    for arg in "$@"; do [[ "$arg" == "--json" ]] && return 0; done
    return 1
}

# --- Non-interactive argument mode ---
if [[ $# -gt 0 ]]; then
    case "$1" in
        /add|add)
            u_name="$2"
            u_pass="$3"
            u_days="$4"
            u_limit="$5"
            if [[ -z "$u_name" || -z "$u_pass" ]]; then
                has_json "$@" && json_error "add" 5 "Invalid parameter: username and password required" || \
                    echo -e "${RED}Usage: iranux /add <username> <password> [days] [maxlogins]${NC}"
                exit 5
            fi
            if id "$u_name" &>/dev/null; then
                has_json "$@" && json_error "add" 3 "User already exists" || \
                    echo -e "${RED}[!] User '$u_name' already exists.${NC}"
                exit 3
            fi
            if ! useradd -m -s /bin/false "$u_name"; then
                has_json "$@" && json_error "add" 6 "System error creating user" || \
                    echo -e "${RED}[!] System error: failed to create user '$u_name'.${NC}"
                exit 6
            fi
            echo "$u_name:$u_pass" | chpasswd
            if [[ -n "$u_days" ]]; then
                exp_date=$(date -d "+$u_days days" +%Y-%m-%d)
                chage -E "$exp_date" "$u_name"
            else
                exp_date="Never"
            fi
            if [[ -n "$u_limit" ]]; then
                sed -i "/^$u_name/d" /etc/security/limits.conf
                echo "$u_name soft maxlogins $u_limit" >> /etc/security/limits.conf
            else
                u_limit="Unlimited"
            fi
            payload="GET ${SECRET_PATH} HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]"
            if has_json "$@"; then
                data=$(printf '{"username":"%s","password":"%s","expiry":"%s","max_logins":"%s","ssh_host":"%s","ssh_port":443,"udpgw_port":%s,"sni":"%s","protocol":"SSH-TLS-Payload","payload":"%s"}' \
                    "$u_name" "$u_pass" "$exp_date" "$u_limit" "$DOMAIN" "$BADVPN_PORT" "$DOMAIN" "$payload")
                json_success "add" "$data"
            else
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
                echo -e "Expiry      : ${exp_date}"
                echo -e "Max Logins  : ${u_limit}"
            fi
            exit 0
            ;;
        /del|del)
            u_del="$2"
            if [[ -z "$u_del" ]]; then
                has_json "$@" && json_error "del" 5 "Invalid parameter: username required" || \
                    echo -e "${RED}Usage: iranux /del <username>${NC}"
                exit 5
            fi
            if id "$u_del" &>/dev/null; then
                userdel -r "$u_del" 2>/dev/null
                sed -i "/^$u_del/d" /etc/security/limits.conf
                if has_json "$@"; then
                    data=$(printf '{"username":"%s","message":"User deleted successfully"}' "$u_del")
                    json_success "del" "$data"
                else
                    echo -e "${GREEN}[+] User '$u_del' deleted.${NC}"
                fi
            else
                has_json "$@" && json_error "del" 4 "User not found" || \
                    echo -e "${RED}[!] User '$u_del' not found.${NC}"
                exit 4
            fi
            exit 0
            ;;
        /list|list)
            if has_json "$@"; then
                users_json=""
                total=0
                while IFS=: read -r uname _ uid _; do
                    if [[ "$uid" -ge 1000 && "$uname" != "nobody" ]]; then
                        u_expiry=$(chage -l "$uname" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs || echo "Never")
                        u_maxlogins=$(grep "^$uname soft maxlogins" /etc/security/limits.conf 2>/dev/null | awk '{print $4}' || echo "Unlimited")
                        [[ -n "$users_json" ]] && users_json+=","
                        users_json+=$(printf '{"username":"%s","expiry":"%s","max_logins":"%s","active":true}' "$uname" "$u_expiry" "$u_maxlogins")
                        total=$((total + 1))
                    fi
                done < /etc/passwd
                data=$(printf '{"users":[%s],"total":%s}' "$users_json" "$total")
                json_success "list" "$data"
            else
                echo -e "${GREEN}=== System Users ===${NC}"
                awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd
            fi
            exit 0
            ;;
        /status|status)
            PROXY_STATUS=$(systemctl is-active iranux-tunnel 2>/dev/null || echo "inactive")
            BADVPN_STATUS=$(systemctl is-active badvpn 2>/dev/null || echo "inactive")
            UPTIME=$(uptime -p 2>/dev/null || echo "unknown")
            if has_json "$@"; then
                data=$(printf '{"domain":"%s","ssh_port":22,"proxy_port":443,"proxy_status":"%s","udpgw_port":%s,"udpgw_status":"%s","badvpn_status":"%s","uptime":"%s"}' \
                    "$DOMAIN" "$PROXY_STATUS" "$BADVPN_PORT" "$BADVPN_STATUS" "$BADVPN_STATUS" "$UPTIME")
                json_success "status" "$data"
            else
                echo -e "${CYAN}=== IRANUX STATUS ===${NC}"
                echo -e "Domain       : ${DOMAIN}"
                echo -e "SSH Port     : 22"
                echo -e "Proxy Port   : 443 (${PROXY_STATUS})"
                echo -e "UDPGW Port   : ${BADVPN_PORT} (${BADVPN_STATUS})"
                echo -e "Uptime       : ${UPTIME}"
            fi
            exit 0
            ;;
        /info|info)
            u_info="$2"
            if [[ -z "$u_info" ]]; then
                has_json "$@" && json_error "info" 5 "Invalid parameter: username required" || \
                    echo -e "${RED}Usage: iranux /info <username>${NC}"
                exit 5
            fi
            if ! id "$u_info" &>/dev/null; then
                has_json "$@" && json_error "info" 4 "User not found" || \
                    echo -e "${RED}[!] User '$u_info' not found.${NC}"
                exit 4
            fi
            u_expiry=$(chage -l "$u_info" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs || echo "Never")
            u_maxlogins=$(grep "^$u_info soft maxlogins" /etc/security/limits.conf 2>/dev/null | awk '{print $4}' || echo "Unlimited")
            if has_json "$@"; then
                data=$(printf '{"username":"%s","expiry":"%s","max_logins":"%s","active":true,"created_at":"unknown"}' \
                    "$u_info" "$u_expiry" "$u_maxlogins")
                json_success "info" "$data"
            else
                echo -e "${GREEN}=== User Info: $u_info ===${NC}"
                echo -e "Username   : $u_info"
                echo -e "Expiry     : $u_expiry"
                echo -e "Max Logins : $u_maxlogins"
            fi
            exit 0
            ;;
        --schema)
            cat << 'SCHEMA'
{
  "protocol": "iranux-json-rpc",
  "version": "1.0.0",
  "encoding": "utf-8",
  "transport": "ssh-stdout",
  "commands": {
    "add": {
      "description": "Create a new SSH tunnel user",
      "cli": "iranux /add {username} {password} [days] [max_logins] [--json]",
      "parameters": [
        { "name": "username", "type": "string", "required": true, "position": 1, "description": "SSH username", "validation": { "min_length": 3, "max_length": 32, "pattern": "^[a-z][a-z0-9_-]*$", "pattern_hint": "Lowercase letters, numbers, underscore, dash. Must start with a letter." } },
        { "name": "password", "type": "string", "required": true, "position": 2, "description": "SSH password", "validation": { "min_length": 6, "max_length": 64 } },
        { "name": "days", "type": "integer", "required": false, "position": 3, "default": null, "description": "Account expiry in days. Omit for no expiry.", "validation": { "min": 1, "max": 3650 } },
        { "name": "max_logins", "type": "integer", "required": false, "position": 4, "default": null, "description": "Max simultaneous logins. Omit for unlimited.", "validation": { "min": 1, "max": 100 } },
        { "name": "--json", "type": "flag", "required": false, "position": null, "description": "Output result as JSON instead of human-readable text" }
      ],
      "response": { "success": { "status": "success", "command": "add", "data": { "username": "string", "password": "string", "expiry": "string|null", "max_logins": "integer|string", "ssh_host": "string", "ssh_port": "integer", "udpgw_port": "integer", "sni": "string", "protocol": "string", "payload": "string" } }, "error": { "status": "error", "command": "add", "code": "integer", "message": "string" } }
    },
    "del": {
      "description": "Delete an existing SSH tunnel user",
      "cli": "iranux /del {username} [--json]",
      "parameters": [
        { "name": "username", "type": "string", "required": true, "position": 1, "description": "Username to delete", "validation": { "min_length": 1, "max_length": 32 } },
        { "name": "--json", "type": "flag", "required": false, "position": null, "description": "Output result as JSON instead of human-readable text" }
      ],
      "response": { "success": { "status": "success", "command": "del", "data": { "username": "string", "message": "string" } }, "error": { "status": "error", "command": "del", "code": "integer", "message": "string" } }
    },
    "list": {
      "description": "List all SSH tunnel users on the system",
      "cli": "iranux /list [--json]",
      "parameters": [
        { "name": "--json", "type": "flag", "required": false, "position": null, "description": "Output result as JSON instead of human-readable text" }
      ],
      "response": { "success": { "status": "success", "command": "list", "data": { "users": [ { "username": "string", "expiry": "string|null", "max_logins": "integer|string", "active": "boolean" } ], "total": "integer" } }, "error": { "status": "error", "command": "list", "code": "integer", "message": "string" } }
    },
    "status": {
      "description": "Get server and service status (proxy, UDPGW, uptime)",
      "cli": "iranux /status [--json]",
      "parameters": [
        { "name": "--json", "type": "flag", "required": false, "position": null, "description": "Output result as JSON instead of human-readable text" }
      ],
      "response": { "success": { "status": "success", "command": "status", "data": { "domain": "string", "ssh_port": "integer", "proxy_port": "integer", "proxy_status": "string", "udpgw_port": "integer", "udpgw_status": "string", "badvpn_status": "string", "uptime": "string" } }, "error": { "status": "error", "command": "status", "code": "integer", "message": "string" } }
    },
    "info": {
      "description": "Get info about a specific SSH tunnel user",
      "cli": "iranux /info {username} [--json]",
      "parameters": [
        { "name": "username", "type": "string", "required": true, "position": 1, "description": "Username to look up" },
        { "name": "--json", "type": "flag", "required": false, "position": null, "description": "Output result as JSON instead of human-readable text" }
      ],
      "response": { "success": { "status": "success", "command": "info", "data": { "username": "string", "expiry": "string|null", "max_logins": "integer|string", "active": "boolean", "created_at": "string" } }, "error": { "status": "error", "command": "info", "code": "integer", "message": "string" } }
    },
    "schema": {
      "description": "Print the full JSON-RPC schema for this CLI (this document)",
      "cli": "iranux --schema",
      "parameters": [],
      "response": { "success": { "note": "Prints this schema document to stdout. No --json flag needed." } }
    },
    "help": {
      "description": "Show CLI help and usage information",
      "cli": "iranux /help",
      "aliases": ["/help", "help", "--help", "-h"],
      "parameters": [],
      "response": { "success": { "note": "Prints human-readable help to stdout. No --json flag." } }
    }
  },
  "error_codes": {
    "1": "General error",
    "2": "Permission denied (not root)",
    "3": "User already exists",
    "4": "User not found",
    "5": "Invalid parameter",
    "6": "System error (useradd failed)",
    "7": "Service not running"
  },
  "meta": { "schema_command": "iranux --schema", "json_flag": "--json", "min_app_version": "1.0.0" }
}
SCHEMA
            exit 0
            ;;
        /help|help|--help|-h)
            echo -e "${CYAN}=== IRANUX CLI HELP ===${NC}"
            echo -e ""
            echo -e "${GREEN}USAGE:${NC}"
            echo -e "  iranux                                Open interactive menu"
            echo -e "  iranux /add <u> <p> [days] [lim]     Create user non-interactively"
            echo -e "  iranux /del <username>                Delete user non-interactively"
            echo -e "  iranux /list                          List all users"
            echo -e "  iranux /status                        Show service status"
            echo -e "  iranux /info <username>               Show user info"
            echo -e "  iranux --schema                       Print JSON-RPC schema"
            echo -e "  iranux /help                          Show this help"
            echo -e ""
            echo -e "${GREEN}FLAGS:${NC}"
            echo -e "  --json                                Output in JSON format"
            echo -e ""
            echo -e "${GREEN}EXAMPLES:${NC}"
            echo -e "  iranux /add ali P@ss123 30 2          Create user 'ali', 30 days, max 2 logins"
            echo -e "  iranux /add bob secret                Create user 'bob' with no expiry/limit"
            echo -e "  iranux /del ali                       Delete user 'ali'"
            echo -e "  iranux /list                          Show all users"
            echo -e "  iranux /list --json                   Show all users in JSON format"
            echo -e "  iranux /status --json                 Show service status in JSON format"
            echo -e "  iranux /info ali --json               Show user info in JSON format"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Unknown command: $1${NC}"
            echo -e "Run 'iranux /help' for usage."
            exit 1
            ;;
    esac
fi

while true; do
    clear
    echo -e "${CYAN}=== IRANUX TERMINAL MANAGER ===${NC}"
    echo -e " 1) Create User"
    echo -e " 2) Delete User"
    echo -e " 3) List Users"
    echo -e " 4) User Info"
    echo -e " 5) Server Status"
    echo -e " 0) Exit"
    echo -e "-------------------------------"
    read -p " Select: " choice
    case $choice in
        1)
            read -p "Username: " u_name
            read -p "Password: " u_pass
            read -p "Expiry days (leave blank = never): " u_days
            read -p "Max logins (leave blank = unlimited): " u_limit
            if id "$u_name" &>/dev/null; then
                echo -e "${RED}[!] User already exists.${NC}"
                read -p "Press Enter..."
                continue
            fi
            if ! useradd -m -s /bin/false "$u_name"; then
                echo -e "${RED}[!] Failed to create user.${NC}"
                read -p "Press Enter..."
                continue
            fi
            echo "$u_name:$u_pass" | chpasswd
            if [[ -n "$u_days" ]]; then
                exp_date=$(date -d "+$u_days days" +%Y-%m-%d)
                chage -E "$exp_date" "$u_name"
            else
                exp_date="Never"
            fi
            if [[ -n "$u_limit" ]]; then
                sed -i "/^$u_name[[:space:]]/d" /etc/security/limits.conf
                echo "$u_name soft maxlogins $u_limit" >> /etc/security/limits.conf
            else
                u_limit="Unlimited"
            fi
            payload="GET ${SECRET_PATH} HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]"
            echo -e "\n${GREEN}=== HTTP CUSTOM CONFIG ===${NC}"
            echo -e "Protocol    : SSH-TLS-Payload"
            echo -e "Remarks     : ${u_name}"
            echo -e "SSH Host    : ${DOMAIN}"
            echo -e "SSH Port    : 443"
            echo -e "UDPGW Port  : ${BADVPN_PORT}"
            echo -e "SSH Username: ${u_name}"
            echo -e "SSH Password: ${u_pass}"
            echo -e "Expiry      : ${exp_date}"
            echo -e "Max Logins  : ${u_limit}"
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
        4)
            read -p "Username: " u_info
            if ! id "$u_info" &>/dev/null; then
                echo -e "${RED}[!] User not found.${NC}"
            else
                u_expiry=$(chage -l "$u_info" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs || echo "Never")
                u_maxlogins=$(grep "^$u_info soft maxlogins" /etc/security/limits.conf 2>/dev/null | awk '{print $4}' || echo "Unlimited")
                echo -e "${GREEN}=== User Info: $u_info ===${NC}"
                echo -e "Username   : $u_info"
                echo -e "Expiry     : $u_expiry"
                echo -e "Max Logins : $u_maxlogins"
            fi
            read -p "Press Enter..."
            ;;
        5)
            PROXY_STATUS=$(systemctl is-active iranux-tunnel 2>/dev/null || echo "inactive")
            BADVPN_STATUS=$(systemctl is-active badvpn 2>/dev/null || echo "inactive")
            UPTIME=$(uptime -p 2>/dev/null || echo "unknown")
            echo -e "${CYAN}=== IRANUX STATUS ===${NC}"
            echo -e "Domain       : ${DOMAIN}"
            echo -e "SSH Port     : 22"
            echo -e "Proxy Port   : 443 (${PROXY_STATUS})"
            echo -e "UDPGW Port   : ${BADVPN_PORT} (${BADVPN_STATUS})"
            echo -e "Uptime       : ${UPTIME}"
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

echo -e "\n${CYAN}===========================================${RESET}"
echo -e "${CYAN}        IRANUX CLI COMMAND REFERENCE       ${RESET}"
echo -e "${CYAN}===========================================${RESET}"
echo -e ""
echo -e "  ${GREEN}INTERACTIVE MODE:${RESET}"
echo -e "    iranux                            Open interactive menu"
echo -e ""
echo -e "  ${GREEN}NON-INTERACTIVE COMMANDS:${RESET}"
echo -e "    iranux /add <user> <pass> [days] [maxlogins]"
echo -e "                                      Create a new SSH user"
echo -e "    iranux /del <username>             Delete a user"
echo -e "    iranux /list                       List all users"
echo -e "    iranux /help                       Show full help"
echo -e ""
echo -e "  ${GREEN}EXAMPLES:${RESET}"
echo -e "    ${CYAN}iranux /add ali P@ss 30 2${RESET}         Create 'ali', 30-day expiry, max 2 logins"
echo -e "    ${CYAN}iranux /add bob secret${RESET}            Create 'bob' with no expiry or login limit"
echo -e "    ${CYAN}iranux /del ali${RESET}                   Delete user 'ali'"
echo -e "    ${CYAN}iranux /list${RESET}                      Show all system users"
echo -e ""
echo -e "  ${GREEN}TELEGRAM BOT COMMANDS:${RESET}"
echo -e "    /menu                              Show bot menu"
echo -e "    /add <user> <pass> <days> <limit>  Create user via Telegram"
echo -e ""
echo -e "${CYAN}===========================================${RESET}"
