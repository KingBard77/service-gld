#!/usr/bin/env bash

# COLORS
NC='\033[0m'
SUCCESS='\033[0;32m'
ERROR='\033[0;31m'
WARN='\033[0;33m'
INFO='\033[1;34m'

MENU="
######################################################################
# Golden Configuration Setup
# Usage:
#    sudo ./setup.sh -i <service>   # Install a specific service
#    sudo ./setup.sh -r <service>   # Remove a specific service
#    sudo ./setup.sh -i:-r all      # Install or remove all services
#    sudo ./setup.sh -l             # List available services
#######################################################################
"

# FALSE = run inside VM, TRUE = run remotely via xxclustersh
IS_REMOTE=TRUE

# SOURCE SCRIPT DIRECTORY
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" && "${BASH_SOURCE[0]}" != "-bash" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
else
    SCRIPT_DIR="$(pwd)"
fi

# SOURCE SETUP.CONF
if [[ "$IS_REMOTE" == FALSE ]]; then
    CONFIG_FILE="${SCRIPT_DIR}/conf/setup.conf"
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        echo -e "${ERROR}  ERROR: Missing configuration file: $CONFIG_FILE${NC}"
        exit 1
    fi
fi

echo -e "${INFO}##### Package: Update ${NC}"
apt --assume-yes --quiet update

# Advanced Package Tool (APT)
apt_install(){
    echo -e "${INFO}##### Package: Upgrade ${NC}"
    apt --assume-yes upgrade

    echo -e "${INFO}##### Package: Install ${NC}"
    apt install --assume-yes ${PACKAGE}
}

# Z Shell (ZSH)
zsh_install(){
    echo -e "${INFO}##### Install: ZSH Client ${NC}"

    apt --assume-yes install zsh

    CHSH=no RUNZSH=no sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

    echo -e "${INFO}##### Oh-My-Zsh: Apply autload hostname and username ${NC}"
    echo 'autoload -U colors && colors' >> /root/.zshrc
    echo "PROMPT='%{\$fg_bold[green]%}%n@%m %{\$fg_bold[blue]%}%1~ %{\$reset_color%}%# '" >> /root/.zshrc

    echo -e "${INFO}##### Oh-My-Zsh: Copy to user Infra ${NC}"
    cp -a /root/.oh-my-zsh/ /home/infra/
    cp -a /root/.zshrc /home/infra/
    chown infra:infra /home/infra/.oh-my-zsh/ /home/infra/.zshrc

    echo -e "${INFO}##### Oh-My-Zsh: Copy to /etc/skel ${NC}"
    cp -a /root/.oh-my-zsh /etc/skel/
    cp -a /root/.zshrc /etc/skel/
    chown root:root /etc/skel/.oh-my-zsh/ /etc/skel/.zshrc

    echo -e "${INFO}##### Oh-My-Zsh: Apply default shell for new user${NC}"
    sed -i 's|SHELL=.*|SHELL=/usr/bin/zsh|' /etc/default/useradd
    usermod -s /usr/bin/zsh infra
    usermod -s /usr/bin/zsh root
    chsh -s /usr/bin/zsh infra
    chsh -s /usr/bin/zsh root

    echo -e "${INFO}##### Home: SSH Key ${NC}"
    mkdir -p /home/infra/.ssh
    echo "${SSH_KEY}" > /home/infra/.ssh/authorized_keys
    echo 'infra ALL=(ALL) NOPASSWD: ALL' | EDITOR='tee -a' visudo

    echo -e "${SUCCESS}##### ZSH: Install complete: Please logout and login again to use ZSH as the default shell ${NC}"
}

# Network File System (NFS)
nfs_install(){
    echo -e "${INFO}##### Install: NFS Client ${NC}"

    apt --assume-yes install autofs nfs-common
    echo "/mnt/mydid /etc/auto.nfs_home --timeout=600"  | tee -a /etc/auto.master
    systemctl restart autofs
    systemctl daemon-reload
    echo -e "${SUCCESS}##### NFS: Install complete ${NC}"
}

nfs_remove(){
    echo -e "${INFO}##### Remove: NFS Client ${NC}"

    sed -i "\|/mnt/mydid /etc/auto.nfs_home|d" /etc/auto.master
    systemctl stop autofs
    systemctl disable autofs
    apt --assume-yes purge autofs nfs-common

    echo -e "${SUCCESS}##### NFS: Removal complete ${NC}"
}

# Log Server (Logstash + Filebeat on same VM; Logstash -> ES over TLS)
log_install() {
  echo -e "${INFO}##### Install: Log Client ${NC}"

  # 0) Ensure system CA store is fresh (for Elastic APT TLS)
  apt -y install --reinstall ca-certificates >/dev/null 2>&1 || true
  update-ca-certificates >/dev/null 2>&1 || true

  # 1) Elastic APT repo + Logstash
  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
    | gpg --dearmor --yes -o /usr/share/keyrings/elastic.gpg
  echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/${ES_VERSION}/apt stable main" \
    > /etc/apt/sources.list.d/elastic-${ES_VERSION}.list
  apt update
  apt -y install apt-transport-https logstash

  # 2) CA that Logstash (and curl) can read
  CA_PATH="/etc/logstash/certs/http_ca.crt"     # <— hard set (not :=)
  mkdir -p "$(dirname "$CA_PATH")"

  if [[ -r /etc/elasticsearch/certs/http_ca.crt ]]; then
    echo -e "${INFO}##### Copying ES CA to ${CA_PATH} ${NC}"
    install -m 0644 /etc/elasticsearch/certs/http_ca.crt "$CA_PATH"
  else
    echo -e "${INFO}##### CA: Fetching from https://${ES_SERVER_HOST}:${ES_SERVER_PORT} ${NC}"
    curl -ks "https://${ES_SERVER_HOST}:${ES_SERVER_PORT}" \
      | grep -oP '(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----' \
      > "$CA_PATH" || true
  fi

  if [[ ! -s "$CA_PATH" ]]; then
    echo -e "${ERROR}Failed to obtain Elasticsearch CA at ${CA_PATH}.${NC}"
    exit 1
  fi
  chmod 0644 "$CA_PATH"

  if [[ ! -s "$CA_PATH" ]]; then
    echo -e "${ERROR}Failed to obtain Elasticsearch CA at ${CA_PATH}.${NC}"
    exit 1
  fi
  chmod 0644 "$CA_PATH"

  echo -e "${INFO}##### Logstash: Writing pipeline ${NC}"
  printf "%s\n" "$LS_INPUT_CONF"  >/etc/logstash/conf.d/00-input-beats.conf
  printf "%s\n" "$LS_FILTER_CONF" >/etc/logstash/conf.d/10-filter.conf
  printf "%s\n" "$LS_OUTPUT_CONF" >/etc/logstash/conf.d/99-output-es.conf

  if [[ "${LS_AUTORELOAD:-false}" == "true" || "${LS_AUTORELOAD:-false}" == "TRUE" ]]; then
    sed -ri 's/^#?\s*config.reload.automatic:.*/config.reload.automatic: true/' /etc/logstash/logstash.yml
    grep -q '^config.reload.interval:' /etc/logstash/logstash.yml || echo 'config.reload.interval: 3s' >> /etc/logstash/logstash.yml
  fi

  systemctl daemon-reload
  systemctl enable logstash
  systemctl restart logstash

  # 4) Filebeat (ships syslog/auth to Logstash 5044)
  echo -e "${INFO}##### Install: Filebeat ${NC}"
  apt update
  apt -y install filebeat

  # Minimal config: ship syslog & auth.log to local Logstash
  printf "%s\n" "$FB_YML" >/etc/filebeat/filebeat.yml
  systemctl enable --now filebeat

  # Enable system module for nicer parsing (optional but useful)
  filebeat modules enable system >/dev/null 2>&1 || true

  systemctl enable --now filebeat

  # 5) Verify ES connectivity via readable CA
  echo -e "${INFO}##### Verify: ES health via CA ${NC}"
  curl -s -u "$ES_USERNAME:$ES_PASSWORD" \
    --cacert "$CA_PATH" \
    "https://${ES_SERVER_HOST}:${ES_SERVER_PORT}/_cluster/health?pretty" || true

  echo -e "${SUCCESS}##### Log: Install complete ${NC}"
}


# Mail Relay Client
mil_install(){
    echo -e "${INFO}##### Install: Mail Client ${NC}"

    apt install --assume-yes postfix
    MAILNAME=$(hostname -f 2>/dev/null || hostname)
    debconf-set-selections <<< "postfix postfix/mailname string $MAILNAME"
    debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
    sed -i "/^relayhost =/c\relayhost = $RELAYHOST" "$POSTFIX_MAIN_CF" || echo "relayhost = $RELAYHOST" | tee -a "$POSTFIX_MAIN_CF"
    systemctl enable postfix
    systemctl restart postfix

    echo -e "${SUCCESS}#### Mail: Install Complete ${NC}"
}

mil_remove(){
    echo -e "${INFO}##### Remove: DHCP ${NC}"

    grep -q "^relayhost =" "$POSTFIX_MAIN_CF" && sed -i "s/^relayhost =.*/#&/" "$POSTFIX_MAIN_CF" || echo "No relayhost setting to restore."
    systemctl restart postfix

    echo -e "${SUCCESS}##### DHCP: Remove complete ${NC}"
}

# Checkmk Monitoring Agent Client
cmk_install() {
    echo -e "${INFO}##### Install: CMK Client ${NC}"

    AGENT_URL=$(curl -s -u "$CMK_USER":"$CMK_PASSWORD" "$CMK_AGENT_URL" | grep -oP 'href="check-mk-agent[^"]+\.deb"' | head -n 1 | awk -F'"' '{print "'"$CMK_AGENT_URL"'" $2}' )
    wget -O check-mk-agent.deb "$AGENT_URL"
    apt install --assume-yes ./check-mk-agent.deb
    rm -rf check-mk-agent.deb
    systemctl restart check-mk-agent.socket
    systemctl restart check-mk-agent-async.service 

    echo -e "${SUCCESS}##### CMK: Install complete ${NC}"
}

cmk_remove() {
    echo -e "${INFO}##### Remove: CMK Client ${NC}"

    systemctl stop check-mk-agent.socket
    systemctl stop check-mk-agent-async.service 
    systemctl disable check-mk-agent.socket
    systemctl disable check-mk-agent-async.service 
    apt remove --assume-yes check-mk-agent
    systemctl daemon-reload

    echo -e "${SUCCESS}##### CMK: Remove complete ${NC}"
}

# Dynamic Host Configuration Protocol (DHCP) 
dcp_install () {
    echo -e "${INFO}##### Install: DHCP Client Configuration ${NC}"

    NETPLAN_FILE=$(find /etc/netplan/ -type f -name "*.yaml" | head -n 1)
    sed -i '/^network:/,/^version:/d' $NETPLAN_FILE
    echo "$NETPLAN_DYNAMIC_CONTENT" > $NETPLAN_FILE
    netplan apply
    echo -e "${SUCCESS}##### DHCP Client: Configuration complete ${NC}"
}

dcp_remove () {
    echo -e "${INFO}##### Remove: DHCP Configuration ${NC}"

    NETPLAN_FILE=$(find /etc/netplan/ -type f -name "*.yaml" | head -n 1)
    sed -i '/^network:/,/^version:/d' $NETPLAN_FILE
    echo "$NETPLAN_STATIC_CONTENT" > $NETPLAN_FILE
    netplan apply
    echo -e "${SUCCESS}##### DHCP Client: Removal complete ${NC}"
}

# Lightweight Directory Access Protocol (LDAP)
ldp_install() {
    echo -e "${INFO}##### Install: LDAP Client ${NC}"

    export DEBIAN_FRONTEND=noninteractive
    LDP_PASSWORD_ESCAPED=$(echo "$LDP_PASSWORD" | sed 's/\([#&]\)/\\\1/g')

    apt install --assume-yes debconf-utils
    # Set debconf selections for libnss-ldap
    echo "libnss-ldap libnss-ldap/ldap-server string ldap://$LDP_SERVER" | debconf-set-selections
    echo "libnss-ldap shared/ldapns/base-dn string dc=$LDP_NAME,dc=$LDP_DOMAIN" | debconf-set-selections
    echo "libnss-ldap libnss-ldap/binddn string cn=$LDP_ADMIN,dc=$LDP_NAME,dc=$LDP_DOMAIN" | debconf-set-selections
    echo "libnss-ldap libnss-ldap/bindpw password $LDP_PASSWORD_ESCAPED" | debconf-set-selections
    echo "libnss-ldap libnss-ldap/ldap_version select 3" | debconf-set-selections
    echo "libnss-ldap libnss-ldap/dblogin boolean false" | debconf-set-selections
    echo "libnss-ldap libnss-ldap/rootbinddn string cn=$LDP_ADMIN,dc=$LDP_NAME,dc=$LDP_DOMAIN" | debconf-set-selections
    echo "libnss-ldap libnss-ldap/override boolean true" | debconf-set-selections
    # Set debconf selections for libpam-ldap
    echo "libpam-ldap libpam-ldap/ldap-server string ldap://$LDP_SERVER" | debconf-set-selections
    echo "libpam-ldap libpam-ldap/base-dn string dc=$LDP_NAME,dc=$LDP_DOMAIN" | debconf-set-selections
    echo "libpam-ldap libpam-ldap/binddn string cn=$LDP_ADMIN,dc=$LDP_NAME,dc=$LDP_DOMAIN" | debconf-set-selections
    echo "libpam-ldap libpam-ldap/bindpw password $LDP_PASSWORD_ESCAPED" | debconf-set-selections
    echo "libpam-ldap libpam-ldap/dblogin boolean false" | debconf-set-selections
    echo "libpam-ldap libpam-ldap/pam_password select md5" | debconf-set-selections
    # Set debconf selections for ldap-utils 
    echo "ldap-utils ldap-utils/ldap-server string ldap://$LDP_SERVER" | debconf-set-selections
    echo "ldap-utils ldap-utils/ldap_version select 3" | debconf-set-selections
    # Install or reconfigure packages
    apt install --assume-yes libnss-ldap libpam-ldap ldap-utils nscd nslcd
    # File /etc/ldap.conf 
    sed -i "s|^uri.*|uri ldap://$LDP_SERVER|" /etc/ldap.conf
    sed -i "s|^base.*|base dc=$LDP_NAME,dc=$LDP_DOMAIN|" /etc/ldap.conf
    sed -i "s|^rootbinddn.*|rootbinddn cn=$LDP_ADMIN,dc=$LDP_NAME,dc=$LDP_DOMAIN|" /etc/ldap.conf
    sed -i "s|^pam_password.*|pam_password md5|" /etc/ldap.conf
    # File /etc/ldap.secret
    echo "$LDP_PASSWORD" | tee /etc/ldap.secret > /dev/null
    chmod 600 /etc/ldap.secret
    chown nslcd:nslcd /etc/ldap.secret
    # File /etc/nslcd.conf
    echo "$CONF_ETC_NSLCD" > /etc/nslcd.conf
    systemctl restart nslcd
    systemctl restart nscd
    # ldapsearch -x -H "ldap://$LDP_SERVER" -D "cn=$LDP_ADMIN,dc=$LDP_NAME,dc=$LDP_DOMAIN" -w '#mydid123' -b "dc=$LDP_NAME,dc=$LDP_DOMAIN" '(objectClass=*)'

    echo -e "${SUCCESS}##### LDAP: Install complete ${NC}"
}

ldp_remove(){
    echo -e "${INFO}##### Remove: LDAP ${NC}"

    apt purge --assume-yes libnss-ldapd libnss-ldap libpam-ldap ldap-utils nscd nslcd
    apt remove --assume-yes libnss-ldapd libnss-ldap libpam-ldap ldap-utils nscd nslcd
    rm -f /etc/nslcd.conf
    rm -f /etc/ldap.secret

    echo -e "${SUCCESS}##### LDAP: Remove complete ${NC}"
}

# Netbox (IPM)
ipm_install(){
    echo -e "${INFO}##### Install: IPAM Client ${NC}"

    apt update
    apt install -y python3 python3-pip python3-venv jq curl

    python3 -m venv /opt/netbox-agent-venv
    source /opt/netbox-agent-venv/bin/activate

    pip install --upgrade pip
    pip install netbox-agent

    mkdir -p /etc/netbox-agent
    cat <<EOF > "$NETBOX_PATH"
netbox:
  url: "$NETBOX_URL"
  token: "$NETBOX_TOKEN"
  ssl_verify: false

virtual:
  enabled: true
  cluster_name: "$CLUSTER_NAME"
  hypervisor: false

hostname_cmd: "hostname"
EOF

$NETBOX_AGENT_BIN \
  --config "$CONFIG_PATH" \
  --register \
  --update-network \
  --update-inventory \
  --log_level debug
    
    echo -e "${SUCCESS}##### IPAM Client: Configuration complete ${NC}"
}

# Display available services
services_display() {
    echo -e "${INFO}################################################## ${NC}"
    echo -e "${INFO}# Available Services for Configuration and Removal ${NC}"
    echo "  - apt: Advanced Package Tool"
    echo "  - zsh: Z Shell"
    echo "  - nfs: Network File System"
    echo "  - log: Log Stash"
    echo "  - mil: Mail Relay"
    echo "  - cmk: Dynamic Host Configuration Protocol"
    echo "  - dcp: Checkmk Monitoring Agent"
    echo "  - ldp: Lightweight Directory Access Protocol"
    echo "  - ipm: Netbox"
    echo -e "${INFO}###################################################${NC}"
}

while getopts "i:r:l" opt; do
    case $opt in
        i)
            case $OPTARG in
                apt) apt_install ;;
                zsh) zsh_install ;;
                nfs) nfs_install ;;
                log) log_install ;;
                mil) mil_install ;;
                cmk) cmk_install ;;
                dcp) dcp_install ;;
                ldp) ldp_install ;;
                ipm) ipm_install ;;
                all)
                    apt_install
                    zsh_install
                    nfs_install
                    log_install
                    mil_install
                    cmk_install
                    dcp_install
                    ldp_install
                    ipm_install
                    ;;
                *) echo -e "${ERROR}Invalid option for -i: $OPTARG${NC}"; exit 1 ;;
            esac
            ;;
        r)
            case $OPTARG in
                mil) mil_remove ;;
                cmk) cmk_remove ;;
                nfs) nfs_remove ;;
                dcp) dcp_remove ;;
                ldp) ldp_remove ;;
                all)
                    mil_remove
                    cmk_remove
                    nfs_remove
                    dcp_remove
                    ldp_remove
                    ;;
                *) echo -e "${ERROR}Invalid option for -r: $OPTARG${NC}"; exit 1 ;;
            esac
            ;;
        l)
            services_display
            ;;
        *)
            echo -e "${INFO}Invalid option: $opt - Usage: $0 [-i|-r] [apt|zsh|nfs|log|cmk|dcp|ldp|all]${NC}"
            exit 1
            ;;
    esac
done
            
# Display menu if no options were provided
if [ $OPTIND -eq 1 ]; then
    echo -e "${INFO}$MENU${NC}"
fi

echo -e "${INFO}##### Package: Cleaning ${NC}"
apt --assume-yes autoremove
apt --assume-yes autoclean

echo -e "${INFO}#### Reboot ${NC}"
# reboot
