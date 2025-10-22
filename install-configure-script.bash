#!/usr/bin/env bash
# Automated Linux Server Setup - Enterprise Edition
# Supports: Debian (12+), Ubuntu (20.04+), CentOS (7+), RHEL (7+)
# Installs and configures: Nginx, PHP-FPM, MariaDB (MySQL-compatible), phpMyAdmin,
# Node.js, Fail2Ban, firewall (UFW or firewalld), Certbot (Let's Encrypt)
# Optional Docker stack deployment.

set -euo pipefail
IFS=$'\n\t'

SCRIPT_NAME=$(basename "$0")
LOG_FILE="/var/log/enterprise-server-setup.log"
STATE_DIR="/var/local/enterprise-server-setup"
mkdir -p "$(dirname "$LOG_FILE")" "$STATE_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

exec > >(tee -a "$LOG_FILE") 2>&1

log(){
  local level=$1; shift
  printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

die(){
  log "ERROR" "$*"
  exit 1
}

trap 'handle_error $? ${LINENO}' ERR
handle_error(){
  local exit_code=$1
  local line=$2
  log "ERROR" "Script failed at line ${line} with exit code ${exit_code}. Review ${LOG_FILE}."
  exit "$exit_code"
}

cleanup(){
  log "INFO" "${SCRIPT_NAME} finished. Review ${LOG_FILE} for a persistent record."
}
trap cleanup EXIT

# --------------------------- CONFIG (env vars or args) ---------------------------
DOMAINS_RAW=${DOMAINS_RAW:-""}
MODE=${MODE:-native}
EMAIL=${EMAIL:-""}
DB_ROOT_PASS=${DB_ROOT_PASS:-""}
PHP_VERSION=${PHP_VERSION:-"8.2"}
FORCE=${FORCE:-false}
ENABLE_SSH_HARDENING=${ENABLE_SSH_HARDENING:-false}
ENABLE_AUTO_UPDATES=${ENABLE_AUTO_UPDATES:-true}
WEB_USER=""
WEB_GROUP=""
PRIMARY_DOMAIN=""
declare -a DOMAIN_GROUPS=()

usage(){
  cat <<EOF
Usage: sudo ${SCRIPT_NAME} [options]

Options:
  --domains           Domain definitions. Use comma-separated values per vhost.
                      Multiple vhosts can be separated by semicolons, e.g.
                      "example.com,www.example.com;api.example.com".
  --mode              Deployment mode: native | docker (default: native).
  --email             Administrator email used for Let's Encrypt registration.
  --db-root-pass      MariaDB root password. Generated if omitted.
  --php               PHP version (default: 8.2). Use format 8.2, 8.1, etc.
  --force             Continue even if potential conflicts are detected.
  --help              Show this help message.

Environment variables mirror the CLI arguments. Additional toggles:
  ENABLE_SSH_HARDENING=true   Apply conservative SSH configuration.
  ENABLE_AUTO_UPDATES=false   Skip unattended upgrades setup.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --domains) DOMAINS_RAW="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;;
    --email) EMAIL="$2"; shift 2;;
    --db-root-pass) DB_ROOT_PASS="$2"; shift 2;;
    --php) PHP_VERSION="$2"; shift 2;;
    --force) FORCE=true; shift 1;;
    --help) usage; exit 0;;
    *) die "Unknown arg: $1";;
  esac
done

if [ -n "${DOMAIN-}" ] && [ -z "$DOMAINS_RAW" ]; then
  DOMAINS_RAW="$DOMAIN"
fi
if [ -n "${DOMAINS-}" ] && [ -z "$DOMAINS_RAW" ]; then
  DOMAINS_RAW="$DOMAINS"
fi
if [ -z "$DOMAINS_RAW" ]; then
  die "No domains provided. Supply via --domains or DOMAINS environment variable."
fi

if [ -z "$DB_ROOT_PASS" ]; then
  command -v openssl >/dev/null 2>&1 || die "openssl is required to generate a database password. Install it first."
  DB_ROOT_PASS=$(openssl rand -base64 24)
  log "WARN" "No DB root password provided; generated a secure password automatically."
fi

# --------------------------- UTILS ---------------------------
detect_os(){
  . /etc/os-release || true
  OS_ID=${ID,,}
  OS_LIKE=${ID_LIKE,,}
  OS_VERSION=${VERSION_ID,,}
  log "INFO" "Detected OS: $OS_ID (like: $OS_LIKE) version: $OS_VERSION"
}

require_root(){
  if [ "$EUID" -ne 0 ]; then
    die "This script must be run as root. Retry with sudo."
  fi
}

verify_prerequisites(){
  local required_cmds=(curl wget tar systemctl)
  for bin in "${required_cmds[@]}"; do
    command -v "$bin" >/dev/null 2>&1 || die "Required command '$bin' not found. Install it and retry."
  done
}

parse_domain_groups(){
  local raw="$1"
  local sanitized
  IFS=';' read -ra sanitized <<< "$raw"
  DOMAIN_GROUPS=()
  for entry in "${sanitized[@]}"; do
    local trimmed=${entry//[[:space:]]/}
    [ -n "$trimmed" ] || continue
    DOMAIN_GROUPS+=("$trimmed")
  done
  if [ "${#DOMAIN_GROUPS[@]}" -eq 0 ]; then
    die "Unable to parse provided domains."
  fi
  PRIMARY_DOMAIN=$(printf '%s' "${DOMAIN_GROUPS[0]}" | awk -F',' '{print $1}')
  log "INFO" "Primary domain resolved as: ${PRIMARY_DOMAIN}"
}

determine_web_user(){
  case "$OS_ID" in
    ubuntu|debian)
      WEB_USER=${WEB_USER:-www-data}
      WEB_GROUP=${WEB_GROUP:-www-data}
      ;;
    centos|rhel)
      WEB_USER=${WEB_USER:-nginx}
      WEB_GROUP=${WEB_GROUP:-nginx}
      ;;
    *)
      die "Unsupported OS: $OS_ID"
      ;;
  esac
}

check_system_resources(){
  local mem_required=1000
  local mem_available
  mem_available=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  if (( mem_available < mem_required )); then
    log "WARN" "Less than ${mem_required}MB RAM detected (${mem_available}MB). Installation may fail."
    if ! $FORCE; then
      die "Insufficient memory. Rerun with --force if you want to continue regardless."
    fi
  fi
}

update_system_packages(){
  log "INFO" "Updating base operating system packages"
  case "$OS_ID" in
    ubuntu|debian)
      apt-get update
      apt-get -y upgrade
      apt-get -y dist-upgrade
      apt-get -y autoremove
      ;;
    centos|rhel)
      yum -y update
      ;;
  esac
}

ensure_state_marker(){
  echo "mode=${MODE}" > "${STATE_DIR}/last-run"
}

# --------------------------- INSTALL COMMON TOOLS ---------------------------
install_common(){
  log "INFO" "Installing base packages"
  case "$OS_ID" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y ca-certificates curl wget gnupg lsb-release software-properties-common unzip git openssh-server rsync cron
      ;;
    centos|rhel)
      yum install -y epel-release yum-utils curl wget unzip git openssh-server rsync cronie
      systemctl enable --now sshd || true
      ;;
    *)
      die "Unsupported OS: $OS_ID"
      ;;
  esac
}

# --------------------------- PACKAGE INSTALLERS ---------------------------
install_node(){
  local NODE_VERSION=20
  log "INFO" "Installing Node.js ${NODE_VERSION}.x"
  case "$OS_ID" in
    ubuntu|debian)
      curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
      apt-get install -y nodejs build-essential
      ;;
    centos|rhel)
      curl -fsSL https://rpm.nodesource.com/setup_${NODE_VERSION}.x | bash -
      yum install -y nodejs gcc-c++ make
      ;;
  esac
}

install_php(){
  log "INFO" "Installing PHP ${PHP_VERSION}"
  case "$OS_ID" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get install -y lsb-release ca-certificates apt-transport-https gnupg
      if [ ! -f /etc/apt/sources.list.d/php.list ]; then
        curl -fsSL https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /etc/apt/trusted.gpg.d/sury-php.gpg
        echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list
      fi
      apt-get update
      apt-get install -y php${PHP_VERSION} php${PHP_VERSION}-fpm php${PHP_VERSION}-mysql php${PHP_VERSION}-cli \
        php${PHP_VERSION}-curl php${PHP_VERSION}-gd php${PHP_VERSION}-mbstring php${PHP_VERSION}-xml php${PHP_VERSION}-zip php${PHP_VERSION}-bcmath
      ;;
    centos|rhel)
      yum install -y https://rpms.remirepo.net/enterprise/remi-release-${OS_VERSION%%.*}.rpm || true
      yum install -y yum-utils
      local remi_stream=${PHP_VERSION//./}
      yum-config-manager --enable remi-php${remi_stream} || true
      yum install -y php php-fpm php-mysqlnd php-cli php-curl php-gd php-mbstring php-xml php-zip php-bcmath
      ;;
  esac
}

install_database(){
  log "INFO" "Installing MariaDB server"
  case "$OS_ID" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get install -y mariadb-server mariadb-client
      systemctl enable --now mariadb
      ;;
    centos|rhel)
      yum install -y mariadb-server mariadb
      systemctl enable --now mariadb
      ;;
  esac
  mysql --user=root <<MYSQL_SECURE
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
FLUSH PRIVILEGES;
MYSQL_SECURE
  log "INFO" "MariaDB configured with provided root password"
}

install_nginx(){
  log "INFO" "Installing Nginx"
  case "$OS_ID" in
    ubuntu|debian)
      apt-get install -y nginx
      ;;
    centos|rhel)
      yum install -y nginx
      ;;
  esac
  systemctl enable --now nginx
}

install_phpmyadmin_native(){
  log "INFO" "Installing phpMyAdmin"
  case "$OS_ID" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect none" | debconf-set-selections
      echo "phpmyadmin phpmyadmin/dbconfig-install boolean false" | debconf-set-selections
      apt-get install -y phpmyadmin
      ;;
    centos|rhel)
      local PHP_MYADMIN_DIR=/usr/share/phpmyadmin
      mkdir -p "$PHP_MYADMIN_DIR"
      wget -qO- https://files.phpmyadmin.net/phpMyAdmin/latest/phpMyAdmin-latest-all-languages.tar.gz | \
        tar xz --strip-components=1 -C "$PHP_MYADMIN_DIR"
      mkdir -p /var/lib/phpmyadmin/tmp
      chown -R root:root "$PHP_MYADMIN_DIR"
      ;;
  esac
}

install_fail2ban(){
  log "INFO" "Installing Fail2Ban"
  case "$OS_ID" in
    ubuntu|debian)
      apt-get install -y fail2ban
      ;;
    centos|rhel)
      yum install -y fail2ban
      ;;
  esac
  mkdir -p /etc/fail2ban/jail.d
  cat >/etc/fail2ban/jail.d/hardening.conf <<'JAIL'
[sshd]
enabled = true
port    = ssh
maxretry = 5
findtime = 600
bantime = 3600

[nginx-http-auth]
enabled = true
JAIL
  systemctl enable --now fail2ban
}

install_certbot(){
  log "INFO" "Installing Certbot"
  case "$OS_ID" in
    ubuntu|debian)
      apt-get install -y certbot python3-certbot-nginx
      ;;
    centos|rhel)
      yum install -y certbot python3-certbot-nginx
      ;;
  esac
}

configure_firewall(){
  log "INFO" "Configuring firewall"
  case "$OS_ID" in
    ubuntu|debian)
      apt-get install -y ufw
      ufw default deny incoming
      ufw default allow outgoing
      ufw allow OpenSSH
      ufw allow 'Nginx Full'
      ufw allow 8080/tcp
      ufw --force enable
      ;;
    centos|rhel)
      yum install -y firewalld || true
      systemctl enable --now firewalld
      firewall-cmd --permanent --add-service=http
      firewall-cmd --permanent --add-service=https
      firewall-cmd --permanent --add-service=ssh
      firewall-cmd --permanent --add-port=8080/tcp
      firewall-cmd --reload
      ;;
  esac
}


# --------------------------- SECURITY & MAINTENANCE ---------------------------
configure_mysql_root_client(){
  cat >/root/.my.cnf <<MYSQLCNF
[client]
user=root
password=${DB_ROOT_PASS}
MYSQLCNF
  chmod 600 /root/.my.cnf
}

enable_automatic_updates(){
  if ! $ENABLE_AUTO_UPDATES; then
    log "INFO" "Skipping automatic OS update configuration (ENABLE_AUTO_UPDATES=false)"
    return
  fi
  case "$OS_ID" in
    ubuntu|debian)
      apt-get install -y unattended-upgrades apt-listchanges
      dpkg-reconfigure -f noninteractive unattended-upgrades
      ;;
    centos|rhel)
      if command -v dnf >/dev/null 2>&1; then
        yum install -y dnf-automatic || true
        systemctl enable --now dnf-automatic.timer || true
      else
        yum install -y yum-cron || true
        systemctl enable --now yum-cron || true
      fi
      ;;
  esac
  log "INFO" "Automatic security updates configured"
}

apply_ssh_hardening(){
  if ! $ENABLE_SSH_HARDENING; then
    log "INFO" "SSH hardening disabled (ENABLE_SSH_HARDENING=false)"
    return
  fi
  local config_dir=/etc/ssh/sshd_config.d
  mkdir -p "$config_dir"
  cat >${config_dir}/99-enterprise-hardening.conf <<'SSH'
PasswordAuthentication no
PermitRootLogin prohibit-password
ClientAliveInterval 300
ClientAliveCountMax 2
SSH
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
  log "INFO" "Applied conservative SSH hardening profile"
}

create_backup_tooling(){
  local backup_dir=/var/backups/mariadb
  local backup_script=/usr/local/sbin/backup-mariadb.sh
  mkdir -p "$backup_dir"
  cat >$backup_script <<'BACKUP'
#!/usr/bin/env bash
set -euo pipefail
STAMP=$(date +%F)
DEST=/var/backups/mariadb
mkdir -p "$DEST"
mysqldump --defaults-file=/root/.my.cnf --single-transaction --quick --lock-tables=false --all-databases > "$DEST/all-${STAMP}.sql"
find "$DEST" -type f -mtime +14 -delete
BACKUP
  chmod 700 $backup_script
  cat >/etc/cron.d/mariadb-backup <<CRON
0 2 * * * root $backup_script
CRON
  log "INFO" "Automated MariaDB backup job installed (daily 02:00)"
}

configure_php(){
  local php_ini
  if [[ "$OS_ID" =~ (ubuntu|debian) ]]; then
    php_ini=/etc/php/${PHP_VERSION}/fpm/php.ini
  else
    php_ini=/etc/php.ini
  fi
  if [ -f "$php_ini" ]; then
    sed -i "s/^;*cgi.fix_pathinfo=.*/cgi.fix_pathinfo=0/" "$php_ini"
    sed -i "s/^;*date.timezone.*/date.timezone = UTC/" "$php_ini"
  fi
  local php_service
  if [[ "$OS_ID" =~ (ubuntu|debian) ]]; then
    php_service=php${PHP_VERSION}-fpm
  else
    php_service=php-fpm
  fi
  systemctl enable --now "$php_service"
  systemctl restart "$php_service"
  log "INFO" "PHP-FPM configured and restarted ($php_service)"
}

verify_services(){
  local services=(nginx mariadb fail2ban)
  local php_service
  if [[ "$OS_ID" =~ (ubuntu|debian) ]]; then
    php_service=php${PHP_VERSION}-fpm
  else
    php_service=php-fpm
  fi
  services+=("$php_service")
  for svc in "${services[@]}"; do
    if systemctl is-active --quiet "$svc"; then
      log "INFO" "Service '$svc' is active"
    else
      log "WARN" "Service '$svc' is not running. Check logs."
    fi
  done
}

summary(){
  local mode=${MODE}
  local stack_id=$(echo "${PRIMARY_DOMAIN}" | tr '.' '_')
  log "INFO" "Setup complete (mode: ${mode}). MariaDB root password stored securely in /root/.my.cnf"
  log "INFO" "Primary domain: ${PRIMARY_DOMAIN}"
  if [ "$mode" = "docker" ]; then
    cat <<EOF
NEXT STEPS:
 - Change directory to /opt/${stack_id}
 - Start the stack: docker compose up -d
 - Access phpMyAdmin via http://<server_ip>:8080
EOF
  else
    cat <<EOF
NEXT STEPS:
 - Place your website files into the web root(s): /var/www/<domain_group>/html
 - Check nginx config: nginx -t
 - Check php-fpm: systemctl status php${PHP_VERSION}-fpm
 - Manage MariaDB: mysql --defaults-file=/root/.my.cnf
 - Access phpMyAdmin at https://<your-domain>/phpmyadmin
EOF
  fi
}
# --------------------------- NGINX VHOST GENERATOR ---------------------------
generate_nginx_vhost(){
  local server_names="$1"
  local site_name
  local root_dir
  local fastcgi_block
  local has_sites_enabled=0

  site_name=$(echo "$server_names" | tr ' ' '_' | tr ',' '_')
  root_dir="/var/www/${site_name}/html"
  mkdir -p "$root_dir"
  chown -R "$WEB_USER":"$WEB_GROUP" "$root_dir" || true

  if [[ "$OS_ID" =~ (ubuntu|debian) ]]; then
    fastcgi_block=$'        include snippets/fastcgi-php.conf;\n        fastcgi_pass unix:/var/run/php/php'"${PHP_VERSION}"$'-fpm.sock;'
  else
    fastcgi_block=$'        include fastcgi_params;\n        fastcgi_pass unix:/run/php-fpm/www.sock;\n        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;'
  fi

  if [ -d /etc/nginx/sites-enabled ]; then
    has_sites_enabled=1
  fi
  mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
  cat > /etc/nginx/sites-available/${site_name}.conf <<NGINXCONF
server {
    listen 80;
    listen [::]:80;
    server_name ${server_names};

    root ${root_dir};
    index index.php index.html index.htm;

    access_log /var/log/nginx/${site_name}.access.log;
    error_log /var/log/nginx/${site_name}.error.log;

    location / {
        try_files \${uri} \${uri}/ =404;
    }

    location ~ \.php$ {
${fastcgi_block}
    }

    location ~ /\.ht {
        deny all;
    }
}
NGINXCONF

  if [ "$has_sites_enabled" -eq 1 ]; then
    ln -sf /etc/nginx/sites-available/${site_name}.conf /etc/nginx/sites-enabled/${site_name}.conf
  else
    mkdir -p /etc/nginx/conf.d
    cp /etc/nginx/sites-available/${site_name}.conf /etc/nginx/conf.d/${site_name}.conf
  fi

  if nginx -t; then
    systemctl reload nginx || true
    log "INFO" "Generated Nginx vhost for: ${server_names} at ${root_dir}"
  else
    log "WARN" "nginx -t failed; review configuration for ${server_names}"
  fi
}

# --------------------------- SSL (Let’s Encrypt) ---------------------------
obtain_ssl(){
  local domains_str="$1"
  local primary
  primary=$(echo "$domains_str" | awk -F',' '{print $1}')
  if [ -z "${EMAIL}" ]; then
    EMAIL="admin@${primary}"
    log "WARN" "No email provided for Let's Encrypt; defaulting to ${EMAIL}"
  fi
  if ! command -v certbot >/dev/null 2>&1; then
    log "WARN" "Certbot not installed; skipping SSL issuance for ${domains_str}"
    return 0
  fi
  local cert_args
  cert_args=$(echo "$domains_str" | tr ',' ' ')
  if certbot --nginx --keep-until-expiring --redirect --non-interactive --agree-tos --email "${EMAIL}" $(printf ' -d %s' $cert_args); then
    log "INFO" "SSL certificate issued for: ${domains_str}"
  else
    log "WARN" "Certbot failed for ${domains_str}. Review ${LOG_FILE}"
  fi
}
# --------------------------- DOCKER MODE: write docker-compose.yml ---------------------------
write_docker_compose(){
  local site_tag=$(echo "${PRIMARY_DOMAIN}" | tr '.' '_')
  local stack_dir=/opt/${site_tag}
  local owner=${SUDO_USER:-root}
  local domain_csv="${DOMAIN_GROUPS[0]}"
  local domain_space=$(echo "$domain_csv" | tr ',' ' ')
  mkdir -p "${stack_dir}/nginx/conf.d" "${stack_dir}/www"
  cat >"${stack_dir}/docker-compose.yml" <<DOCKER
version: "3.8"
services:
  db:
    image: mariadb:11
    restart: unless-stopped
    environment:
      MARIADB_ROOT_PASSWORD: "${DB_ROOT_PASS}"
    volumes:
      - db_data:/var/lib/mysql

  phpmyadmin:
    image: phpmyadmin:latest
    restart: unless-stopped
    environment:
      PMA_HOST: db
      MYSQL_ROOT_PASSWORD: "${DB_ROOT_PASS}"
    ports:
      - "8080:80"

  web:
    image: nginx:stable
    restart: unless-stopped
    volumes:
      - ./www:/var/www/html:delegated
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - php
      - db

  php:
    image: php:${PHP_VERSION}-fpm
    restart: unless-stopped
    volumes:
      - ./www:/var/www/html

volumes:
  db_data:
DOCKER
  cat >"${stack_dir}/nginx/conf.d/${site_tag}.conf" <<NGINXDC
server {
  listen 80;
  server_name ${domain_space};
  root /var/www/html;
  index index.php index.html;

  location / {
    try_files \$uri \$uri/ =404;
  }

  location ~ \.php$ {
    fastcgi_pass php:9000;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /var/www/html\$fastcgi_script_name;
  }
}
NGINXDC
  cat >"${stack_dir}/www/index.php" <<'PHP'
<?php phpinfo();
PHP
  chown -R "$owner":"$owner" "${stack_dir}"
  log "INFO" "Docker compose stack written to ${stack_dir}"
  log "INFO" "Run: cd ${stack_dir} && docker compose up -d"
}
# --------------------------- MAIN FLOW ---------------------------
require_root
verify_prerequisites
parse_domain_groups "$DOMAINS_RAW"
detect_os
determine_web_user
check_system_resources
install_common
update_system_packages
enable_automatic_updates

case "$MODE" in
  native|docker)
    ;;
  *)
    die "Unsupported mode: $MODE"
    ;;
esac

if [ "$MODE" = "docker" ]; then
  log "INFO" "Setting up Docker mode"
  case "$OS_ID" in
    ubuntu|debian)
      apt-get remove -y docker docker-engine docker.io containerd runc || true
      curl -fsSL https://get.docker.com | sh
      apt-get install -y docker-compose-plugin
      systemctl enable --now docker
      ;;
    centos|rhel)
      curl -fsSL https://get.docker.com | sh
      yum install -y docker-compose-plugin || true
      systemctl enable --now docker
      ;;
  esac
  install_node
  write_docker_compose
  configure_firewall
  apply_ssh_hardening
  summary
  ensure_state_marker
  exit 0
fi

install_nginx
install_php
configure_php
install_database
configure_mysql_root_client
create_backup_tooling
install_phpmyadmin_native
install_node
install_fail2ban
install_certbot
configure_firewall
apply_ssh_hardening

for domain_csv in "${DOMAIN_GROUPS[@]}"; do
  log "INFO" "Configuring domain group: ${domain_csv}"
  generate_nginx_vhost "$domain_csv"
  obtain_ssl "$domain_csv"
done

verify_services
summary
ensure_state_marker
