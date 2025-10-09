#!/usr/bin/env bash
# Automated Linux Server Setup
# Supports: Debian (12+), Ubuntu (20.04+), CentOS (7+), RHEL (7+)
# Installs and configures: Nginx, PHP-FPM, MariaDB (MySQL-compatible), phpMyAdmin,
# Node.js, Fail2Ban, firewall (UFW or firewalld), Certbot (Let's Encrypt)
# Supports: single or multiple domains; two modes: "native" (install on host) or "docker" (deploy via Docker Compose)
# Usage: curl -fsSL https://example.com/automated-linux-server-setup.sh | sudo DOMAIN=example.com MODE=native bash
# or: sudo bash automated-linux-server-setup.sh --domains "example.com,www.example.com" --mode docker

set -euo pipefail
IFS=$'\n\t'

# --------------------------- CONFIG (edit / pass env vars) ---------------------------
# Example environment variables (can be passed before running the script):
# DOMAIN (single) or DOMAINS (comma-separated)
# MODE: native | docker (default: native)
# EMAIL: admin@example.com  (for Let's Encrypt)
# DB_ROOT_PASS: secure_root_password
# WEB_USER: www-data (default for Debian/Ubuntu), nginx for CentOS/RHEL will be adjusted
# PHP_VERSION: 8.2 (adjustable)

# Parse args (simple)
DOMAINS=""
MODE="native"
EMAIL=""
DB_ROOT_PASS=""
PHP_VERSION="8.2"
FORCE=false

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --domains) DOMAINS="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;;
    --email) EMAIL="$2"; shift 2;;
    --db-root-pass) DB_ROOT_PASS="$2"; shift 2;;
    --php) PHP_VERSION="$2"; shift 2;;
    --force) FORCE=true; shift 1;;
    --help) echo "Usage: $0 [--domains \"a.com,b.com\"] [--mode native|docker] [--email admin@...]"; exit 0;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

# Allow env-provided DOMAIN / DOMAINS
if [ -n "${DOMAIN-}" ] && [ -z "$DOMAINS" ]; then
  DOMAINS="$DOMAIN"
fi
if [ -n "${DOMAINS-}" ]; then
  # normalize commas -> spaces
  IFS=',' read -r -a DOMAIN_ARRAY <<< "$DOMAINS"
else
  echo "ERROR: No domains provided. Provide via DOMAINS env or --domains. Exiting." >&2
  exit 1
fi

if [ -n "${EMAIL-}" ]; then
  : # keep
fi

if [ -z "$DB_ROOT_PASS" ]; then
  # generate a random one but show the user
  DB_ROOT_PASS=$(openssl rand -base64 18)
  echo "[INFO] No DB root password provided; generated: $DB_ROOT_PASS"
fi

# --------------------------- UTILS ---------------------------
log(){ echo -e "[INFO] $*"; }
err(){ echo -e "[ERROR] $*" >&2; }

detect_os(){
  . /etc/os-release || true
  OS_ID=${ID,,}
  OS_LIKE=${ID_LIKE,,}
  OS_VERSION=${VERSION_ID,,}
  log "Detected OS: $OS_ID (like: $OS_LIKE) version: $OS_VERSION"
}

require_root(){
  if [ "$EUID" -ne 0 ]; then
    err "This script must be run as root. Retry with sudo."; exit 1
  fi
}

# --------------------------- INSTALL COMMON TOOLS ---------------------------
install_common(){
  case "$OS_ID" in
    ubuntu|debian)
      apt-get update
      apt-get install -y ca-certificates curl wget gnupg lsb-release software-properties-common unzip git openssh-server
      ;;
    centos|rhel)
      yum install -y epel-release yum-utils curl wget unzip git openssh-server
      systemctl enable --now sshd || true
      ;;
    *)
      err "Unsupported OS: $OS_ID"; exit 1
      ;;
  esac
}

# --------------------------- PACKAGE INSTALLERS ---------------------------
install_node(){
  NODE_VERSION=20
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
  case "$OS_ID" in
    ubuntu|debian)
      # use sury PPA for latest PHP
      apt-get install -y lsb-release ca-certificates apt-transport-https
      curl -fsSL https://packages.sury.org/php/apt.gpg | apt-key add -
      echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list
      apt-get update
      apt-get install -y php${PHP_VERSION} php${PHP_VERSION}-fpm php${PHP_VERSION}-mysql php${PHP_VERSION}-cli php${PHP_VERSION}-curl php${PHP_VERSION}-gd php${PHP_VERSION}-mbstring php${PHP_VERSION}-xml php${PHP_VERSION}-zip
      ;;
    centos|rhel)
      # Remi repo for PHP
      yum install -y https://rpms.remirepo.net/enterprise/remi-release-${OS_VERSION}.rpm || true
      yum install -y yum-utils
      yum-config-manager --enable remi-php82 || true
      yum install -y php php-fpm php-mysqlnd php-cli php-curl php-gd php-mbstring php-xml php-zip
      ;;
  esac
}

install_database(){
  case "$OS_ID" in
    ubuntu|debian)
      DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client
      systemctl enable --now mariadb
      ;;
    centos|rhel)
      yum install -y mariadb-server mariadb
      systemctl enable --now mariadb
      ;;
  esac
  # Secure installation (non-interactive)
  mysql --user=root <<MYSQL_SECURE
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
FLUSH PRIVILEGES;
MYSQL_SECURE
  log "MariaDB configured with provided root password"
}

install_nginx(){
  case "$OS_ID" in
    ubuntu|debian)
      apt-get install -y nginx
      systemctl enable --now nginx
      ;;
    centos|rhel)
      yum install -y nginx
      systemctl enable --now nginx
      ;;
  esac
}

install_phpmyadmin_native(){
  case "$OS_ID" in
    ubuntu|debian)
      apt-get install -y phpmyadmin
      # phpmyadmin package may prompt; we assume noninteractive
      ;;
    centos|rhel)
      # no default package; install manual
      PHP_MYADMIN_DIR=/usr/share/phpmyadmin
      mkdir -p $PHP_MYADMIN_DIR
      wget -qO- https://files.phpmyadmin.net/phpMyAdmin/latest/phpMyAdmin-latest-all-languages.tar.gz | tar xz --strip-components=1 -C $PHP_MYADMIN_DIR
      mkdir -p /var/lib/phpmyadmin/tmp
      chown -R root:root $PHP_MYADMIN_DIR
      ;;
  esac
}

install_fail2ban(){
  case "$OS_ID" in
    ubuntu|debian)
      apt-get install -y fail2ban
      systemctl enable --now fail2ban
      ;;
    centos|rhel)
      yum install -y fail2ban
      systemctl enable --now fail2ban
      ;;
  esac
}

install_certbot(){
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
  case "$OS_ID" in
    ubuntu|debian)
      # UFW
      apt-get install -y ufw
      ufw default deny incoming
      ufw default allow outgoing
      ufw allow OpenSSH
      ufw allow 'Nginx Full'
      ufw --force enable
      ;;
    centos|rhel)
      # firewalld
      yum install -y firewalld || true
      systemctl enable --now firewalld
      firewall-cmd --permanent --add-service=http
      firewall-cmd --permanent --add-service=https
      firewall-cmd --permanent --add-service=ssh
      firewall-cmd --reload
      ;;
  esac
}

# --------------------------- NGINX VHOST GENERATOR ---------------------------
generate_nginx_vhost(){
  server_names="$1"
  site_name=$(echo $server_names | tr ' ' '_' | tr ',' '_')
  root_dir="/var/www/${site_name}/html"
  mkdir -p "$root_dir"
  chown -R www-data:www-data "$root_dir" || chown -R nginx:nginx "$root_dir" || true
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
        try_files \$uri \$uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
NGINXCONF
  # enable
  if [ -d /etc/nginx/sites-enabled ]; then
    ln -sf /etc/nginx/sites-available/${site_name}.conf /etc/nginx/sites-enabled/${site_name}.conf
  else
    # on some systems nginx uses conf.d
    cp /etc/nginx/sites-available/${site_name}.conf /etc/nginx/conf.d/${site_name}.conf
  fi
  systemctl reload nginx || true
  log "Generated Nginx vhost for: ${server_names} at ${root_dir}"
}

# --------------------------- SSL (Let’s Encrypt) ---------------------------
obtain_ssl(){
  domains_str="$1"
  primary=$(echo $domains_str | awk -F',' '{print $1}')
  if [ -z "${EMAIL}" ]; then
    EMAIL="admin@${primary}"
  fi
  certbot --nginx -d $(echo $domains_str | tr ',' ' -d ') --non-interactive --agree-tos --email ${EMAIL} || {
    err "Certbot failed for $domains_str"; return 1
  }
  log "SSL certificate issued for: $domains_str"
}

# --------------------------- DOCKER MODE: write docker-compose.yml ---------------------------
write_docker_compose(){
  site_tag=$(echo ${DOMAIN_ARRAY[0]} | tr '.' '_')
  mkdir -p /opt/${site_tag}
  cat > /opt/${site_tag}/docker-compose.yml <<DOCKER
version: '3.8'
services:
  db:
    image: mariadb:11
    restart: unless-stopped
    environment:
      MARIADB_ROOT_PASSWORD: ${DB_ROOT_PASS}
    volumes:
      - db_data:/var/lib/mysql

  phpmyadmin:
    image: phpmyadmin:latest
    restart: unless-stopped
    environment:
      PMA_HOST: db
      MYSQL_ROOT_PASSWORD: ${DB_ROOT_PASS}
    ports:
      - "8080:80"

  web:
    image: nginx:stable
    volumes:
      - ./www:/var/www/html:delegated
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - php

  php:
    image: php:${PHP_VERSION}-fpm
    volumes:
      - ./www:/var/www/html

volumes:
  db_data:
DOCKER
  cat > /opt/${site_tag}/nginx/conf.d/${site_tag}.conf <<NGINXDC
server {
  listen 80;
  server_name ${DOMAINS//,/ };
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
  mkdir -p /opt/${site_tag}/www
  chown -R $SUDO_USER:${SUDO_USER:-root} /opt/${site_tag}
  log "Docker compose written to /opt/${site_tag}"
}

# --------------------------- MAIN FLOW ---------------------------
require_root
detect_os
install_common

if [ "$MODE" = "docker" ]; then
  log "Setting up Docker mode"
  # Install Docker
  case "$OS_ID" in
    ubuntu|debian)
      apt-get remove -y docker docker-engine docker.io containerd runc || true
      curl -fsSL https://get.docker.com | sh
      apt-get install -y docker-compose-plugin
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
  log "Docker-based stack prepared. You can now: cd /opt/... && docker compose up -d"
  exit 0
fi

# Native installations
install_nginx
install_php
install_database
install_phpmyadmin_native
install_node
install_fail2ban
install_certbot
configure_firewall

# Create vhosts for each domain group (we will create one vhost per provided comma-group)
for domain_csv in "${DOMAINS}"; do
  # for now treat the whole CSV as one set; if multiple groups were desired, user can supply multiple --domains
  generate_nginx_vhost "$domain_csv"
  obtain_ssl "$domain_csv" || log "Skipping SSL for $domain_csv"
done

# Final notes
log "Setup complete. Web root(s) under /var/www. MariaDB root password: ${DB_ROOT_PASS}"
log "phpMyAdmin may be available at /phpmyadmin or via docker port 8080 depending on installation."

# Helpful commands
cat <<EOF

NEXT STEPS:
 - Place your website files into the web root(s): /var/www/<domain_group>/html
 - Check nginx config: nginx -t
 - Check php-fpm: systemctl status php${PHP_VERSION}-fpm
 - Manage MariaDB: mysql -u root -p

EOF
