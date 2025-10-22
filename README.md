# Automated Linux Server Setup

This project provides a fully automated Bash script to set up an enterprise-ready Linux server or Docker stack on **Debian**, **Ubuntu**, **CentOS**, or **RHEL**. The script installs, configures, and hardens all essential components for web hosting and applications while maintaining detailed audit logs.

## Features

- **Operating Systems**: Debian 12+, Ubuntu 20.04+, CentOS 7+, RHEL 7+
- **Installed & Configured Components**:

  - Nginx (web server)
  - PHP-FPM (configurable version, e.g., 8.2)
  - MariaDB / MySQL-compatible
  - phpMyAdmin
  - Node.js 20+
  - Fail2Ban (brute-force protection)
  - Firewall (UFW on Debian/Ubuntu, firewalld on CentOS/RHEL)
  - SSL certificates via Certbot (Let's Encrypt)
  - Automated MariaDB backups with daily cron job
  - Optional SSH hardening (disable password auth, restrict root login)
  - Automatic OS security updates (configurable)

- **Modes**:

  - `native`: installation directly on the host server
  - `docker`: Docker Compose stack with DB, Nginx, PHP-FPM, phpMyAdmin

- **Enterprise Enhancements**
  - Central execution log at `/var/log/enterprise-server-setup.log`
  - Multi-domain support with per-virtual-host isolation (`example.com,www.example.com;api.example.com`)
  - Automatic Nginx vhosts and HTTPS provisioning for every domain group
  - Non-interactive MariaDB setup with secure root credential storage in `/root/.my.cnf`
  - Docker support for instant containerized deployment

## Requirements

- Root access on the server (sudo)
- At least 1 GB RAM
- Internet connection
- Optional: domains pointing to the server

## Installation

### 1. Download the script

```bash
curl -fsSL https://example.com/automated-linux-server-setup.sh -o automated-linux-server-setup.sh
chmod +x automated-linux-server-setup.sh
```

### 2. Native Installation (without Docker)

Multiple domain groups are separated by semicolons (`;`). Domains within a group share the same virtual host and should be comma-separated (`example.com,www.example.com`).

```bash
sudo DOMAINS="example.com,www.example.com;api.example.com" \
     EMAIL="admin@example.com" \
     MODE=native \
     DB_ROOT_PASS="securepassword" \
     bash automated-linux-server-setup.sh
```

### 3. Docker Installation

```bash
sudo DOMAINS="example.com" \
     MODE=docker \
     DB_ROOT_PASS="securepassword" \
     bash automated-linux-server-setup.sh
```

After execution, the Docker Compose stack is located under `/opt/<domain>`.

Logs for every run are appended to `/var/log/enterprise-server-setup.log`. A lightweight state file is written to `/var/local/enterprise-server-setup/last-run` to help with auditing.

## Configuration

- **Web root**: `/var/www/<domain_group>/html` (native) or `/opt/<domain>/www` (docker)
- **MariaDB**: Root password is stored in `/root/.my.cnf` for safe automation access
- **phpMyAdmin**: Access via `/phpmyadmin` (native) or port 8080 for Docker
- **Nginx vhosts**: automatically generated for each domain group with HTTPS enforcement
- **PHP-FPM Socket**: `/var/run/php/php<version>-fpm.sock` (native)
- **Backups**: Daily cron at 02:00 writes dumps to `/var/backups/mariadb`

## Options

- `--domains` - semicolon-delimited domain groups; commas separate aliases within a group
- `--mode` - `native` or `docker` (default: native)
- `--email` - administrator email for SSL
- `--db-root-pass` - MariaDB root password
- `--php` - PHP version (default: 8.2)
- `--force` - overwrite existing configurations
- Environment toggles:
  - `ENABLE_AUTO_UPDATES=false` to skip unattended upgrades
  - `ENABLE_SSH_HARDENING=true` to enforce key-based SSH authentication

## Security Measures

- Fail2Ban to protect against brute-force attacks (with hardened jail profiles)
- Firewall configuration (UFW/firewalld) on standard ports plus phpMyAdmin (8080)
- SSL certificates via Let's Encrypt with automatic HTTP→HTTPS redirect
- Non-interactive MariaDB setup removes insecure defaults and stores credentials securely
- Automated daily database dumps with retention policy (14 days)
- Optional SSH hardening and unattended OS updates

## Next Steps

1. Review `/var/log/enterprise-server-setup.log` for the full execution transcript.
2. Place your website files in the web root: `/var/www/<domain>/html` or `/opt/<domain>/www`.
3. Validate services: `nginx -t`, `systemctl status php<version>-fpm`, and `systemctl status mariadb` (native).
4. Access MariaDB using the stored credentials: `mysql --defaults-file=/root/.my.cnf`.
5. Access phpMyAdmin: `https://<domain>/phpmyadmin` (native) or `http://<server_ip>:8080` (Docker).

## Support & Issues

If you encounter problems, please open an issue on GitHub or contact the administrator.

**Note:** The script is intended for production environments. Test it first in a safe environment. Optional adjustments can include specific security policies, SELinux, load balancers, or CI/CD integration.
