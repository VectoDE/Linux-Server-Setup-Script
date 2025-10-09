# Automated Linux Server Setup

This project provides a fully automated Bash script to set up a production-ready Linux server or Docker stack on **Debian**, **Ubuntu**, **CentOS**, or **RHEL**. The script installs and configures all essential components for web hosting and applications.

## Features

- **Operating Systems**: Debian 12+, Ubuntu 20.04+, CentOS 7+, RHEL 7+
- **Installed Components**:

  - Nginx (web server)
  - PHP-FPM (configurable version, e.g., 8.2)
  - MariaDB / MySQL-compatible
  - phpMyAdmin
  - Node.js 20+
  - Fail2Ban (brute-force protection)
  - Firewall (UFW on Debian/Ubuntu, firewalld on CentOS/RHEL)
  - SSL certificates via Certbot (Let's Encrypt)

- **Modes**:

  - `native`: installation directly on the host server
  - `docker`: Docker Compose stack with DB, Nginx, PHP-FPM, phpMyAdmin

- **Multi-Domain Support**: single or multiple domains can be configured simultaneously
- **Automatic Nginx vhosts** for each domain
- **Non-interactive MariaDB setup** with root password
- **Docker support** for instant containerized deployment

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

```bash
sudo DOMAINS="example.com,www.example.com" \
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

## Configuration

- **Web root**: `/var/www/<domain_group>/html` (native) or `/opt/<domain>/www` (docker)
- **MariaDB**: Root password is set automatically, default user `root`
- **phpMyAdmin**: Access via `/phpmyadmin` or port 8080 for Docker
- **Nginx vhosts**: automatically generated for each domain group
- **PHP-FPM Socket**: `/var/run/php/php<version>-fpm.sock` (native)

## Options

- `--domains` - comma-separated domains
- `--mode` - `native` or `docker` (default: native)
- `--email` - administrator email for SSL
- `--db-root-pass` - MariaDB root password
- `--php` - PHP version (default: 8.2)
- `--force` - overwrite existing configurations

## Security Measures

- Fail2Ban to protect against brute-force attacks
- Firewall configuration (UFW/firewalld) on standard ports
- SSL certificates via Let's Encrypt
- Non-interactive MariaDB setup removes insecure defaults

## Next Steps

1. Place your website files in the web root: `/var/www/<domain>/html` or `/opt/<domain>/www`
2. Check Nginx configuration: `nginx -t`
3. Check PHP-FPM: `systemctl status php<version>-fpm`
4. Access MariaDB: `mysql -u root -p`
5. Access phpMyAdmin: `http://<domain>/phpmyadmin` (native) or `http://<server_ip>:8080` (Docker)

## Support & Issues

If you encounter problems, please open an issue on GitHub or contact the administrator.

**Note:** The script is intended for production environments. Test it first in a safe environment. Optional adjustments can include specific security policies, SELinux, load balancers, or CI/CD integration.
