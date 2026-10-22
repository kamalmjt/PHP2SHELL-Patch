# PHP2Shell Remediation Toolkit — CVE-2026-109618 & CVE-2026-109619

**Languages / Idiomas:** [English](#english) · [Español](#español)

---

## English

Comprehensive remediation and hardening toolkit for the PHP2Shell vulnerabilities **CVE-2026-109618** (OOM `longjmp` memory corruption in multipart parser) and **CVE-2026-109619** (cross-request stale global state in persistent workers).

`php2shellfix.sh` automates security hardening across Linux servers running **ISPConfig**, **HestiaCP**, **Plesk**, or **Standalone / Self-Hosted** environments (no control panel). It enforces server-wide and per-site configurations, audits installed binaries against official patch releases, hardens PHP-FPM pools and Apache `mod_php`, and performs real service restarts.

> [!IMPORTANT]
> **Definitive Fix vs. Configuration Mitigations:**
> Configuration mitigations (disabling upload progress, setting `php_admin_flag`, recycling workers) are **defensive stopgaps** that neutralize known exploitation vectors. The **only 100% complete fix** is upgrading PHP packages to the official security releases:
> - **PHP 8.2.35+**
> - **PHP 8.3.36+**
> - **PHP 8.4.27+**
> - **PHP 8.5.12+**
>
> For **legacy EOL PHP** (PHP 5.4 - 8.1), no official upstream binary patches exist. These configuration mitigations, paired with worker recycling and perimeter WAF/isolation, represent the primary line of defense.

### Contents

- [Features](#features)
- [Supported environments](#supported-environments)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Options](#options)
- [What the script does](#what-the-script-does)
- [Binary & Version Security Audit](#binary--version-security-audit)
- [Output and statuses](#output-and-statuses)
- [Safety](#safety)
- [Rollback](#rollback)
- [Verification](#verification)
- [Exit codes](#exit-codes)
- [Customisation](#customisation)
- [Disclaimer](#disclaimer)
- [License](#license)

### Features

- **Binary & Version Audit (CLI, FPM, mod_php):** Detects every PHP installation and flags versions below `8.2.35`, `8.3.36`, `8.4.27`, or `8.5.12` as `[VULNERABLE]`, alerting when legacy EOL PHP is detected. Binaries whose `php -v` reports `built:` on or after **Oct 21 2026** already include the backported fix (e.g. sury builds of PHP 7.x) and are reported as `[PATCHED - BACKPORT]`, regardless of version.
- **Base `php.ini` Hardening:** Enforces `session.upload_progress.enabled = 0` across all `php.ini` files and backup/staging copies (`php.ini.vst.back`, `php.ini.ucf-dist`).
- **PHP 8.5 Support:** Automatically enforces `fatal_error_backtraces = 0` on PHP 8.5 to block fatal error backtrace use-after-free vectors.
- **Persistent Drop-ins:** Deploys `99-php2shell.ini` into all `conf.d` / `php.d` directories so distro package updates cannot silently revert the fix.
- **PHP-FPM Pool Hardening (Plesk, Standalone, HestiaCP, ISPConfig):** Injects `php_admin_flag[session.upload_progress.enabled] = off` into templates and active domain pools, preventing `.user.ini` / `.htaccess` / `ini_set` overrides.
- **Worker Recycling (`pm.max_requests`):** Sets `pm.max_requests = 500` if currently 0 or unset, recycling workers to flush stale global state (CVE-2026-109619).
- **Global Apache `mod_php` Hardening:** Deploys global configuration with `php_admin_flag session.upload_progress.enabled off` for Apache on Debian/Ubuntu and RHEL/CentOS.
- **OOM Vulnerability Ratio Audit:** Compares `post_max_size` against `memory_limit` to identify CVE-2026-109618 request parsing traps.
- **Real Service Restarts:** Executes real, verified restarts of all active PHP-FPM services (including Plesk `plesk-php*-fpm`) and Apache/HTTPD to clear running worker memory.
- **Vhost Rebuild & Reporting:** Supports automatic vhost regeneration and logging across HestiaCP, Plesk, and ISPConfig.

### Supported environments

| Environment | What is covered |
|---|---|
| **Standalone / No Panel** | `/etc/php/*/{fpm,cli,apache2,cgi}/php.ini`, `/etc/php.ini`, `/etc/php.d`, `/etc/php-fpm.d/*.conf`, `/etc/php/*/fpm/pool.d/*.conf`, Remi SCL, Apache global conf |
| **Plesk** | `/opt/plesk/php/*/etc` (`php.ini`, `php.d`, `php-fpm.d/*.conf`), `/var/www/vhosts/system/*/{etc,conf}`, `plesk bin php_settings -u`, `plesk-php*-fpm` restarts |
| **HestiaCP** | Panel PHP (`/usr/local/hestia/php/lib/php.ini`), templates (`data/templates/web/php-fpm/*.tpl` and install multiphp copies), `v-rebuild-web-domain`, backend restarts |
| **ISPConfig** | Custom master templates (`server/conf-custom/php_fpm_pool.conf.master`), `/opt/php-*` extra versions, `datalogUpdate()` forced resync + `server.sh` |

### Requirements

- Linux, run as **root**.
- **Bash 4.4 or newer**, GNU coreutils/findutils (`realpath`, `stat -c`, `find -print0`), `perl`, `diff`, `timeout`.
- `systemctl` (or SysVinit `/etc/init.d/`) to restart PHP-FPM and Apache.
- ISPConfig: the `php` CLI (used for forced website resync).
- Plesk: the `plesk` command.

### Quick start

```bash
# Download
curl -fsSLO https://raw.githubusercontent.com/kamalmjt/PHP2SHELL-Patch/main/php2shellfix.sh
chmod +x php2shellfix.sh

# 1. Inspect what would change (dry-run, no changes made)
sudo ./php2shellfix.sh --dry-run

# 2. Apply hardening, pool locks, and restart services
sudo ./php2shellfix.sh
```

### Options

```text
Usage: php2shellfix.sh [OPTIONS] [PATH ...]

Options:
  -n, --dry-run          Show what would change without modifying anything
  --no-rebuild           Patch files, templates, and drop-ins, but do not rebuild vhosts
  --force-rebuild        Rebuild the vhosts even if nothing changed in this run
  --max-requests N       Set pm.max_requests in FPM pools if 0/unset (default: 500)
  --no-max-requests      Do not modify pm.max_requests in PHP-FPM pools
  --no-dropins           Do not create persistent 99-php2shell.ini drop-in files
  --no-oom-check         Skip post_max_size vs memory_limit OOM ratio audit
  -h, --help             Show help message and exit
```

Examples:

```bash
sudo ./php2shellfix.sh --dry-run                       # Safe preview of all actions
sudo ./php2shellfix.sh --max-requests 250              # Set worker recycle limit to 250 requests
sudo ./php2shellfix.sh --no-rebuild                    # Patch configs and restart without rebuilding vhosts
sudo ./php2shellfix.sh /etc/php/7.4                    # Target a specific legacy version
```

### Binary & Version Security Audit

During execution, `php2shellfix.sh` evaluates all discovered CLI binaries, FPM daemons, and Apache modules:

```text
================================================================================
 PHP ENVIRONMENT SECURITY AUDIT (CVE-2026-109618 & CVE-2026-109619)
================================================================================
  /usr/bin/php7.4                          7.4.33       [VULNERABLE - EOL] (No official upstream patch)
  /opt/plesk/php/8.2/bin/php               8.2.20       [VULNERABLE] (Requires update to >= 8.2.35)
  /opt/plesk/php/8.3/bin/php               8.3.36       [PATCHED]
================================================================================
```

### Safety & Rollback

- **Root verification & trusted paths:** Modifies only files owned by root in secure, untamperable paths.
- **In-place updates:** Preserves permissions, inode attributes, hard links, and SELinux contexts.
- **Timestamped backups:** Generates `<file>.bak.YYYYmmdd_HHMMSS` before modifying any file.
- **Full Rollback:**
  ```bash
  STAMP=20261021_120000   # Use the timestamp from the script execution
  find /etc /opt /usr/local /var/www /home -name "*.bak.$STAMP" 2>/dev/null | while IFS= read -r b; do
      cat -- "$b" > "${b%.bak.$STAMP}"
  done
  ```

---

## Español

Kit integral de remediación y bastionado contra las vulnerabilidades PHP2Shell **CVE-2026-109618** (corrupción de memoria OOM `longjmp` en el parseo multipart) y **CVE-2026-109619** (estado global residual entre peticiones sucesivas en workers persistentes).

`php2shellfix.sh` automatiza el aseguramiento de servidores Linux gestionados con **ISPConfig**, **HestiaCP**, **Plesk** o **Servidores independientes / Sin panel**. Aplica configuraciones globales y por sitio, audita versiones frente a parches oficiales, asegura los pools PHP-FPM y Apache `mod_php`, y realiza reinicios efectivos de servicios.

> [!IMPORTANT]
> **Solución definitiva vs. Mitigaciones de configuración:**
> Las medidas de configuración (desactivar upload progress, fijar `php_admin_flag`, reciclar workers) son **mitigaciones defensivas temporales**. La **única solución 100% definitiva** es actualizar los paquetes de PHP a las versiones oficiales corregidas:
> - **PHP 8.2.35+**
> - **PHP 8.3.36+**
> - **PHP 8.4.27+**
> - **PHP 8.5.12+**
>
> Para **versiones legacy EOL** (PHP 5.4 a 8.1), no existen parches binarios oficiales. Estas mitigaciones de configuración, junto al reciclaje de workers y WAF perimetral, son la defensa indispensable.

### Características

- **Auditoría de versiones (CLI, FPM, mod_php):** Comprueba cada binario y marca como `[VULNERABLE]` todo lo que esté por debajo de `8.2.35`, `8.3.36`, `8.4.27` o `8.5.12`, advirtiendo de software legacy EOL. Los binarios cuyo `php -v` indica `built:` del **21 de octubre de 2026** o posterior ya incluyen el parche backporteado (p. ej. builds de sury de PHP 7.x) y se marcan como `[PATCHED - BACKPORT]`, sea cual sea la versión.
- **Aseguramiento de `php.ini`:** Fija `session.upload_progress.enabled = 0` en todos los `php.ini` y copias de seguridad/plantilla (`php.ini.vst.back`, `php.ini.ucf-dist`).
- **Soporte para PHP 8.5:** En PHP 8.5, fija automáticamente `fatal_error_backtraces = 0` para bloquear el vector UAF de rastreo de errores fatales.
- **Drop-ins persistentes:** Instala `99-php2shell.ini` en todos los directorios `conf.d` / `php.d` para evitar que una actualización de paquetes de la distribución vuelva a activar la directiva.
- **Aseguramiento de pools PHP-FPM (Plesk, Standalone, HestiaCP, ISPConfig):** Inyecta `php_admin_flag[session.upload_progress.enabled] = off` en plantillas y pools reales de dominios, impidiendo que `.user.ini`, `.htaccess` o `ini_set()` lo reactiven.
- **Reciclaje de workers (`pm.max_requests`):** Configura `pm.max_requests = 500` (si está en 0 o sin definir) para obligar a reciclar procesos worker y eliminar memoria sucia residual (CVE-2026-109619).
- **Aseguramiento global de Apache `mod_php`:** Despliega configuración global de Apache con `php_admin_flag session.upload_progress.enabled off` en Debian/Ubuntu (`/etc/apache2/conf-available/`) y RHEL/CentOS (`/etc/httpd/conf.d/`).
- **Auditoría de ratio OOM:** Compara `post_max_size` frente a `memory_limit` para detectar trampas de memoria asociadas a CVE-2026-109618.
- **Reinicio real de servicios:** Reinicia de verdad todos los servicios activos de PHP-FPM (incluidos `plesk-php*-fpm` de Plesk) y Apache/HTTPD.
- **Regeneración de vhosts e informes:** Regenera vhosts e informa del estado en HestiaCP, Plesk e ISPConfig.

### Inicio rápido

```bash
# Descargar
curl -fsSLO https://raw.githubusercontent.com/kamalmjt/PHP2SHELL-Patch/main/php2shellfix.sh
chmod +x php2shellfix.sh

# 1. Comprobación en seco (dry-run, no modifica nada)
sudo ./php2shellfix.sh --dry-run

# 2. Aplicar el bastionado y reiniciar servicios
sudo ./php2shellfix.sh
```

### Opciones

```text
Uso: php2shellfix.sh [OPCIONES] [RUTA ...]

Opciones:
  -n, --dry-run          Muestra lo que cambiaría sin modificar nada
  --no-rebuild           Corrige ficheros, plantillas y drop-ins, pero no regenera vhosts
  --force-rebuild        Regenera vhosts aunque no haya habido cambios en la ejecución
  --max-requests N       Fija pm.max_requests en pools si está en 0/sin definir (defecto: 500)
  --no-max-requests      No modifica pm.max_requests en los pools PHP-FPM
  --no-dropins           No crea ficheros drop-in 99-php2shell.ini en conf.d/php.d
  --no-oom-check         Omite la auditoría de ratio post_max_size vs memory_limit
  -h, --help             Muestra la ayuda y sale
```

### Seguridad y Marcha Atrás

- Se crean copias de seguridad con marca de tiempo `<fichero>.bak.AAAAmmdd_HHMMSS` antes de modificar cualquier fichero.
- Para revertir los cambios de una ejecución:
  ```bash
  STAMP=20261021_120000   # Sustituir por la marca de tiempo de la ejecución
  find /etc /opt /usr/local /var/www /home -name "*.bak.$STAMP" 2>/dev/null | while IFS= read -r b; do
      cat -- "$b" > "${b%.bak.$STAMP}"
  done
  ```

### Licencia

[GNU General Public License v3.0](LICENSE).

**Autor:** Kamal Majaiti EL Majaiti
