# PHP2Shell Remediation Toolkit — CVE-2026-109618 & CVE-2026-109619

**Languages / Idiomas:** [English](#english) · [Español](#español)

---

## English

Remediation script for the PHP2Shell vulnerabilities **CVE-2026-109618** and **CVE-2026-109619**.
`php2shellfix.sh` disables `session.upload_progress.enabled` in every PHP configuration it finds on a
Linux server and, on **HestiaCP**, **Plesk** and **ISPConfig**, also in the per-site configuration of
every vhost, then regenerates the sites and reports the result for each one.

> **Why this directive?** When `session.upload_progress.enabled` is not set, PHP uses its built-in
> default, which is **On**. The script therefore does not only fix lines that enable it: it adds
> `session.upload_progress.enabled = 0` to every `php.ini` where it is missing.

### Contents

- [Features](#features)
- [Supported environments](#supported-environments)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Options](#options)
- [What the script does](#what-the-script-does)
- [Output and statuses](#output-and-statuses)
- [Safety](#safety)
- [Rollback](#rollback)
- [Verification](#verification)
- [Exit codes](#exit-codes)
- [Customisation](#customisation)
- [Disclaimer](#disclaimer)
- [License](#license)

### Features

- Patches every `php.ini` (and the `php.ini.vst.back` / `php.ini.ucf-dist` copies, so a restore or a
  package upgrade cannot bring the setting back).
- Fixes drop-in `.ini` files (`conf.d`, `php.d`) that re-enable it.
- Hardens the panels' PHP-FPM pool templates with
  `php_admin_flag[session.upload_progress.enabled] = off`, which also prevents sites from turning it
  back on through `.user.ini` or `ini_set()`.
- Rebuilds every vhost with the panel's own tools and writes a per-site report.
- Reports (without touching) pools, vhosts, nginx `PHP_VALUE`, `.user.ini` and `.htaccess` lines that
  re-enable it.
- Runs `php-fpm -t` and `php-fpm -i` on every PHP-FPM binary to show the effective value.
- `--dry-run` mode with unified diffs; timestamped backup of every modified file.

### Supported environments

| Environment | What is covered |
|---|---|
| **Self-hosted** | Debian/Ubuntu `/etc/php/*/{fpm,cli,apache2,cgi,phpdbg}/php.ini`; RHEL `/etc/php.ini`, `/etc/php.d`, `/etc/php-fpm.d`; Alpine `/etc/phpXY`; Remi SCL `/etc/opt/remi/phpXY`; legacy `/etc/php5` |
| **HestiaCP** | Panel PHP (`/usr/local/hestia/php/lib/php.ini`), PHP-FPM templates (`data/templates/web/php-fpm/*.tpl` and the install copies), users' web roots and per-domain configs (`/home/*/web`, `/home/*/conf/web`) |
| **Plesk** | `/opt/plesk/php/*/etc` (`php.ini`, `php.d`, `php-fpm.d`) and per-domain `/var/www/vhosts/system/*/{etc,conf}`. The panel's own `php.ini` (sw-engine) is excluded |
| **ISPConfig** | Per-site `php.ini` in `/var/www/conf`, pools in `pool.d`, `*.vhost` files, `*.master` templates in `/usr/local/ispconfig/server/conf{,-custom}`, extra PHP versions in `/opt` |

Pseudo filesystems, container storage (Docker, containerd, LXC/LXD), snaps, mail and backup
directories are never traversed.

### Requirements

- Linux, run as **root**.
- **Bash 4.4 or newer** (the script uses `mapfile`, associative arrays and negative array indexes),
  GNU coreutils/findutils (`realpath`, `stat -c`, `find -print0`), `perl`, `diff`, `timeout`.
- `systemctl` is used to reload PHP-FPM when available.
- ISPConfig: the `php` CLI (used to queue the website resync).
- Plesk: the `plesk` command.

### Quick start

```bash
# Download
curl -fsSLO https://raw.githubusercontent.com/kamalmjt/PHP2SHELL-Patch/main/php2shellfix.sh
chmod +x php2shellfix.sh

# 1. See what would change (nothing is modified)
sudo ./php2shellfix.sh --dry-run

# 2. Apply
sudo ./php2shellfix.sh
```

Always read the script and run `--dry-run` first on production servers, and make sure you have backups.

### Options

```text
Usage: php2shellfix.sh [--dry-run] [--no-rebuild | --force-rebuild] [PATH ...]
```

| Option | Description |
|---|---|
| `-n`, `--dry-run` | Show what would change (diffs, sites to rebuild) without touching anything |
| `--no-rebuild` | Patch files and vhost templates, but do not rebuild the vhosts |
| `--force-rebuild` | Rebuild the vhosts even if nothing changed in this run (by default they are rebuilt only when something changed) |
| `PATH ...` | Only process these directories: no templates, no rebuild. Useful for package hooks. Default: `/etc /opt /usr/local /var/www`, plus `/home/*/web` and `/home/*/conf/web` on HestiaCP |
| `-h`, `--help` | Show help |

Examples:

```bash
sudo ./php2shellfix.sh --no-rebuild            # patch now, rebuild the sites later
sudo ./php2shellfix.sh --force-rebuild         # re-run the rebuild and the per-site report
sudo ./php2shellfix.sh /etc/php/8.3            # only one PHP version (e.g. from an apt hook)
```

### What the script does

1. **`php.ini`** — sets the directive to `0`. If it is commented out it is uncommented as `0`; if it is
   missing it is added under `[Session]` (or at the top of the file). The same applies to the copies
   listed in `INI_NAMES`.
2. **Other `*.ini` files** — active lines that enable it are set to `0` (`conf.d` / `php.d` drop-ins).
3. **Vhost templates** (panel mode only) — PHP-FPM pool templates get
   `php_admin_flag[session.upload_progress.enabled] = off`:
   - **HestiaCP:** `data/templates/web/php-fpm/*.tpl` and the install copies used by
     `v-add-web-php` / `v-update-web-templates`.
   - **ISPConfig:** `server/conf-custom/php_fpm_pool.conf.master` (created from `server/conf/` if it
     does not exist, so ISPConfig updates do not overwrite it).
   - **Plesk:** has no server-wide pool template; the per-domain `php.ini` is generated from the
     handler `php.ini` patched in step 1.
4. **Rebuild** (when something changed, or with `--force-rebuild`) — regenerates every vhost and checks
   each site:
   - **HestiaCP:** `v-rebuild-web-domain` for each domain, then `v-restart-web-backend`,
     `v-restart-web` and `v-restart-proxy`.
   - **Plesk:** `plesk bin php_settings -u` and a PHP-FPM reload.
   - **ISPConfig:** queues a resync of every website (the same as *Tools › Resync*) and runs
     `server.sh` to apply it.
5. **Report only** — `*.conf`, `*.vhost`, `*.tpl`, `*.master`, `.user.ini` and `.htaccess` lines that
   re-enable it are listed for manual review.
6. **Check** — runs `php-fpm -t` and `php-fpm -i` on every PHP-FPM binary found.

### Output and statuses

Per file:

| Status | Meaning |
|---|---|
| `MODIFIED` / `WOULD CHANGE` | The file was (or would be) changed; the backup path is shown |
| `OK` | Already disabled / template already enforces it |
| `CREATED` | ISPConfig custom template created from the default one |
| `REVIEW` | Not owned by root or its path is writable by other users: left untouched |
| `SKIPPED` | Not writable (read-only filesystem) or template without an active pool section |
| `EXCLUDED` | Listed in `EXCLUDE`: left untouched |
| `ERROR` | Could not be processed; the original was restored from the backup |

Per site (rebuild step):

| Status | Meaning |
|---|---|
| `OK` | Rebuilt and the generated configuration disables the directive |
| `CHECK` | Rebuilt, but something needs a manual look (no pool found, pool re-enables it…) |
| `PENDING` | ISPConfig: the job is still in the queue (see *Monitor › Jobqueue*) |
| `FAILED` | The panel command failed |

The per-site report is also written to `/var/log/php2shellfix-YYYYmmdd_HHMMSS.log`.

### Safety

- Only writes to **root-owned** files whose path cannot be altered by another user (no directory in the
  path is writable by others, unless it is sticky).
- Never writes to the paths listed in `EXCLUDE`.
- Files are rewritten **in place** (same inode): owner, permissions, SELinux context and hard links are
  kept. CRLF line endings are preserved.
- Before every change a backup is created next to the file: `<file>.bak.YYYYmmdd_HHMMSS`.
- Only PHP-FPM binaries that are root-owned and in a trusted path are executed.
- Pool templates whose pool section is commented out (e.g. Hestia `no-php.tpl`) are left alone, so
  PHP-FPM cannot fail to start because of a line outside a `[pool]` section.

### Rollback

Every modified file has a backup with the same timestamp. To restore them all from one run:

```bash
STAMP=20261021_120000   # timestamp printed by the script ("backup: ...")
find /etc /opt /usr/local /var/www /home -name "*.bak.$STAMP" 2>/dev/null | while IFS= read -r b; do
    cat -- "$b" > "${b%.bak.$STAMP}"
done
```

Then rebuild the vhosts from the panel and reload PHP-FPM / the web server.

### Verification

```bash
php -i | grep session.upload_progress.enabled          # CLI
php-fpm8.3 -i | grep session.upload_progress.enabled   # each FPM version
```

The last section of the script output already shows the value for every PHP-FPM binary. Note that it
does not include pool overrides; the per-site report covers those.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Not run as root, no valid search path, a file error, or a site rebuild `FAILED` |
| `2` | Invalid option |

### Customisation

Variables at the top of the script:

| Variable | Purpose |
|---|---|
| `INI_NAMES` | `php.ini` file names to enforce (add other copies here) |
| `DEFAULT_ROOTS` | Directories searched when no `PATH` is given |
| `EXCLUDE` | Files that are never modified (by default the Plesk panel's own `php.ini`) |
| `PRUNE` | Directories that are never traversed |
| `HESTIA` (env) | HestiaCP install directory (default `/usr/local/hestia`) |

### Disclaimer

This script is provided **"AS IS"**, without warranty of any kind, express or implied. The author takes
no responsibility and accepts no liability for the use or misuse of this script, nor for any damage,
data loss, service interruption or any other consequence arising from its use. You use it entirely at
your own risk: review the code, run it with `--dry-run` first and make sure you have backups.

### License

[GNU General Public License v3.0](LICENSE).

**Author:** Kamal Majaiti EL Majaiti

---

## Español

Script de remediación para las vulnerabilidades PHP2Shell **CVE-2026-109618** y **CVE-2026-109619**.
`php2shellfix.sh` desactiva `session.upload_progress.enabled` en toda la configuración de PHP que
encuentra en un servidor Linux y, en **HestiaCP**, **Plesk** e **ISPConfig**, también en la
configuración de cada vhost; después regenera los sitios e informa del resultado de cada uno.

> **¿Por qué esta directiva?** Si `session.upload_progress.enabled` no está definida, PHP usa su valor
> por defecto, que es **On**. Por eso el script no solo corrige las líneas que la activan: añade
> `session.upload_progress.enabled = 0` en cada `php.ini` donde falta.

### Índice

- [Características](#características)
- [Entornos soportados](#entornos-soportados)
- [Requisitos](#requisitos)
- [Inicio rápido](#inicio-rápido)
- [Opciones](#opciones)
- [Qué hace el script](#qué-hace-el-script)
- [Salida y estados](#salida-y-estados)
- [Seguridad](#seguridad)
- [Marcha atrás](#marcha-atrás)
- [Verificación](#verificación)
- [Códigos de salida](#códigos-de-salida)
- [Personalización](#personalización)
- [Aviso legal](#aviso-legal)
- [Licencia](#licencia)

### Características

- Corrige todos los `php.ini` (y las copias `php.ini.vst.back` / `php.ini.ucf-dist`, para que una
  restauración o una actualización de paquetes no vuelva a activarla).
- Corrige los `.ini` adicionales (`conf.d`, `php.d`) que la reactivan.
- Refuerza las plantillas de pool PHP-FPM de los paneles con
  `php_admin_flag[session.upload_progress.enabled] = off`, lo que además impide que los sitios la
  vuelvan a activar mediante `.user.ini` o `ini_set()`.
- Regenera todos los vhosts con las herramientas del propio panel y genera un informe por sitio.
- Informa (sin modificar) de las líneas en pools, vhosts, `PHP_VALUE` de nginx, `.user.ini` y
  `.htaccess` que la reactivan.
- Ejecuta `php-fpm -t` y `php-fpm -i` en cada binario PHP-FPM para mostrar el valor efectivo.
- Modo `--dry-run` con diffs unificados; copia de seguridad con fecha de cada fichero modificado.

### Entornos soportados

| Entorno | Qué cubre |
|---|---|
| **Servidor propio** | Debian/Ubuntu `/etc/php/*/{fpm,cli,apache2,cgi,phpdbg}/php.ini`; RHEL `/etc/php.ini`, `/etc/php.d`, `/etc/php-fpm.d`; Alpine `/etc/phpXY`; Remi SCL `/etc/opt/remi/phpXY`; antiguo `/etc/php5` |
| **HestiaCP** | PHP del panel (`/usr/local/hestia/php/lib/php.ini`), plantillas PHP-FPM (`data/templates/web/php-fpm/*.tpl` y las copias de instalación), webs de los usuarios y configuración por dominio (`/home/*/web`, `/home/*/conf/web`) |
| **Plesk** | `/opt/plesk/php/*/etc` (`php.ini`, `php.d`, `php-fpm.d`) y por dominio `/var/www/vhosts/system/*/{etc,conf}`. El `php.ini` del propio panel (sw-engine) queda excluido |
| **ISPConfig** | `php.ini` por sitio en `/var/www/conf`, pools en `pool.d`, ficheros `*.vhost`, plantillas `*.master` en `/usr/local/ispconfig/server/conf{,-custom}`, versiones PHP adicionales en `/opt` |

Nunca se recorren sistemas de ficheros virtuales, almacenamiento de contenedores (Docker, containerd,
LXC/LXD), snaps, correo ni directorios de copias de seguridad.

### Requisitos

- Linux, ejecutado como **root**.
- **Bash 4.4 o superior** (usa `mapfile`, arrays asociativos e índices negativos), GNU
  coreutils/findutils (`realpath`, `stat -c`, `find -print0`), `perl`, `diff`, `timeout`.
- Se usa `systemctl` para recargar PHP-FPM si está disponible.
- ISPConfig: la CLI `php` (para encolar la resincronización de los sitios).
- Plesk: el comando `plesk`.

### Inicio rápido

```bash
# Descargar
curl -fsSLO https://raw.githubusercontent.com/kamalmjt/PHP2SHELL-Patch/main/php2shellfix.sh
chmod +x php2shellfix.sh

# 1. Ver qué cambiaría (no se modifica nada)
sudo ./php2shellfix.sh --dry-run

# 2. Aplicar
sudo ./php2shellfix.sh
```

En servidores de producción, lee siempre el script y ejecuta primero `--dry-run`, y asegúrate de tener
copias de seguridad.

### Opciones

```text
Uso: php2shellfix.sh [--dry-run] [--no-rebuild | --force-rebuild] [RUTA ...]
```

| Opción | Descripción |
|---|---|
| `-n`, `--dry-run` | Muestra lo que cambiaría (diffs, sitios a regenerar) sin tocar nada |
| `--no-rebuild` | Corrige ficheros y plantillas, pero no regenera los vhosts |
| `--force-rebuild` | Regenera los vhosts aunque no haya cambiado nada en esta ejecución (por defecto solo se regeneran si hubo cambios) |
| `RUTA ...` | Procesa solo esos directorios: sin plantillas ni regeneración. Útil en hooks de paquetes. Por defecto: `/etc /opt /usr/local /var/www`, más `/home/*/web` y `/home/*/conf/web` en HestiaCP |
| `-h`, `--help` | Muestra la ayuda |

Ejemplos:

```bash
sudo ./php2shellfix.sh --no-rebuild            # corregir ahora, regenerar los sitios más tarde
sudo ./php2shellfix.sh --force-rebuild         # repetir la regeneración y el informe por sitio
sudo ./php2shellfix.sh /etc/php/8.3            # solo una versión de PHP (p. ej. desde un hook de apt)
```

### Qué hace el script

1. **`php.ini`** — pone la directiva a `0`. Si está comentada, la descomenta como `0`; si no existe, la
   añade bajo `[Session]` (o al principio del fichero). Lo mismo para las copias de `INI_NAMES`.
2. **Otros `*.ini`** — las líneas activas que la habilitan pasan a `0` (`conf.d` / `php.d`).
3. **Plantillas de vhost** (solo en modo panel) — las plantillas de pool PHP-FPM reciben
   `php_admin_flag[session.upload_progress.enabled] = off`:
   - **HestiaCP:** `data/templates/web/php-fpm/*.tpl` y las copias de instalación que usan
     `v-add-web-php` / `v-update-web-templates`.
   - **ISPConfig:** `server/conf-custom/php_fpm_pool.conf.master` (se crea a partir de `server/conf/`
     si no existe, para que las actualizaciones de ISPConfig no la sobrescriban).
   - **Plesk:** no tiene plantilla de pool global; el `php.ini` de cada dominio se genera a partir del
     `php.ini` del handler corregido en el paso 1.
4. **Regeneración** (si hubo cambios, o con `--force-rebuild`) — regenera todos los vhosts y comprueba
   cada sitio:
   - **HestiaCP:** `v-rebuild-web-domain` por dominio y después `v-restart-web-backend`,
     `v-restart-web` y `v-restart-proxy`.
   - **Plesk:** `plesk bin php_settings -u` y recarga de PHP-FPM.
   - **ISPConfig:** encola una resincronización de todos los sitios (igual que *Herramientas ›
     Resincronizar*) y ejecuta `server.sh` para aplicarla.
5. **Solo informe** — se listan para revisión manual las líneas de `*.conf`, `*.vhost`, `*.tpl`,
   `*.master`, `.user.ini` y `.htaccess` que la reactivan.
6. **Comprobación** — ejecuta `php-fpm -t` y `php-fpm -i` en cada binario PHP-FPM encontrado.

### Salida y estados

Por fichero:

| Estado | Significado |
|---|---|
| `MODIFIED` / `WOULD CHANGE` | El fichero se ha modificado (o se modificaría); se muestra la ruta de la copia |
| `OK` | Ya estaba desactivada / la plantilla ya la fuerza |
| `CREATED` | Plantilla personalizada de ISPConfig creada a partir de la original |
| `REVIEW` | No pertenece a root o su ruta es escribible por otros usuarios: no se toca |
| `SKIPPED` | No escribible (sistema de ficheros de solo lectura) o plantilla sin sección de pool activa |
| `EXCLUDED` | Incluido en `EXCLUDE`: no se toca |
| `ERROR` | No se pudo procesar; se restauró el original desde la copia |

Por sitio (paso de regeneración):

| Estado | Significado |
|---|---|
| `OK` | Regenerado y la configuración generada desactiva la directiva |
| `CHECK` | Regenerado, pero hay algo que revisar a mano (no se encontró el pool, el pool la reactiva…) |
| `PENDING` | ISPConfig: la tarea sigue en cola (ver *Monitor › Cola de trabajos*) |
| `FAILED` | Falló el comando del panel |

El informe por sitio también se guarda en `/var/log/php2shellfix-AAAAmmdd_HHMMSS.log`.

### Seguridad

- Solo escribe en ficheros **propiedad de root** cuya ruta no pueda alterar otro usuario (ningún
  directorio de la ruta es escribible por otros, salvo que tenga el bit sticky).
- Nunca escribe en las rutas de `EXCLUDE`.
- Los ficheros se reescriben **in situ** (mismo inodo): se conservan propietario, permisos, contexto
  SELinux y enlaces duros. Se respetan los finales de línea CRLF.
- Antes de cada cambio se crea una copia junto al fichero: `<fichero>.bak.AAAAmmdd_HHMMSS`.
- Solo se ejecutan binarios PHP-FPM propiedad de root y en una ruta de confianza.
- Las plantillas cuya sección de pool está comentada (p. ej. `no-php.tpl` de Hestia) no se tocan, para
  que PHP-FPM no deje de arrancar por una línea fuera de una sección `[pool]`.

### Marcha atrás

Cada fichero modificado tiene una copia con la misma marca de tiempo. Para restaurar todos los de una
ejecución:

```bash
STAMP=20261021_120000   # marca de tiempo que muestra el script ("backup: ...")
find /etc /opt /usr/local /var/www /home -name "*.bak.$STAMP" 2>/dev/null | while IFS= read -r b; do
    cat -- "$b" > "${b%.bak.$STAMP}"
done
```

Después regenera los vhosts desde el panel y recarga PHP-FPM / el servidor web.

### Verificación

```bash
php -i | grep session.upload_progress.enabled          # CLI
php-fpm8.3 -i | grep session.upload_progress.enabled   # cada versión de FPM
```

La última sección de la salida del script ya muestra el valor de cada binario PHP-FPM. Ten en cuenta
que no incluye los valores de los pools; esos los cubre el informe por sitio.

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Correcto |
| `1` | No se ejecutó como root, ninguna ruta válida, error en un fichero o algún sitio en `FAILED` |
| `2` | Opción no válida |

### Personalización

Variables al principio del script:

| Variable | Uso |
|---|---|
| `INI_NAMES` | Nombres de `php.ini` a corregir (añade aquí otras copias) |
| `DEFAULT_ROOTS` | Directorios en los que se busca si no se indica `RUTA` |
| `EXCLUDE` | Ficheros que nunca se modifican (por defecto el `php.ini` del propio panel Plesk) |
| `PRUNE` | Directorios que nunca se recorren |
| `HESTIA` (entorno) | Directorio de instalación de HestiaCP (por defecto `/usr/local/hestia`) |

### Aviso legal

Este script se proporciona **"TAL CUAL"**, sin garantía de ningún tipo, expresa o implícita. El autor no
asume ninguna responsabilidad por el uso o mal uso de este script, ni por daños, pérdida de datos,
interrupciones del servicio o cualquier otra consecuencia derivada de su uso. Lo utilizas bajo tu
propia responsabilidad: revisa el código, ejecútalo primero con `--dry-run` y asegúrate de tener
copias de seguridad.

### Licencia

[GNU General Public License v3.0](LICENSE).

**Autor:** Kamal Majaiti EL Majaiti
