# PHP2Shell Ansible Vulnerability Detection Playbook
### CVE-2026-109618 & CVE-2026-109619

**Idiomas / Languages:** [Español](#español) · [English](#english)

---

## Español

Playbook de Ansible para detectar de forma automatizada y centralizada versiones vulnerables a **CVE-2026-109618** y **CVE-2026-109619** (PHP2Shell) en flotas de servidores Linux.

Audita servidores con **Plesk**, **HestiaCP**, **ISPConfig** o **servidores sin panel (Standalone)**, inspeccionando:
- Binarios CLI (`/usr/bin/php*`, `/opt/plesk/php/*/bin/php`, `/opt/php-*/bin/php`).
- Binarios PHP-FPM (`/usr/sbin/php-fpm*`, `/opt/plesk/php/*/sbin/php-fpm`, etc.).
- Módulos Apache `mod_php` (`libphp*.so`).
- Detección de directiva `session.upload_progress.enabled` activa.
- Detección de `fatal_error_backtraces` activo en PHP 8.5 (vector UAF).
- Auditoría de riesgo OOM: `post_max_size >= memory_limit` (vector de fallo fatal en parseo de peticiones multipart).

### Estructura de ficheros

- `detect_php2shell.yml`: Playbook principal de Ansible.
- `audit_php2shell.py`: Script de inspección y auditoría ejecutado en los nodos remotos (también utilizable directamente con `python3 audit_php2shell.py`).
- `inventory.example.ini`: Ejemplo de inventario con grupos para Plesk, Hestia, ISPConfig y Standalone.

### Requisitos

- **En el nodo de control (Ansible Controller):** Ansible 2.9 o superior.
- **En los nodos gestionados:** Python 3 (`/usr/bin/python3`).

### Uso rápido

```bash
# 1. Copia y edita el inventario con tus servidores
cp inventory.example.ini inventory.ini
nano inventory.ini

# 2. Ejecutar la auditoría en todos los servidores
ansible-playbook -i inventory.ini detect_php2shell.yml
```

### Opciones y variables adicionales

Puedes pasar variables mediante `-e` para modificar el comportamiento:

```bash
# Fallar el playbook si se encuentra algún host con versiones vulnerables (ideal para pipelines CI/CD)
ansible-playbook -i inventory.ini detect_php2shell.yml -e "fail_on_vulnerable=true"

# Descargar copias de los informes JSON al controlador local (en el directorio ./reports/)
ansible-playbook -i inventory.ini detect_php2shell.yml -e "fetch_local_report=true"

# Auditar únicamente un grupo de servidores (p. ej. solo servidores Plesk)
ansible-playbook -i inventory.ini detect_php2shell.yml -l plesk_servers
```

### Variables disponibles

| Variable | Defecto | Descripción |
|---|---|---|
| `fail_on_vulnerable` | `false` | Si es `true`, provoca el fallo de la tarea si se detectan binarios vulnerables. |
| `save_remote_report` | `true` | Guarda un informe JSON completo en cada servidor gestionado. |
| `remote_report_path` | `/var/log/php2shell-audit.json` | Ruta destino del informe JSON en el nodo remoto. |
| `fetch_local_report` | `false` | Descarga el informe JSON de cada host al nodo de control de Ansible. |
| `local_report_dir` | `./reports` | Directorio local donde se guardan los informes descargados. |

---

## English

Ansible playbook to automatically and centrally audit Linux server fleets for **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell) vulnerabilities.

Audits systems running **Plesk**, **HestiaCP**, **ISPConfig**, or **Standalone / No Panel** environments, inspecting:
- CLI binaries (`/usr/bin/php*`, `/opt/plesk/php/*/bin/php`, `/opt/php-*/bin/php`).
- PHP-FPM binaries (`/usr/sbin/php-fpm*`, `/opt/plesk/php/*/sbin/php-fpm`, etc.).
- Apache `mod_php` modules (`libphp*.so`).
- Check if `session.upload_progress.enabled` is currently active.
- Check if `fatal_error_backtraces` is active on PHP 8.5 (UAF vector).
- Audit OOM ratios: `post_max_size >= memory_limit` (multipart request parser OOM trap).

### File Structure

- `detect_php2shell.yml`: Main Ansible playbook.
- `audit_php2shell.py`: Remote inspection script executed on targets (can also be run standalone: `python3 audit_php2shell.py`).
- `inventory.example.ini`: Sample inventory file grouped by panel type.

### Requirements

- **Ansible Controller:** Ansible 2.9 or newer.
- **Managed Nodes:** Python 3 (`/usr/bin/python3`).

### Quick Start

```bash
# 1. Copy and configure your inventory
cp inventory.example.ini inventory.ini
nano inventory.ini

# 2. Run the audit across all managed nodes
ansible-playbook -i inventory.ini detect_php2shell.yml
```

### Custom Variables

```bash
# Fail the playbook execution if any host has vulnerable PHP versions (ideal for CI/CD)
ansible-playbook -i inventory.ini detect_php2shell.yml -e "fail_on_vulnerable=true"

# Fetch JSON audit reports to the local controller (stored in ./reports/)
ansible-playbook -i inventory.ini detect_php2shell.yml -e "fetch_local_report=true"

# Target a specific inventory group (e.g. Plesk servers only)
ansible-playbook -i inventory.ini detect_php2shell.yml -l plesk_servers
```

### Variables reference

| Variable | Default | Description |
|---|---|---|
| `fail_on_vulnerable` | `false` | When `true`, fails the play on any host where vulnerable PHP versions are found. |
| `save_remote_report` | `true` | Saves a structured JSON report on the remote host. |
| `remote_report_path` | `/var/log/php2shell-audit.json` | Remote destination path for the JSON report. |
| `fetch_local_report` | `false` | Fetches JSON reports from all target nodes back to the controller. |
| `local_report_dir` | `./reports` | Local controller directory where reports are stored. |

### Remediation Next Steps

If vulnerable binaries are discovered:
1. For supported branches (PHP 8.2+), upgrade packages immediately to **8.2.35+**, **8.3.36+**, **8.4.27+**, or **8.5.12+**.
2. For legacy EOL software (PHP 5.x, 7.x, 8.0, 8.1), run [`php2shellfix.sh`](../php2shellfix.sh) to lock down pools with `php_admin_flag`, recycle workers via `pm.max_requests = 500`, and deploy persistent drop-ins.
