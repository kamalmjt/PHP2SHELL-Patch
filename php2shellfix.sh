#!/usr/bin/env bash
#
#  ____  _   _ ____ ____  ____  _   _ _____ _     _       _____ _____  __
# |  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |     |  ___|_ _\ \/ /
# | |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |     | |_   | | \  /
# |  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___  |  _|  | | /  \
# |_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____| |_|   |___/_/\_\
#
# php2shellfix.sh
# Comprehensive Remediation & Hardening Toolkit for PHP2Shell:
#   - CVE-2026-109618 (CVSS 9.2): Out-Of-Memory (OOM) memory corruption via longjmp()
#     during multipart/form-data upload parsing and upload-progress tracking.
#   - CVE-2026-109619 (CVSS 9.2): Stale global state cross-request contamination in
#     persistent worker processes (PHP-FPM) leading to Use-After-Free and RCE.
#
# Specially tailored for legacy PHP (PHP 5.4 - 8.1 EOL) and modern PHP across:
#   - ISPConfig (conf-custom templates, extra /opt/php-*, datalogUpdate resync)
#   - HestiaCP (web templates, multiphp templates, panel PHP, v-rebuild-web-domain)
#   - Plesk (opt handlers, per-domain php.ini & pool configs, php_settings -u)
#   - Standalone / Self-hosted LAMP & LEMP environments (no panel)
#
# Author: Kamal Majaiti EL Majaiti
#
# DISCLAIMER
#   This script is provided "AS IS", without warranty of any kind, express or implied.
#   The author takes no responsibility and accepts no liability for the use or misuse
#   of this script, nor for any damage, data loss, service interruption or any other
#   consequence arising from its use. You use it entirely at your own risk: review the
#   code, run it with --dry-run first and make sure you have backups.
#
# WHAT IT DOES
#   1. binary & version audit -> inspects CLI, FPM, and Apache mod_php binaries.
#                                Compares versions against official security releases:
#                                  PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+
#                                Flags legacy EOL versions (PHP 5.x, 7.x, 8.0, 8.1)
#                                and unpatched branches as VULNERABLE.
#   2. php.ini (all versions) -> sets session.upload_progress.enabled = 0; adds it
#                                when not active (if absent, PHP defaults to On).
#                                Same for backup/staging copies (php.ini.vst.back,
#                                php.ini.ucf-dist).
#                                For PHP 8.5+, enforces fatal_error_backtraces = 0.
#   3. other *.ini drop-ins   -> fixes active lines in conf.d / php.d that re-enable it.
#   4. persistent drop-ins    -> deploys 99-php2shell.ini into all conf.d/php.d dirs
#                                so distro/panel package upgrades cannot revert the fix.
#   5. pool hardening (all)   -> enforces locked administrative flags in PHP-FPM pools
#                                (standalone, Plesk, HestiaCP, ISPConfig):
#                                  php_admin_flag[session.upload_progress.enabled] = off
#                                which prevents websites from re-enabling it via
#                                .user.ini, .htaccess or runtime ini_set().
#                                Sets pm.max_requests = 500 (if 0 or unset) to
#                                force regular worker recycling, neutralizing
#                                CVE-2026-109619 stale global state accumulation.
#   6. Apache mod_php global  -> deploys global Apache configuration:
#                                  php_admin_flag session.upload_progress.enabled off
#                                across Debian/Ubuntu (/etc/apache2/conf-available/)
#                                and RHEL/CentOS (/etc/httpd/conf.d/).
#   7. rebuild & resync       -> regenerates and validates vhosts when changed:
#                                  HestiaCP : v-rebuild-web-domain + backend restarts.
#                                  Plesk    : plesk bin php_settings -u + FPM reload.
#                                  ISPConfig: datalogUpdate() forced resync + server.sh.
#                                Full report written to /var/log/php2shellfix-*.log.
#   8. live service restarts  -> directly restarts all running PHP-FPM and Apache
#                                daemons to terminate any contaminated worker states.
#   9. OOM ratio audit        -> audits post_max_size vs memory_limit ratios to alert
#                                on CVE-2026-109618 OOM vulnerability traps.
#
# Usage: php2shellfix.sh [--dry-run] [--no-rebuild | --force-rebuild]
#                        [--max-requests N | --no-max-requests]
#                        [--no-dropins] [--no-oom-check] [PATH ...]
#
set -Eeuo pipefail

DIRECTIVE='session.upload_progress.enabled'
POOL_LINE='php_admin_flag[session.upload_progress.enabled] = off'
DROPIN_NAME='99-php2shell.ini'
MAX_REQUESTS_DEFAULT=500

# php.ini plus copies that are not loaded by PHP but may be restored/merged later
# (VestaCP backups, ucf's pending package version). Add other names here if needed.
INI_NAMES=(php.ini php.ini.vst.back php.ini.ucf-dist)
DEFAULT_ROOTS=(/etc /opt /usr/local /var/www)
HESTIA_DIR="${HESTIA:-/usr/local/hestia}"
ISPC_DIR=/usr/local/ispconfig
# Never modified (reported as EXCLUDED). Plesk internal engine (sw-engine) is excluded by default.
EXCLUDE=(/usr/local/psa/admin/conf/php.ini /opt/psa/admin/conf/php.ini)
# Never traversed: pseudo filesystems, container storage, mail and backups.
PRUNE=(/proc /sys /dev /run /var/lib/docker /var/lib/containerd /var/lib/lxc /var/lib/lxd /snap
       /backup '/home/*/mail' '/home/*/backup')

banner() {
    cat <<'BANNER'
 ____  _   _ ____ ____  ____  _   _ _____ _     _       _____ _____  __
|  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |     |  ___|_ _\ \/ /
| |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |     | |_   | | \  /
|  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___  |  _|  | | /  \
|_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____| |_|   |___/_/\_\

 Remediation Toolkit: CVE-2026-109618 & CVE-2026-109619 (PHP2Shell)
 Author: Kamal Majaiti EL Majaiti
 Legacy Software & Control Panel Hardening: ISPConfig, HestiaCP, Plesk, Standalone

 DISCLAIMER: provided "AS IS", without warranty of any kind. The author is not
 responsible or liable for the use or misuse of this script, nor for any damage
 or consequence arising from it. Use at your own risk; run --dry-run first.

BANNER
}

usage() {
    echo "Usage: ${0##*/} [OPTIONS] [PATH ...]"
    echo
    echo "Options:"
    echo "  -n, --dry-run          Show what would change without modifying anything"
    echo "  --no-rebuild           Patch files, templates, and drop-ins, but do not rebuild vhosts"
    echo "  --force-rebuild        Rebuild the vhosts even if nothing changed in this run"
    echo "  --max-requests N       Set pm.max_requests in FPM pools if 0/unset (default: 500, disrupts CVE-2026-109619)"
    echo "  --no-max-requests      Do not modify pm.max_requests in PHP-FPM pools"
    echo "  --no-dropins           Do not create persistent $DROPIN_NAME drop-in files in conf.d/php.d"
    echo "  --no-oom-check         Skip post_max_size vs memory_limit OOM ratio audit (CVE-2026-109618)"
    echo "  -h, --help             Show this help message and exit"
    echo
    echo "PATH:"
    echo "  Optional directories to process in isolation (no templates, no panel rebuilds)."
    echo "  Default search paths: ${DEFAULT_ROOTS[*]} (plus /home on HestiaCP)."
    echo "Works on standalone PHP (/etc/php*), HestiaCP, Plesk and ISPConfig."
}

DRY_RUN=0
REBUILD=auto
MAX_REQUESTS="$MAX_REQUESTS_DEFAULT"
MANAGE_MAX_REQUESTS=1
CREATE_DROPINS=1
CHECK_OOM=1
ROOTS=()

while (( $# > 0 )); do
    case "$1" in
        -n|--dry-run)          DRY_RUN=1; shift ;;
        --no-rebuild)          REBUILD=no; shift ;;
        --force-rebuild)       REBUILD=force; shift ;;
        --max-requests)        MAX_REQUESTS="$2"; shift 2 ;;
        --max-requests=*)      MAX_REQUESTS="${1#*=}"; shift ;;
        --no-max-requests)     MANAGE_MAX_REQUESTS=0; shift ;;
        --no-dropins)          CREATE_DROPINS=0; shift ;;
        --no-oom-check)        CHECK_OOM=0; shift ;;
        -h|--help)             banner; usage; exit 0 ;;
        -*)                    usage >&2; exit 2 ;;
        *)                     ROOTS+=("$1"); shift ;;
    esac
done

banner

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run this script as root." >&2
    exit 1
fi

IS_HESTIA=0 IS_PLESK=0 IS_ISPC=0
PANELS=()
if [[ -x $HESTIA_DIR/bin/v-list-users ]];   then IS_HESTIA=1; PANELS+=("HestiaCP"); fi
if [[ -d /usr/local/psa || -d /opt/psa ]];  then IS_PLESK=1;  PANELS+=("Plesk"); fi
if [[ -d $ISPC_DIR/server ]];               then IS_ISPC=1;   PANELS+=("ISPConfig"); fi

# Panel mode (templates + rebuild) only when no explicit paths were given.
PANEL_MODE=0
if (( ${#ROOTS[@]} == 0 )); then PANEL_MODE=1; fi

EXCLUDE_REAL=()
for e in "${EXCLUDE[@]}"; do
    if real=$(realpath -e -- "$e" 2>/dev/null); then EXCLUDE_REAL+=("$real"); fi
done

if (( PANEL_MODE )); then
    ROOTS=("${DEFAULT_ROOTS[@]}")
    if (( IS_HESTIA )); then
        shopt -s nullglob
        ROOTS+=(/home/*/web /home/*/conf/web)
        shopt -u nullglob
    fi
fi

SEARCH=()
for r in "${ROOTS[@]}"; do
    if [[ -d $r ]]; then SEARCH+=("$r"); else echo "WARNING: $r does not exist, ignored." >&2; fi
done
if (( ${#SEARCH[@]} == 0 )); then
    echo "ERROR: none of the search paths exist." >&2
    exit 1
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
CHANGED=0 SKIPPED=0 ERRORS=0 LIVE_CHANGED=0 PANEL_CHANGED=0
SITES_OK=0 SITES_WARN=0 SITES_FAIL=0 REBUILT_ANY=0 FPM_RELOADED=0
REPORT="/var/log/php2shellfix-${STAMP}.log"

# --- Version status checker for CVE-2026-109618 & CVE-2026-109619
# Official patches: 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+
check_version_status() {
    local v=$1
    local major minor patch
    major=$(awk -F. '{print $1}' <<<"$v" | grep -oE '^[0-9]+' || echo "0")
    minor=$(awk -F. '{print $2}' <<<"$v" | grep -oE '^[0-9]+' || echo "0")
    patch=$(awk -F. '{print $3}' <<<"$v" | grep -oE '^[0-9]+' || echo "0")

    if (( major < 8 )) || (( major == 8 && minor < 2 )); then
        echo "EOL"
        return 0
    elif (( major == 8 )); then
        case $minor in
            2) (( patch >= 35 )) && echo "PATCHED" && return 0 ;;
            3) (( patch >= 36 )) && echo "PATCHED" && return 0 ;;
            4) (( patch >= 27 )) && echo "PATCHED" && return 0 ;;
            5) (( patch >= 12 )) && echo "PATCHED" && return 0 ;;
            *) (( minor > 5 ))   && echo "PATCHED" && return 0 ;;
        esac
        echo "UNPATCHED"
        return 0
    elif (( major > 8 )); then
        echo "PATCHED"
        return 0
    fi
    echo "UNPATCHED"
}

get_target_version() {
    local v=$1
    local minor
    minor=$(awk -F. '{print $2}' <<<"$v" | grep -oE '^[0-9]+' || echo "0")
    case $minor in
        2) echo "8.2.35" ;;
        3) echo "8.3.36" ;;
        4) echo "8.4.27" ;;
        5) echo "8.5.12" ;;
        *) echo "8.2.35+" ;;
    esac
}

# --- Perl: rewrites a file. Args: mode(enforce|fix|pool) input output max_requests
read -r -d '' PERL_FIX <<'PERL' || true
use strict; use warnings;
my ($mode, $in, $out, $max_requests) = @ARGV;
open(my $fh, "<:raw", $in) or die "Cannot read $in: $!\n";
my @l = <$fh>;
close $fh;
my $eol = (grep { /\r\n\z/ } @l) ? "\r\n" : "\n";
my @msgs = ();

if ($mode eq "pool") {
    # Templates or pool files whose pool section is commented out (e.g. Hestia no-php.tpl) are left alone:
    # an active line outside a [pool] section would make php-fpm refuse to start.
    if (grep { /^[ \t]*\[[^\]]+\]/ } @l) {
        # 1. session.upload_progress.enabled in pool: php_admin_flag off
        my $re_prog = qr/^[ \t]*php_(?:admin_)?(?:value|flag)[ \t]*\[[ \t]*session\.upload_progress\.enabled[ \t]*\]/;
        my $replaced = grep { $_ =~ $re_prog } @l;
        @l = grep { $_ !~ $re_prog } @l;
        $l[-1] .= $eol if @l && $l[-1] !~ /\n\z/;
        push @l, "php_admin_flag[session.upload_progress.enabled] = off" . $eol;
        push @msgs, ($replaced ? "pool: replaced existing upload_progress flag with php_admin_flag off"
                               : "pool: added php_admin_flag[session.upload_progress.enabled] = off");

        # 2. pm.max_requests (mitigates CVE-2026-109619 stale global worker state accumulation)
        if (defined $max_requests && $max_requests =~ /^\d+$/ && $max_requests > 0) {
            my $found_active = 0;
            my $found_commented = -1;
            for my $i (0 .. $#l) {
                if ($l[$i] =~ /^[ \t]*pm\.max_requests[ \t]*=[ \t]*(\d+)/) {
                    $found_active = 1;
                    if ($1 == 0) {
                        my ($le) = $l[$i] =~ /(\r?\n)\z/;
                        $l[$i] = "pm.max_requests = $max_requests" . ($le // $eol);
                        push @msgs, "pm.max_requests: was 0, set to $max_requests";
                    }
                    last;
                } elsif ($found_commented == -1 && $l[$i] =~ /^[ \t]*;+[ \t]*pm\.max_requests[ \t]*=/) {
                    $found_commented = $i;
                }
            }
            if (!$found_active) {
                if ($found_commented != -1) {
                    my ($le) = $l[$found_commented] =~ /(\r?\n)\z/;
                    $l[$found_commented] = "pm.max_requests = $max_requests" . ($le // $eol);
                    push @msgs, "pm.max_requests: was commented out, enabled as $max_requests";
                } else {
                    push @l, "pm.max_requests = $max_requests" . $eol;
                    push @msgs, "pm.max_requests: set to $max_requests";
                }
            }
        }
    }
} else {
    my $new_prog = "session.upload_progress.enabled = 0";
    my $key_prog = qr/session\.upload_progress\.enabled/;
    my $new_bt   = "fatal_error_backtraces = 0";
    my $key_bt   = qr/fatal_error_backtraces/;

    my ($active_p, $fixed_p, $commented_p, $section_sess) = (0, 0);
    my ($active_b, $fixed_b, $commented_b) = (0, 0);

    for my $i (0 .. $#l) {
        my ($le) = $l[$i] =~ /(\r?\n)\z/;
        # session.upload_progress.enabled
        if ($l[$i] =~ /^[ \t]*$key_prog[ \t]*=([^\r\n]*)/) {
            $active_p++;
            (my $v = $1) =~ s/;.*//;
            $v =~ s/^\s+|\s+\z//g;
            $v =~ s/^(["'])(.*)\1\z/$2/;
            if ($v !~ /^(?:0|off|false|no|none|)\z/i) {
                $l[$i] = $new_prog . ($le // "");
                $fixed_p++;
            }
        } elsif (!defined $commented_p && $l[$i] =~ /^[ \t]*;+[ \t]*$key_prog[ \t]*=/) {
            $commented_p = $i;
        } elsif (!defined $section_sess && $l[$i] =~ /^[ \t]*\[Session\][ \t]*\r?\n?\z/i) {
            $section_sess = $i;
        }

        # fatal_error_backtraces (PHP 8.5+ CVE-2026-109619 mitigation)
        if ($l[$i] =~ /^[ \t]*$key_bt[ \t]*=([^\r\n]*)/) {
            $active_b++;
            (my $v = $1) =~ s/;.*//;
            $v =~ s/^\s+|\s+\z//g;
            $v =~ s/^(["'])(.*)\1\z/$2/;
            if ($v !~ /^(?:0|off|false|no|none|)\z/i) {
                $l[$i] = $new_bt . ($le // "");
                $fixed_b++;
            }
        } elsif (!defined $commented_b && $l[$i] =~ /^[ \t]*;+[ \t]*$key_bt[ \t]*=/) {
            $commented_b = $i;
        }
    }

    if ($fixed_p) {
        push @msgs, "upload_progress was enabled, set to 0";
    } elsif ($mode eq "enforce" && !$active_p) {
        if (defined $commented_p) {
            my ($le) = $l[$commented_p] =~ /(\r?\n)\z/;
            $l[$commented_p] = $new_prog . ($le // "");
            push @msgs, "upload_progress was commented out (default On), uncommented as 0";
        } elsif (defined $section_sess) {
            $l[$section_sess] .= $eol unless $l[$section_sess] =~ /\n\z/;
            splice @l, $section_sess + 1, 0, $new_prog . $eol;
            push @msgs, "upload_progress was missing (default On), added under [Session]";
        } else {
            unshift @l, $new_prog . $eol;
            push @msgs, "upload_progress was missing (default On), added at the top";
        }
    }

    if ($fixed_b) {
        push @msgs, "fatal_error_backtraces was enabled, set to 0";
    } elsif ($mode eq "enforce" && defined $commented_b && !$active_b) {
        my ($le) = $l[$commented_b] =~ /(\r?\n)\z/;
        $l[$commented_b] = $new_bt . ($le // "");
        push @msgs, "fatal_error_backtraces uncommented as 0";
    } elsif ($mode eq "enforce" && !$active_b && $in =~ /8\.5/) {
        unshift @l, $new_bt . $eol;
        push @msgs, "PHP 8.5 detected: fatal_error_backtraces = 0 added";
    }
}

open(my $o, ">:raw", $out) or die "Cannot write $out: $!\n";
print {$o} @l;
close $o or die "Error writing $out: $!\n";
print join("; ", @msgs);
PERL

# --- Perl: reports active lines that set upload_progress or fatal backtraces to insecure values.
read -r -d '' PERL_AUDIT <<'PERL' || true
if (!/^\s*[;#]/) {
    if (/session\.upload_progress\.enabled\]?[ \t]*=?[ \t]*["']?([A-Za-z0-9]*)/) {
        my $v = lc $1;
        (my $t = $_) =~ s/\s+\z//;
        print "  $ARGV:$.: $t\n" unless $v =~ /^(?:0|off|false|no|none)\z/;
    }
    if (/fatal_error_backtraces\]?[ \t]*=?[ \t]*["']?([A-Za-z0-9]*)/) {
        my $v = lc $1;
        (my $t = $_) =~ s/\s+\z//;
        print "  $ARGV:$.: $t\n" unless $v =~ /^(?:0|off|false|no|none)\z/;
    }
}
close ARGV if eof;
PERL

find_files() {
    local prune=() p
    for p in "${PRUNE[@]}"; do prune+=(-path "$p" -o); done
    find -H "${SEARCH[@]}" \( "${prune[@]}" -false \) -prune -o -type f \( "$@" \) -print0 2>/dev/null
}

# Root-owned file, and no directory in its path writable by others (unless sticky).
trusted_path() {
    local f=$1 d uid mode
    [[ $(stat -c %u -- "$f" 2>/dev/null) == 0 ]] || return 1
    d=${f%/*}; d=${d:-/}
    while :; do
        read -r uid mode < <(stat -c '%u %a' -- "$d" 2>/dev/null || echo "1 777")
        [[ $uid == 0 ]] || return 1
        (( (8#$mode & 8#1000) || !(8#$mode & 8#022) )) || return 1
        [[ $d == / ]] && return 0
        d=${d%/*}; d=${d:-/}
    done
}

process_ini() {   # process_ini <file> <enforce|fix|pool>
    local file mode=$2 tmp="$WORK/new" action backup
    file=$(realpath -e -- "$1") || return 0

    local e
    for e in "${EXCLUDE_REAL[@]}"; do
        if [[ $file == "$e" ]]; then
            echo "EXCLUDED (listed in EXCLUDE; left untouched): $file"
            ((SKIPPED+=1)); return 0
        fi
    done

    if ! trusted_path "$file"; then
        echo "REVIEW (not owned by root, or path writable by others; left untouched): $file"
        ((SKIPPED+=1)); return 0
    fi
    if [[ ! -w $file ]]; then
        echo "SKIPPED (not writable / read-only filesystem): $file"
        ((SKIPPED+=1)); return 0
    fi

    local req_arg=0
    (( MANAGE_MAX_REQUESTS )) && req_arg="$MAX_REQUESTS"

    if ! action=$(perl -e "$PERL_FIX" -- "$mode" "$file" "$tmp" "$req_arg"); then
        echo "ERROR processing $file" >&2
        ((ERRORS+=1)); return 0
    fi

    if cmp -s -- "$file" "$tmp"; then
        case $mode in
            enforce) echo "OK (already secured): $file" ;;
            pool)    if [[ -z $action ]]; then echo "SKIPPED (no active pool section): $file"
                     else echo "OK (pool already enforces policy): $file"; fi ;;
        esac
        return 0
    fi

    if (( DRY_RUN )); then
        echo "WOULD CHANGE: $file  [$action]"
        diff -u --label "$file" --label "$file (new)" -- "$file" "$tmp" | sed 's/^/    /' || true
        ((CHANGED+=1)); return 0
    fi

    # Rewritten in place (same inode): keeps owner, mode, SELinux context and hard links.
    backup="${file}.bak.${STAMP}"
    cp -a -- "$file" "$backup"
    if cat -- "$tmp" > "$file" && cmp -s -- "$tmp" "$file"; then
        echo "MODIFIED: $file  [$action]"
        echo "    backup: $backup"
        ((CHANGED+=1))
        # Only files PHP actually loads need a service reload (not copies or templates).
        if [[ $file == *.ini || $file == *.conf ]]; then
            LIVE_CHANGED=1
            if [[ $file == "$HESTIA_DIR"/* ]]; then PANEL_CHANGED=1; fi
        fi
    else
        echo "ERROR writing $file; restoring backup." >&2
        cat -- "$backup" > "$file" || echo "ERROR: restore failed. Backup at $backup" >&2
        ((ERRORS+=1))
    fi
}

deploy_dropins() {
    (( CREATE_DROPINS )) || return 0
    echo
    echo "-- Deploying persistent drop-in configurations ($DROPIN_NAME)"
    local dirs=() d real file php85 body created=0

    # Common conf.d and php.d paths across standard distros, Plesk, ISPConfig, and custom /opt PHP
    shopt -s nullglob
    for d in /etc/php/*/fpm/conf.d /etc/php/*/cli/conf.d /etc/php/*/apache2/conf.d /etc/php/*/cgi/conf.d \
             /etc/php.d /etc/php-fpm.d \
             /opt/plesk/php/*/etc/php.d \
             /opt/php-*/lib/php.d /opt/php-*/etc/php.d \
             /etc/opt/remi/php*/php.d /usr/local/etc/php/conf.d; do
        [[ -d $d ]] && dirs+=("$d")
    done
    shopt -u nullglob

    declare -A seen_dirs=()
    for d in "${dirs[@]}"; do
        real=$(realpath -e -- "$d" 2>/dev/null) || continue
        [[ -n ${seen_dirs[$real]:-} ]] && continue
        seen_dirs[$real]=1

        if ! trusted_path "$real"; then
            echo "REVIEW (drop-in directory not trusted, skipped): $real"
            continue
        fi

        file="$real/$DROPIN_NAME"
        php85=0
        [[ $real == *8.5* ]] && php85=1

        body="; Managed by php2shellfix.sh\n; Hardening for CVE-2026-109618 & CVE-2026-109619 (PHP2Shell)\nsession.upload_progress.enabled = 0\n"
        if (( php85 )); then
            body+="fatal_error_backtraces = 0\n"
        fi

        if [[ -f $file ]] && [[ $(cat "$file" 2>/dev/null) == "$(printf '%b' "$body")" ]]; then
            echo "OK (drop-in already active): $file"
            continue
        fi

        if (( DRY_RUN )); then
            echo "WOULD CREATE/UPDATE DROP-IN: $file"
            ((created+=1))
        else
            printf '%b' "$body" > "$file"
            chmod 644 "$file" 2>/dev/null || true
            echo "DEPLOYED DROP-IN: $file"
            ((created+=1))
            LIVE_CHANGED=1
        fi
    done
    CHANGED=$(( CHANGED + created ))
}

deploy_apache_modphp() {
    echo
    echo "-- Apache mod_php global configuration hardening"
    local conf_content="<IfModule mod_php5.c>
    php_admin_flag session.upload_progress.enabled off
</IfModule>
<IfModule mod_php7.c>
    php_admin_flag session.upload_progress.enabled off
</IfModule>
<IfModule mod_php.c>
    php_admin_flag session.upload_progress.enabled off
</IfModule>
"
    local apache_dirs=() target enabled_link
    [[ -d /etc/apache2/conf-available ]] && apache_dirs+=(/etc/apache2/conf-available)
    [[ -d /etc/apache2/conf.d ]]         && apache_dirs+=(/etc/apache2/conf.d)
    [[ -d /etc/httpd/conf.d ]]           && apache_dirs+=(/etc/httpd/conf.d)
    [[ -d /usr/local/etc/apache2/conf.d ]] && apache_dirs+=(/usr/local/etc/apache2/conf.d)

    if (( ${#apache_dirs[@]} == 0 )); then
        echo "No standard Apache global configuration directory found."
        return 0
    fi

    for d in "${apache_dirs[@]}"; do
        target="$d/zz-php2shell-hardening.conf"
        if [[ -f $target ]] && [[ $(cat "$target" 2>/dev/null) == "$conf_content" ]]; then
            echo "OK (Apache hardening current): $target"
        elif (( DRY_RUN )); then
            echo "WOULD CREATE: $target"
            ((CHANGED+=1))
        else
            printf '%s' "$conf_content" > "$target"
            echo "CREATED: $target"
            ((CHANGED+=1))
            LIVE_CHANGED=1
        fi

        if [[ $d == *conf-available* && -d /etc/apache2/conf-enabled ]]; then
            enabled_link="/etc/apache2/conf-enabled/zz-php2shell-hardening.conf"
            if [[ ! -e $enabled_link ]]; then
                if (( DRY_RUN )); then
                    echo "WOULD ENABLE: a2enconf zz-php2shell-hardening"
                else
                    if command -v a2enconf >/dev/null 2>&1; then
                        a2enconf -q zz-php2shell-hardening 2>/dev/null || ln -sf "$target" "$enabled_link"
                    else
                        ln -sf "$target" "$enabled_link"
                    fi
                    echo "ENABLED: Apache configuration zz-php2shell-hardening"
                    LIVE_CHANGED=1
                fi
            fi
        fi
    done
}

# ---------------------------------------------------------------- rebuild helpers

report_site() {   # report_site <panel> <site> <OK|CHECK|PENDING|FAILED|WOULD ...> <detail>
    local panel=$1 site=$2 status=$3 detail=${4:-}
    printf '  %-9s %-8s %-40s %s\n' "$panel" "$status" "$site" "$detail"
    case $status in
        OK)              ((SITES_OK+=1)) ;;
        CHECK|PENDING)   ((SITES_WARN+=1)) ;;
        FAILED)          ((SITES_FAIL+=1)) ;;
    esac
    if (( ! DRY_RUN )); then
        printf '%s\t%s\t%s\t%s\t%s\n' "$(date '+%F %T')" "$panel" "$site" "$status" "$detail" >> "$REPORT"
    fi
}

has_pool_protection() {
    grep -qiE '^[[:space:]]*php_admin_flag\[[[:space:]]*session\.upload_progress\.enabled[[:space:]]*\][[:space:]]*=[[:space:]]*(off|0|false|no|none)' -- "$1" 2>/dev/null
}

last_setting_off() {
    local last
    last=$(grep -E "$DIRECTIVE" -- "$1" 2>/dev/null | grep -vE '^[[:space:]]*[;#]' | tail -n 1)
    [[ -n $last ]] && grep -qiE '=[[:space:]]*"?(off|0|false|no|none)"?[[:space:]]*$' <<<"$last"
}

enables_it() {
    [[ -n $(perl -ne "$PERL_AUDIT" -- "$1" 2>/dev/null) ]]
}

to_bytes() {
    local val="${1^^}"
    [[ $val == "-1" ]] && echo "-1" && return
    local num unit
    num=$(grep -oE '^[0-9]+' <<<"$val" || true)
    unit=$(grep -oE '[A-Z]+$' <<<"$val" || true)
    [[ -z $num ]] && echo "0" && return
    case $unit in
        G|GB) echo $(( num * 1024 * 1024 * 1024 )) ;;
        M|MB) echo $(( num * 1024 * 1024 )) ;;
        K|KB) echo $(( num * 1024 )) ;;
        *)    echo "$num" ;;
    esac
}

restart_services() {
    (( DRY_RUN )) && return 0
    echo
    echo "-- Restarting PHP-FPM and Web Server services (clearing worker states)"

    # 1. PHP-FPM
    local fpm_units=()
    if command -v systemctl >/dev/null 2>&1; then
        mapfile -t fpm_units < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
            | awk '{print $1}' | grep -E '^(plesk-|rh-|opt-)?[^ ]*php[^ ]*fpm[^ ]*\.service$' || true)
        if (( ${#fpm_units[@]} )); then
            echo "  Restarting PHP-FPM services: ${fpm_units[*]}"
            systemctl restart "${fpm_units[@]}" 2>&1 | sed 's/^/    /' || true
        else
            echo "  No running PHP-FPM systemd services detected."
        fi
    elif command -v service >/dev/null 2>&1; then
        for s in /etc/init.d/php*-fpm /etc/init.d/php-fpm; do
            if [[ -x $s ]]; then
                echo "  Restarting service ${s##*/}"
                "$s" restart 2>&1 | sed 's/^/    /' || true
            fi
        done
    fi

    # 2. Apache / HTTPD
    local apache_units=()
    if command -v systemctl >/dev/null 2>&1; then
        mapfile -t apache_units < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
            | awk '{print $1}' | grep -E '^(apache2|httpd)\.service$' || true)
        if (( ${#apache_units[@]} )); then
            local cfg_ok=1
            if command -v apache2ctl >/dev/null 2>&1; then
                apache2ctl configtest >/dev/null 2>&1 || cfg_ok=0
            elif command -v httpd >/dev/null 2>&1; then
                httpd -t >/dev/null 2>&1 || cfg_ok=0
            fi
            if (( cfg_ok )); then
                echo "  Restarting Apache/HTTPD: ${apache_units[*]}"
                systemctl restart "${apache_units[@]}" 2>&1 | sed 's/^/    /' || true
            else
                echo "  WARNING: Apache configtest failed; reloading gracefully instead of full restart."
                systemctl reload "${apache_units[@]}" 2>&1 | sed 's/^/    /' || true
            fi
        fi
    elif command -v apache2ctl >/dev/null 2>&1; then
        apache2ctl graceful 2>/dev/null || true
    elif command -v httpd >/dev/null 2>&1; then
        httpd -k graceful 2>/dev/null || true
    fi

    # 3. HestiaCP panel PHP
    if (( PANEL_CHANGED && IS_HESTIA )); then
        if command -v systemctl >/dev/null 2>&1; then
            echo "  Restarting HestiaCP panel service..."
            systemctl restart hestia 2>&1 | sed 's/^/    /' || true
        fi
    fi
}

rebuild_hestia() {
    local bin="$HESTIA_DIR/bin" user domain out rc pool d n=0
    (( DRY_RUN )) || echo "  HestiaCP: rebuilding web domains (v-rebuild-web-domain)..."
    while IFS= read -r user <&4; do
        [[ -n $user ]] || continue
        while IFS=$'\t' read -r domain _ <&5; do
            [[ -n $domain ]] || continue
            ((n+=1))
            if (( DRY_RUN )); then report_site HestiaCP "$user/$domain" "WOULD" "rebuild"; continue; fi
            if out=$(HESTIA="$HESTIA_DIR" "$bin/v-rebuild-web-domain" "$user" "$domain" no </dev/null 2>&1); then
                pool=""
                for d in /etc/php/*/fpm/pool.d; do
                    if [[ -f $d/$domain.conf ]]; then pool=$d/$domain.conf; break; fi
                    if [[ -f $d/$user.conf ]]; then pool=$d/$user.conf; break; fi
                done
                if [[ -z $pool ]]; then
                    report_site HestiaCP "$user/$domain" CHECK "rebuilt, but no PHP-FPM pool found (no-php backend or suspended user?)"
                elif has_pool_protection "$pool"; then
                    report_site HestiaCP "$user/$domain" OK "rebuilt with php_admin_flag off ($pool)"
                elif last_setting_off "$pool"; then
                    report_site HestiaCP "$user/$domain" OK "rebuilt, $pool"
                else
                    report_site HestiaCP "$user/$domain" CHECK "rebuilt, but pool lacks locked admin flag: $pool"
                fi
            else
                rc=$?
                report_site HestiaCP "$user/$domain" FAILED "rc=$rc: $(tail -n 1 <<<"$out")"
            fi
        done 5< <(HESTIA="$HESTIA_DIR" "$bin/v-list-web-domains" "$user" plain 2>/dev/null)
    done 4< <(HESTIA="$HESTIA_DIR" "$bin/v-list-users" list 2>/dev/null)
    (( n )) || echo "  HestiaCP: no web domains found."
    if (( n && ! DRY_RUN )); then
        REBUILT_ANY=1
        echo "  HestiaCP: restarting PHP-FPM, web server and proxy (Hestia's own restart commands)..."
        HESTIA="$HESTIA_DIR" "$bin/v-restart-web-backend" </dev/null >/dev/null 2>&1 || echo "  WARNING: v-restart-web-backend failed"
        HESTIA="$HESTIA_DIR" "$bin/v-restart-web" </dev/null >/dev/null 2>&1 || echo "  WARNING: v-restart-web failed"
        HESTIA="$HESTIA_DIR" "$bin/v-restart-proxy" </dev/null >/dev/null 2>&1 || echo "  WARNING: v-restart-proxy failed"
    fi
}

rebuild_plesk() {
    local plesk domain out ini pool pools=() n=0 detail protected
    plesk=$(command -v plesk 2>/dev/null || echo /usr/sbin/plesk)
    if [[ ! -x $plesk ]]; then
        report_site Plesk "*" FAILED "plesk command not found"; return 0
    fi
    local domains=()
    mapfile -t domains < <("$plesk" bin site --list 2>/dev/null </dev/null | sed '/^[[:space:]]*$/d')
    if (( ${#domains[@]} == 0 )); then echo "  Plesk: no domains found."; return 0; fi
    if (( DRY_RUN )); then
        for domain in "${domains[@]}"; do report_site Plesk "$domain" "WOULD" "update PHP settings & verify pool protection"; done
        return 0
    fi
    echo "  Plesk: regenerating per-domain PHP settings (plesk bin php_settings -u)..."
    if ! out=$("$plesk" bin php_settings -u </dev/null 2>&1); then
        echo "  WARNING: php_settings -u failed: $(tail -n 1 <<<"$out")"
    fi
    REBUILT_ANY=1
    for domain in "${domains[@]}"; do
        ini="/var/www/vhosts/system/$domain/etc/php.ini"
        shopt -s nullglob
        pools=(/opt/plesk/php/*/etc/php-fpm.d/"$domain".conf
               /var/www/vhosts/system/"$domain"/etc/php-fpm.conf
               /etc/php/*/fpm/pool.d/"$domain".conf
               /etc/php-fpm.d/"$domain".conf)
        shopt -u nullglob
        detail=""
        protected=0
        for pool in "${pools[@]}"; do
            if enables_it "$pool"; then
                detail="pool re-enables it: $pool"; protected=-1; break
            elif has_pool_protection "$pool"; then
                protected=1
                detail="pool secured with php_admin_flag off ($pool)"
                break
            fi
        done
        if [[ $protected -eq -1 ]]; then
            report_site Plesk "$domain" CHECK "$detail"
        elif [[ $protected -eq 1 ]]; then
            report_site Plesk "$domain" OK "$detail"
        elif [[ -f $ini ]] && last_setting_off "$ini"; then
            report_site Plesk "$domain" OK "$ini = 0 (per-domain ini)"
        elif [[ -f $ini ]]; then
            report_site Plesk "$domain" CHECK "$ini does not disable it (default On)"
        else
            report_site Plesk "$domain" OK "PHP-FPM: inherits handler php.ini / drop-in"
        fi
    done
}

read -r -d '' ISPC_PHP <<'PHP' || true
<?php
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING & ~E_DEPRECATED & ~E_STRICT);
$mode = isset($argv[1]) ? $argv[1] : 'list';
$base = '/usr/local/ispconfig/server';
if (!defined('SCRIPT_PATH')) define('SCRIPT_PATH', $base);
chdir($base);
try {
    require $base . '/lib/config.inc.php';
    require $base . '/lib/app.inc.php';
    $_SESSION['s']['user']['username'] = 'admin';   // datalog author, as when an admin resyncs
    $db = (isset($app->dbmaster) && is_object($app->dbmaster)) ? $app->dbmaster : $app->db;
    if ($mode === 'resync') {
        $m = new ReflectionMethod($db, 'datalogUpdate');
        if ($m->getNumberOfParameters() < 5) {
            fwrite(STDERR, "this ISPConfig version has no forced datalogUpdate; use Tools > Resync\n");
            exit(3);
        }
    }
    $rows = $db->queryAllRecords("SELECT domain_id, domain, php FROM web_domain WHERE server_id = ? AND type IN ('vhost','vhostsubdomain','vhostalias') AND active = 'y' ORDER BY domain", $conf['server_id']);
    foreach ((array)$rows as $r) {
        if ($mode === 'resync') {
            $db->datalogUpdate('web_domain', array('domain_id' => $r['domain_id']), 'domain_id', $r['domain_id'], true);
        }
        echo $r['domain_id'], "\t", $r['domain'], "\t", $r['php'], "\n";
    }
} catch (Throwable $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(1);
}
PHP

rebuild_ispconfig() {
    local helper="$WORK/ispc-resync.php" mode=resync out id domain php pool n=0
    printf '%s\n' "$ISPC_PHP" > "$helper"
    (( DRY_RUN )) && mode=list
    if ! command -v php >/dev/null 2>&1; then
        report_site ISPConfig "*" FAILED "php CLI not found; use Tools > Resync > Websites"; return 0
    fi
    if (( ! DRY_RUN )); then echo "  ISPConfig: queueing a resync of every website..."; fi
    if ! out=$(php -q "$helper" "$mode" 2>&1 </dev/null); then
        report_site ISPConfig "*" FAILED "$(tail -n 1 <<<"$out") -- use Tools > Resync > Websites"
        return 0
    fi
    if [[ -z $out ]]; then echo "  ISPConfig: no websites found."; return 0; fi
    if (( DRY_RUN )); then
        while IFS=$'\t' read -r id domain php; do
            report_site ISPConfig "$domain" "WOULD" "resync (web$id, PHP: $php)"
        done <<<"$out"
        return 0
    fi
    REBUILT_ANY=1
    echo "  ISPConfig: applying the queue now (server.sh)..."
    timeout 900 "$ISPC_DIR/server/server.sh" </dev/null >/dev/null 2>&1 || true
    declare -A pools=()
    while IFS= read -r -d '' pool; do pools[${pool##*/}]=$pool; done \
        < <(find /etc /opt -maxdepth 7 -type f -name 'web*.conf' \( -path '*/pool.d/*' -o -path '*/php-fpm.d/*' \) -print0 2>/dev/null)
    while IFS=$'\t' read -r id domain php; do
        if [[ $php != php-fpm ]]; then
            report_site ISPConfig "$domain" OK "resynced (PHP mode '$php': uses patched php.ini)"
        elif [[ -z ${pools[web$id.conf]:-} ]]; then
            report_site ISPConfig "$domain" PENDING "pool web$id.conf not found yet; see Monitor > Jobqueue"
        elif has_pool_protection "${pools[web$id.conf]}"; then
            report_site ISPConfig "$domain" OK "resynced with php_admin_flag off, ${pools[web$id.conf]}"
        elif last_setting_off "${pools[web$id.conf]}"; then
            report_site ISPConfig "$domain" OK "resynced, ${pools[web$id.conf]}"
        else
            report_site ISPConfig "$domain" PENDING "${pools[web$id.conf]} not regenerated yet; see Monitor > Jobqueue"
        fi
    done <<<"$out"
}

audit_binaries_and_versions() {
    echo
    echo "================================================================================"
    echo " PHP ENVIRONMENT SECURITY AUDIT (CVE-2026-109618 & CVE-2026-109619)"
    echo "================================================================================"
    echo " Official patched versions: 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+"
    echo " Legacy PHP (5.x, 7.x, 8.0, 8.1) are EOL: no official binary security patches."
    echo "================================================================================"

    local total_bin=0 total_vuln=0 total_legacy=0 total_patched=0

    # 1. PHP CLI Binaries
    echo
    echo "-- PHP CLI Binaries"
    local cli_bins=() b real ver status target_ver
    shopt -s nullglob
    cli_bins+=(/usr/bin/php* /usr/local/bin/php*)
    cli_bins+=(/opt/plesk/php/*/bin/php)
    cli_bins+=(/opt/php-*/bin/php)
    shopt -u nullglob

    declare -A seen_cli=()
    for b in "${cli_bins[@]}"; do
        [[ -f $b && -x $b ]] || continue
        real=$(realpath -e -- "$b" 2>/dev/null) || continue
        [[ -n ${seen_cli[$real]:-} ]] && continue
        seen_cli[$real]=1
        if ! trusted_path "$real"; then continue; fi

        ((total_bin+=1))
        ver=$(timeout 10 "$b" -r 'echo PHP_VERSION;' 2>/dev/null || true)
        if [[ -z $ver ]]; then
            ver=$(timeout 10 "$b" -v 2>/dev/null | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "Unknown")
        fi

        status=$(check_version_status "$ver")
        case $status in
            PATCHED)
                printf '  %-40s %-12s [PATCHED]\n' "$b" "$ver"
                ((total_patched+=1))
                ;;
            EOL)
                printf '  %-40s %-12s [VULNERABLE - EOL] (No official upstream patch)\n' "$b" "$ver"
                ((total_vuln+=1))
                ((total_legacy+=1))
                ;;
            UNPATCHED)
                target_ver=$(get_target_version "$ver")
                printf '  %-40s %-12s [VULNERABLE] (Requires update to >= %s)\n' "$b" "$ver" "$target_ver"
                ((total_vuln+=1))
                ;;
        esac
    done

    # 2. PHP-FPM Binaries
    echo
    echo "-- PHP-FPM Binaries"
    local fpm_bins=()
    shopt -s nullglob
    fpm_bins+=(/usr/sbin/php-fpm* /usr/local/sbin/php-fpm*)
    fpm_bins+=(/opt/plesk/php/*/sbin/php-fpm)
    fpm_bins+=(/opt/php-*/sbin/php-fpm /opt/php-*/bin/php-fpm)
    shopt -u nullglob

    declare -A seen_fpm=()
    for b in "${fpm_bins[@]}"; do
        [[ -f $b && -x $b ]] || continue
        real=$(realpath -e -- "$b" 2>/dev/null) || continue
        [[ -n ${seen_fpm[$real]:-} ]] && continue
        seen_fpm[$real]=1
        if ! trusted_path "$real"; then continue; fi

        ((total_bin+=1))
        local info ver ini val bt_val
        info=$(timeout 15 "$b" -i 2>/dev/null || true)
        ver=$(sed -n 's/^PHP Version => //p' <<<"$info" | head -n 1)
        if [[ -z $ver ]]; then
            ver=$(timeout 10 "$b" -v 2>/dev/null | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "Unknown")
        fi

        status=$(check_version_status "$ver")
        ini=$(sed -n 's/^Loaded Configuration File => //p' <<<"$info" | head -n 1)
        val=$(sed -n 's/^session\.upload_progress\.enabled => \([^ ]*\) => .*/\1/p' <<<"$info" | head -n 1)

        case $status in
            PATCHED)
                printf '  %-40s %-12s [PATCHED]\n' "$b" "$ver"
                ((total_patched+=1))
                ;;
            EOL)
                printf '  %-40s %-12s [VULNERABLE - EOL] (No official upstream patch)\n' "$b" "$ver"
                ((total_vuln+=1))
                ((total_legacy+=1))
                ;;
            UNPATCHED)
                target_ver=$(get_target_version "$ver")
                printf '  %-40s %-12s [VULNERABLE] (Requires update to >= %s)\n' "$b" "$ver" "$target_ver"
                ((total_vuln+=1))
                ;;
        esac

        if [[ ${val,,} == on || $val == 1 ]]; then
            echo "    ! session.upload_progress.enabled is currently ON ($ini)"
        fi

        if [[ $ver == 8.5* ]]; then
            bt_val=$(sed -n 's/^fatal_error_backtraces => \([^ ]*\) => .*/\1/p' <<<"$info" | head -n 1)
            if [[ ${bt_val,,} == on || $bt_val == 1 ]]; then
                echo "    ! fatal_error_backtraces is ON (CVE-2026-109619 vector on PHP 8.5)"
            fi
        fi

        if (( CHECK_OOM )); then
            local ml pms ml_bytes pms_bytes
            ml=$(sed -n 's/^memory_limit => \([^ ]*\) => .*/\1/p' <<<"$info" | head -n 1)
            pms=$(sed -n 's/^post_max_size => \([^ ]*\) => .*/\1/p' <<<"$info" | head -n 1)
            if [[ -n $ml && -n $pms ]]; then
                ml_bytes=$(to_bytes "$ml")
                pms_bytes=$(to_bytes "$pms")
                if [[ $ml_bytes -ne -1 && $pms_bytes -ge $ml_bytes ]]; then
                    echo "    ! [CVE-2026-109618 RISK] post_max_size ($pms) >= memory_limit ($ml)"
                    echo "      Multipart request parser can hit OOM fatal longjmp before script execution."
                    echo "      Recommendation: Set memory_limit higher than post_max_size, or enforce memory_limit = -1."
                fi
            fi
        fi

        if ! timeout 15 "$b" -t >/dev/null 2>&1; then
            echo "    ! CONFIG TEST FAILED (run: $b -t)"
        fi
    done

    # 3. Apache mod_php Modules
    echo
    echo "-- Apache mod_php Modules"
    local mod_files=() m m_ver
    shopt -s nullglob
    mod_files+=(/usr/lib/apache2/modules/libphp*.so
                /usr/lib64/httpd/modules/libphp*.so
                /etc/httpd/modules/libphp*.so)
    shopt -u nullglob

    declare -A seen_mod=()
    for m in "${mod_files[@]}"; do
        real=$(realpath -e -- "$m" 2>/dev/null) || continue
        [[ -n ${seen_mod[$real]:-} ]] && continue
        seen_mod[$real]=1
        if ! trusted_path "$real"; then continue; fi

        ((total_bin+=1))
        m_ver=$(strings "$real" 2>/dev/null | grep -E '^X-Powered-By: PHP/[0-9]' | head -n 1 | cut -d/ -f2 || true)
        [[ -z $m_ver ]] && m_ver=$(strings "$real" 2>/dev/null | grep -E 'PHP Version => [0-9]' | head -n 1 | awk '{print $4}' || true)
        [[ -z $m_ver ]] && m_ver="Installed"

        if [[ $m_ver != "Installed" ]]; then
            status=$(check_version_status "$m_ver")
            case $status in
                PATCHED)
                    printf '  %-40s %-12s [PATCHED]\n' "$m" "$m_ver"
                    ((total_patched+=1))
                    ;;
                EOL)
                    printf '  %-40s %-12s [VULNERABLE - EOL]\n' "$m" "$m_ver"
                    ((total_vuln+=1))
                    ((total_legacy+=1))
                    ;;
                UNPATCHED)
                    target_ver=$(get_target_version "$m_ver")
                    printf '  %-40s %-12s [VULNERABLE] (Requires update to >= %s)\n' "$m" "$m_ver" "$target_ver"
                    ((total_vuln+=1))
                    ;;
            esac
        else
            printf '  %-40s %-12s [INSTALLED - CHECK PACKAGE]\n' "$m" "$m_ver"
        fi
    done

    # 4. Summary & Critical Warning
    echo
    echo "================================================================================"
    echo " AUDIT SUMMARY: $total_bin binaries inspected | $total_patched patched | $total_vuln vulnerable ($total_legacy EOL)"
    if (( total_vuln > 0 )); then
        echo
        echo " >>> CRITICAL SECURITY ADVISORY <<<"
        echo " The configuration settings applied by this script (disabling upload_progress,"
        echo " setting php_admin_flag, recycling workers via pm.max_requests) are DEFENSIVE STOPGAPS."
        echo " They effectively disrupt known exploitation chains for CVE-2026-109618 & CVE-2026-109619."
        echo " However, the ONLY definitive, 100% resolution is upgrading PHP packages to:"
        echo "   - PHP 8.2.35+"
        echo "   - PHP 8.3.36+"
        echo "   - PHP 8.4.27+"
        echo "   - PHP 8.5.12+"
        if (( total_legacy > 0 )); then
            echo
            echo " ATTENTION FOR LEGACY PHP SOFTWARE:"
            echo " $total_legacy legacy PHP binary/binaries (PHP 5.x, 7.x, 8.0, 8.1) have reached End-of-Life (EOL)."
            echo " Official PHP project binary patches DO NOT exist for EOL versions."
            echo " For legacy software, you must rely on these pool/INI mitigations, maintain strict"
            echo " network/WAF perimeter protection, or acquire vendor LTS backports (e.g. CloudLinux,"
            echo " Ubuntu Pro ESM, Red Hat ELS, Remi Safe)."
        fi
    fi
    echo "================================================================================"
}

# ---------------------------------------------------------------- main

(( DRY_RUN )) && echo "== DRY RUN: nothing will be modified =="
if (( ${#PANELS[@]} )); then
    echo "Control panel detected: ${PANELS[*]}"
else
    echo "No control panel detected (standalone / self-hosted)"
fi
(( PANEL_MODE )) || echo "Paths given: only these paths are processed (no templates, no rebuild)."
echo "Searching: ${SEARCH[*]}"
echo

# 1. Inspect and patch base php.ini files
echo "-- ${INI_NAMES[*]} (Base PHP configurations)"
NAME_ARGS=()
for n in "${INI_NAMES[@]}"; do NAME_ARGS+=(-name "$n" -o); done
unset 'NAME_ARGS[-1]'
while IFS= read -r -d '' f <&3; do
    process_ini "$f" enforce
done 3< <(find_files "${NAME_ARGS[@]}")

# 2. Patch other drop-in .ini files that re-enable it
echo
echo "-- Other .ini files that set it (conf.d / php.d)"
while IFS= read -r -d '' f <&3; do
    process_ini "$f" fix
done 3< <(find_files -name '*.ini' ! -name php.ini ! -name .user.ini | xargs -0 -r grep -lZ -F -- "$DIRECTIVE")

# 3. Deploy persistent drop-ins across conf.d / php.d
deploy_dropins

# 4. Deploy Apache global mod_php hardening
deploy_apache_modphp

# 5. PHP-FPM pools and templates hardening
echo
echo "-- PHP-FPM pool configurations and templates"
POOLS_TO_PATCH=()
shopt -s nullglob
if (( PANEL_MODE )); then
    if (( IS_HESTIA )); then
        POOLS_TO_PATCH+=("$HESTIA_DIR"/data/templates/web/php-fpm/*.tpl
                         "$HESTIA_DIR"/install/deb/php-fpm/multiphp.tpl
                         "$HESTIA_DIR"/install/deb/templates/web/php-fpm/*.tpl
                         /etc/php/*/fpm/pool.d/*.conf)
    fi
    if (( IS_ISPC )); then
        src="$ISPC_DIR/server/conf/php_fpm_pool.conf.master"
        dst="$ISPC_DIR/server/conf-custom/php_fpm_pool.conf.master"
        if [[ ! -f $dst && -f $src ]]; then
            if (( DRY_RUN )); then
                echo "WOULD CREATE: $dst (copy of $src, so ISPConfig updates don't overwrite it)"
                POOLS_TO_PATCH+=("$src")
            else
                mkdir -p -- "${dst%/*}"
                cp -p -- "$src" "$dst"
                echo "CREATED: $dst (copy of $src, so ISPConfig updates don't overwrite it)"
            fi
        fi
        [[ -f $dst ]] && POOLS_TO_PATCH+=("$dst")
        POOLS_TO_PATCH+=(/etc/php/*/fpm/pool.d/web*.conf /opt/php-*/etc/php-fpm.d/*.conf)
    fi
    if (( IS_PLESK )); then
        POOLS_TO_PATCH+=(/opt/plesk/php/*/etc/php-fpm.d/*.conf
                         /var/www/vhosts/system/*/etc/php-fpm.conf
                         /etc/php-fpm.d/*.conf)
    fi
    if (( ! IS_HESTIA && ! IS_ISPC && ! IS_PLESK )); then
        # Standalone / self-hosted server without panel: patch all discovered FPM pools
        POOLS_TO_PATCH+=(/etc/php/*/fpm/pool.d/*.conf
                         /etc/php-fpm.d/*.conf
                         /etc/php*/php-fpm.d/*.conf
                         /etc/opt/remi/php*/php-fpm.d/*.conf
                         /usr/local/etc/php-fpm.d/*.conf)
    fi
else
    # Explicit PATH mode: also check for any pool files in the provided paths
    while IFS= read -r -d '' pf; do
        POOLS_TO_PATCH+=("$pf")
    done < <(find_files -name '*.conf' \( -path '*/pool.d/*' -o -path '*/php-fpm.d/*' \) 2>/dev/null)
fi
shopt -u nullglob

declare -A seen_pools=()
for t in "${POOLS_TO_PATCH[@]}"; do
    [[ -f $t ]] || continue
    real=$(realpath -e -- "$t" 2>/dev/null) || continue
    [[ -n ${seen_pools[$real]:-} ]] && continue
    seen_pools[$real]=1
    process_ini "$real" pool
done

# 6. Panel rebuilds
if (( PANEL_MODE && (IS_HESTIA || IS_ISPC || IS_PLESK) )); then
    echo
    if [[ $REBUILD == force ]] || { [[ $REBUILD == auto ]] && (( CHANGED > 0 )); }; then
        echo "-- Rebuilding vhosts"
        (( IS_HESTIA )) && rebuild_hestia
        (( IS_PLESK ))  && rebuild_plesk
        (( IS_ISPC ))   && rebuild_ispconfig
        if (( DRY_RUN )); then
            echo "  (dry run: sites listed above would be rebuilt)"
        elif (( SITES_OK + SITES_WARN + SITES_FAIL )); then
            echo "  Sites: OK $SITES_OK   check/pending $SITES_WARN   failed $SITES_FAIL"
            echo "  Report: $REPORT"
        fi
    elif [[ $REBUILD == no ]]; then
        echo "-- Rebuild skipped (--no-rebuild): templates and drop-ins are patched; run without it to regenerate the vhosts."
    else
        echo "-- Rebuild skipped: nothing changed in this run (use --force-rebuild to rebuild anyway)."
    fi
fi

# 7. Scan and report overrides
echo
echo "-- Overrides in FPM pools, vhosts, templates, .user.ini and .htaccess (report only)"
OVERRIDES=$(find_files -name '*.conf' -o -name '*.conf_*' -o -name '*.vhost' \
                       -o -name '*.tpl' -o -name '*.stpl' -o -name '*.master' \
                       -o -name .user.ini -o -name .htaccess \
    | xargs -0 -r grep -lZ -F -- "$DIRECTIVE" \
    | xargs -0 -r perl -ne "$PERL_AUDIT" || true)
if [[ -n $OVERRIDES ]]; then
    echo "WARNING: these lines re-enable vulnerable features. In pools with the php_admin_flag added by this script,"
    echo "         .user.ini/.htaccess lines no longer take effect; the rest must be reviewed manually:"
    echo "$OVERRIDES"
else
    echo "None."
fi

# 8. Real service restarts across all modes
if (( (LIVE_CHANGED || REBUILT_ANY) && DRY_RUN == 0 )); then
    restart_services
fi

# 9. Audit PHP binaries and versions
audit_binaries_and_versions

echo
if (( DRY_RUN )); then
    echo "Dry run finished. Would change: $CHANGED   Skipped: $SKIPPED   Errors: $ERRORS"
else
    echo "Done. Modified: $CHANGED   Skipped: $SKIPPED   Errors: $ERRORS"
fi

exit $(( ERRORS > 0 || SITES_FAIL > 0 ))
