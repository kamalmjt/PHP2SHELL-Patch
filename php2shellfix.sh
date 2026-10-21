#!/usr/bin/env bash
#
#  ____  _   _ ____ ____  ____  _   _ _____ _     _       _____ _____  __
# |  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |     |  ___|_ _\ \/ /
# | |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |     | |_   | | \  /
# |  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___  |  _|  | | /  \
# |_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____| |_|   |___/_/\_\
#
# php2shellfix.sh
# Disables session.upload_progress.enabled across the system's PHP configuration
# and, on HestiaCP / Plesk / ISPConfig, in the per-site configuration of every vhost.
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
#   1. php.ini         -> sets the directive to 0; adds it when it is not active
#                         (if absent, PHP falls back to its built-in default: On).
#                         Same for the copies listed in INI_NAMES (php.ini.vst.back,
#                         php.ini.ucf-dist), so a restore or ucf merge can't bring it back.
#   2. other *.ini     -> fixes active lines that re-enable it (conf.d / php.d drop-ins).
#   3. vhost templates -> PHP-FPM pool templates get
#                            php_admin_flag[session.upload_progress.enabled] = off
#                         which also stops sites from re-enabling it via .user.ini/ini_set.
#                           HestiaCP : data/templates/web/php-fpm/*.tpl and the install
#                                      copies used by v-add-web-php / v-update-web-templates
#                           ISPConfig: server/conf-custom/php_fpm_pool.conf.master
#                                      (created from server/conf/ if it does not exist)
#                           Plesk    : has no server-wide pool template; its per-domain
#                                      php.ini is built from the handler php.ini (step 1).
#   4. rebuild         -> when something changed (or with --force-rebuild), regenerates
#                         every vhost and reports each site:
#                           HestiaCP : v-rebuild-web-domain per domain + service restarts
#                           Plesk    : plesk bin php_settings -u + PHP-FPM reload
#                           ISPConfig: queues a resync of every website (as Tools > Resync
#                                      does) and runs server.sh to apply it
#                         The per-site result is also written to /var/log/php2shellfix-*.log
#   5. report only     -> *.conf, *.vhost, *.tpl, *.master, .user.ini and .htaccess lines
#                         that re-enable it (pools, vhosts, nginx PHP_VALUE, sites).
#   6. check           -> runs "php-fpm -t" and "php-fpm -i" on every PHP-FPM binary.
#
# Only writes to root-owned files whose path cannot be altered by another user,
# and never to the paths listed in EXCLUDE.
#
# Layouts covered:
#   Self-hosted  /etc/php/*/{fpm,cli,apache2,cgi,phpdbg}/php.ini (Debian/Ubuntu),
#                /etc/php.ini + /etc/php.d + /etc/php-fpm.d (RHEL), /etc/phpXY (Alpine),
#                /etc/opt/remi/phpXY (Remi SCL), /etc/php5 (legacy)
#   HestiaCP     panel PHP (/usr/local/hestia/php/lib/php.ini), templates, and the users'
#                web roots and per-domain configs (/home/*/web, /home/*/conf/web)
#   Plesk        /opt/plesk/php/*/etc (php.ini, php.d, php-fpm.d) and per-domain
#                /var/www/vhosts/system/*/{etc,conf}. The panel's own php.ini is excluded.
#   ISPConfig    per-site php.ini in /var/www/conf, pools in pool.d, *.vhost files,
#                *.master templates in /usr/local/ispconfig/server/conf{,-custom},
#                extra PHP versions in /opt
#
# Usage: php2shellfix.sh [--dry-run] [--no-rebuild | --force-rebuild] [PATH ...]
#   With PATH arguments only those paths are processed (steps 1, 2, 5, 6):
#   no templates and no rebuild. Useful for package hooks.
#
set -Eeuo pipefail

DIRECTIVE='session.upload_progress.enabled'
POOL_LINE='php_admin_flag[session.upload_progress.enabled] = off'
# php.ini plus copies that are not loaded by PHP but may be restored/merged later
# (VestaCP backups, ucf's pending package version). Add other names here if needed.
INI_NAMES=(php.ini php.ini.vst.back php.ini.ucf-dist)
DEFAULT_ROOTS=(/etc /opt /usr/local /var/www)
HESTIA_DIR="${HESTIA:-/usr/local/hestia}"
ISPC_DIR=/usr/local/ispconfig
# Never modified (reported as EXCLUDED). The Plesk panel's own PHP (sw-engine) is managed
# by Plesk and only serves the panel; remove it from this list if you want it patched too.
EXCLUDE=(/usr/local/psa/admin/conf/php.ini /opt/psa/admin/conf/php.ini)
# Never traversed: pseudo filesystems, container storage (image layers, LXC rootfs), mail and backups.
PRUNE=(/proc /sys /dev /run /var/lib/docker /var/lib/containerd /var/lib/lxc /var/lib/lxd /snap
       /backup '/home/*/mail' '/home/*/backup')

banner() {
    cat <<'BANNER'
 ____  _   _ ____ ____  ____  _   _ _____ _     _       _____ _____  __
|  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |     |  ___|_ _\ \/ /
| |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |     | |_   | | \  /
|  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___  |  _|  | | /  \
|_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____| |_|   |___/_/\_\

 Disables session.upload_progress.enabled in PHP
 Author: Kamal Majaiti EL Majaiti

 DISCLAIMER: provided "AS IS", without warranty of any kind. The author is not
 responsible or liable for the use or misuse of this script, nor for any damage
 or consequence arising from it. Use at your own risk; run --dry-run first.

BANNER
}

usage() {
    echo "Usage: ${0##*/} [--dry-run] [--no-rebuild | --force-rebuild] [PATH ...]"
    echo "  -n, --dry-run  show what would change (diffs, sites to rebuild) without touching anything"
    echo "  --no-rebuild   patch files and vhost templates, but do not rebuild the vhosts"
    echo "  --force-rebuild rebuild the vhosts even if nothing changed in this run"
    echo "                 (by default they are rebuilt only when something changed)"
    echo "  PATH           only process these directories: no templates, no rebuild"
    echo "                 (default: ${DEFAULT_ROOTS[*]}, plus /home/*/web and"
    echo "                 /home/*/conf/web on HestiaCP)"
    echo "Works on self-hosted PHP (/etc/php*), HestiaCP, Plesk and ISPConfig."
}

DRY_RUN=0
REBUILD=auto
ROOTS=()
for arg in "$@"; do
    case $arg in
        -n|--dry-run) DRY_RUN=1 ;;
        --no-rebuild) REBUILD=no ;;
        --force-rebuild) REBUILD=force ;;
        -h|--help)    banner; usage; exit 0 ;;
        -*)           usage >&2; exit 2 ;;
        *)            ROOTS+=("$arg") ;;
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

# --- Perl: rewrites a file. Args: mode(enforce|fix|pool) input output. Prints the action taken.
#   enforce: php.ini (fix active lines; uncomment or add when missing)
#   fix:     drop-in .ini (fix active lines only)
#   pool:    PHP-FPM pool template (php_admin_flag at the end of the pool section)
read -r -d '' PERL_FIX <<'PERL' || true
use strict; use warnings;
my ($mode, $in, $out) = @ARGV;
open(my $fh, "<:raw", $in) or die "Cannot read $in: $!\n";
my @l = <$fh>;
close $fh;
my $eol = (grep { /\r\n\z/ } @l) ? "\r\n" : "\n";
my $msg = "";

if ($mode eq "pool") {
    # Templates whose pool section is commented out (e.g. Hestia no-php.tpl) are left alone:
    # an active line outside a [pool] section would make php-fpm refuse to start.
    if (grep { /^[ \t]*\[[^\]]+\]/ } @l) {
        my $re = qr/^[ \t]*php_(?:admin_)?(?:value|flag)[ \t]*\[[ \t]*session\.upload_progress\.enabled[ \t]*\]/;
        my $replaced = grep { $_ =~ $re } @l;
        @l = grep { $_ !~ $re } @l;
        $l[-1] .= $eol if @l && $l[-1] !~ /\n\z/;
        push @l, "php_admin_flag[session.upload_progress.enabled] = off" . $eol;
        $msg = $replaced ? "pool template: $replaced existing line(s) replaced by php_admin_flag off"
                         : "pool template: php_admin_flag off added";
    }
} else {
    my $new = "session.upload_progress.enabled = 0";
    my $key = qr/session\.upload_progress\.enabled/;
    my ($active, $fixed, $commented, $section) = (0, 0);
    for my $i (0 .. $#l) {
        my ($le) = $l[$i] =~ /(\r?\n)\z/;
        if ($l[$i] =~ /^[ \t]*$key[ \t]*=([^\r\n]*)/) {
            $active++;
            (my $v = $1) =~ s/;.*//;
            $v =~ s/^\s+|\s+\z//g;
            $v =~ s/^(["'])(.*)\1\z/$2/;
            next if $v =~ /^(?:0|off|false|no|none|)\z/i;
            $l[$i] = $new . ($le // "");
            $fixed++;
        } elsif (!defined $commented && $l[$i] =~ /^[ \t]*;+[ \t]*$key[ \t]*=/) {
            $commented = $i;
        } elsif (!defined $section && $l[$i] =~ /^[ \t]*\[Session\][ \t]*\r?\n?\z/i) {
            $section = $i;
        }
    }
    if ($fixed) {
        $msg = "was enabled, set to 0";
    } elsif ($mode eq "enforce" && !$active) {
        if (defined $commented) {
            my ($le) = $l[$commented] =~ /(\r?\n)\z/;
            $l[$commented] = $new . ($le // "");
            $msg = "was commented out (default On), uncommented as 0";
        } elsif (defined $section) {
            $l[$section] .= $eol unless $l[$section] =~ /\n\z/;
            splice @l, $section + 1, 0, $new . $eol;
            $msg = "was missing (default On), added under [Session]";
        } else {
            unshift @l, $new . $eol;
            $msg = "was missing (default On), added at the top";
        }
    }
}
open(my $o, ">:raw", $out) or die "Cannot write $out: $!\n";
print {$o} @l;
close $o or die "Error writing $out: $!\n";
print $msg;
PERL

# --- Perl: reports active lines that set the directive to anything other than off.
read -r -d '' PERL_AUDIT <<'PERL' || true
if (!/^\s*[;#]/ && /session\.upload_progress\.enabled\]?[ \t]*=?[ \t]*["']?([A-Za-z0-9]*)/) {
    my $v = lc $1;
    (my $t = $_) =~ s/\s+\z//;
    print "  $ARGV:$.: $t\n" unless $v =~ /^(?:0|off|false|no|none)\z/;
}
close ARGV if eof;
PERL

find_files() {
    local prune=() p
    for p in "${PRUNE[@]}"; do prune+=(-path "$p" -o); done
    find -H "${SEARCH[@]}" \( "${prune[@]}" -false \) -prune -o -type f \( "$@" \) -print0 2>/dev/null
}

# Root-owned file, and no directory in its path writable by others (unless sticky).
# Prevents writing as root through a path another system user could redirect.
trusted_path() {
    local f=$1 d uid mode
    [[ $(stat -c %u -- "$f") == 0 ]] || return 1
    d=${f%/*}; d=${d:-/}
    while :; do
        read -r uid mode < <(stat -c '%u %a' -- "$d")
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

    if ! action=$(perl -e "$PERL_FIX" -- "$mode" "$file" "$tmp"); then
        echo "ERROR processing $file" >&2
        ((ERRORS+=1)); return 0
    fi

    if cmp -s -- "$file" "$tmp"; then
        case $mode in
            enforce) echo "OK (already disabled): $file" ;;
            pool)    if [[ -z $action ]]; then echo "SKIPPED (no active pool section): $file"
                     else echo "OK (template already enforces it): $file"; fi ;;
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
        if [[ $file == *.ini ]]; then
            LIVE_CHANGED=1
            if [[ $file == "$HESTIA_DIR"/* ]]; then PANEL_CHANGED=1; fi
        fi
    else
        echo "ERROR writing $file; restoring backup." >&2
        cat -- "$backup" > "$file" || echo "ERROR: restore failed. Backup at $backup" >&2
        ((ERRORS+=1))
    fi
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

# Last active line that sets the directive (any syntax) is off.
last_setting_off() {
    local last
    last=$(grep -E "$DIRECTIVE" -- "$1" 2>/dev/null | grep -vE '^[[:space:]]*[;#]' | tail -n 1)
    [[ -n $last ]] && grep -qiE '=[[:space:]]*"?(off|0|false|no|none)"?[[:space:]]*$' <<<"$last"
}

# An active line sets it to something other than off (= re-enables it).
enables_it() {
    [[ -n $(perl -ne "$PERL_AUDIT" -- "$1" 2>/dev/null) ]]
}

reload_fpm() {
    (( FPM_RELOADED )) && return 0
    FPM_RELOADED=1
    command -v systemctl >/dev/null 2>&1 || return 0
    local units=()
    mapfile -t units < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
        | awk '{print $1}' | grep -E '^[^ ]*php[^ ]*-fpm\.service$')
    if (( ${#units[@]} )); then
        echo "  Reloading: ${units[*]}"
        systemctl reload "${units[@]}" 2>&1 | sed 's/^/  /' || true
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
                elif last_setting_off "$pool"; then
                    report_site HestiaCP "$user/$domain" OK "rebuilt, $pool"
                else
                    report_site HestiaCP "$user/$domain" CHECK "rebuilt, but the pool does not disable it: $pool"
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
    local plesk domain out ini pool pools=() n=0 detail
    plesk=$(command -v plesk 2>/dev/null || echo /usr/sbin/plesk)
    if [[ ! -x $plesk ]]; then
        report_site Plesk "*" FAILED "plesk command not found"; return 0
    fi
    local domains=()
    mapfile -t domains < <("$plesk" bin site --list 2>/dev/null </dev/null | sed '/^[[:space:]]*$/d')
    if (( ${#domains[@]} == 0 )); then echo "  Plesk: no domains found."; return 0; fi
    if (( DRY_RUN )); then
        for domain in "${domains[@]}"; do report_site Plesk "$domain" "WOULD" "update PHP settings"; done
        return 0
    fi
    echo "  Plesk: regenerating per-domain PHP settings (plesk bin php_settings -u)..."
    if ! out=$("$plesk" bin php_settings -u </dev/null 2>&1); then
        echo "  WARNING: php_settings -u failed: $(tail -n 1 <<<"$out")"
    fi
    REBUILT_ANY=1
    reload_fpm
    for domain in "${domains[@]}"; do
        ini="/var/www/vhosts/system/$domain/etc/php.ini"
        shopt -s nullglob
        pools=(/opt/plesk/php/*/etc/php-fpm.d/"$domain".conf /etc/php/*/fpm/pool.d/"$domain".conf /etc/php-fpm.d/"$domain".conf)
        shopt -u nullglob
        detail=""
        for pool in "${pools[@]}"; do
            if enables_it "$pool"; then detail="pool re-enables it: $pool"; break; fi
        done
        if [[ -n $detail ]]; then
            report_site Plesk "$domain" CHECK "$detail"
        elif [[ -f $ini ]] && ! last_setting_off "$ini"; then
            report_site Plesk "$domain" CHECK "$ini does not disable it (default On)"
        elif [[ -f $ini ]]; then
            report_site Plesk "$domain" OK "$ini = 0"
        else
            report_site Plesk "$domain" OK "PHP-FPM: inherits the handler php.ini"
        fi
    done
}

# ISPConfig has no CLI resync. As its developers advise, this does what Tools > Resync
# does: a forced datalogUpdate() of every website through ISPConfig's own server library.
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
            report_site ISPConfig "$domain" OK "resynced (PHP mode '$php': uses the patched php.ini)"
        elif [[ -z ${pools[web$id.conf]:-} ]]; then
            report_site ISPConfig "$domain" PENDING "pool web$id.conf not found yet; see Monitor > Jobqueue"
        elif last_setting_off "${pools[web$id.conf]}"; then
            report_site ISPConfig "$domain" OK "resynced, ${pools[web$id.conf]}"
        else
            report_site ISPConfig "$domain" PENDING "${pools[web$id.conf]} not regenerated yet; see Monitor > Jobqueue"
        fi
    done <<<"$out"
    reload_fpm
}

# ---------------------------------------------------------------- main

(( DRY_RUN )) && echo "== DRY RUN: nothing will be modified =="
if (( ${#PANELS[@]} )); then
    echo "Control panel detected: ${PANELS[*]}"
else
    echo "No control panel detected (self-hosted)"
fi
(( PANEL_MODE )) || echo "Paths given: only these paths are processed (no templates, no rebuild)."
echo "Searching: ${SEARCH[*]}"
echo

echo "-- ${INI_NAMES[*]}"
NAME_ARGS=()
for n in "${INI_NAMES[@]}"; do NAME_ARGS+=(-name "$n" -o); done
unset 'NAME_ARGS[-1]'
while IFS= read -r -d '' f <&3; do
    process_ini "$f" enforce
done 3< <(find_files "${NAME_ARGS[@]}")

echo
echo "-- Other .ini files that set it (conf.d / php.d)"
while IFS= read -r -d '' f <&3; do
    process_ini "$f" fix
done 3< <(find_files -name '*.ini' ! -name php.ini ! -name .user.ini | xargs -0 -r grep -lZ -F -- "$DIRECTIVE")

if (( PANEL_MODE && (IS_HESTIA || IS_ISPC || IS_PLESK) )); then
    echo
    echo "-- Vhost PHP-FPM templates"
    TEMPLATES=()
    shopt -s nullglob
    if (( IS_HESTIA )); then
        TEMPLATES+=("$HESTIA_DIR"/data/templates/web/php-fpm/*.tpl
                    "$HESTIA_DIR"/install/deb/php-fpm/multiphp.tpl
                    "$HESTIA_DIR"/install/deb/templates/web/php-fpm/*.tpl)
    fi
    shopt -u nullglob
    if (( IS_ISPC )); then
        src="$ISPC_DIR/server/conf/php_fpm_pool.conf.master"
        dst="$ISPC_DIR/server/conf-custom/php_fpm_pool.conf.master"
        if [[ ! -f $dst && -f $src ]]; then
            if (( DRY_RUN )); then
                echo "WOULD CREATE: $dst (copy of $src, so ISPConfig updates don't overwrite it)"
                TEMPLATES+=("$src")
            else
                mkdir -p -- "${dst%/*}"
                cp -p -- "$src" "$dst"
                echo "CREATED: $dst (copy of $src, so ISPConfig updates don't overwrite it)"
            fi
        fi
        [[ -f $dst ]] && TEMPLATES+=("$dst")
    fi
    if (( IS_PLESK )); then
        echo "Plesk: no server-wide pool template; per-domain php.ini comes from the handler php.ini patched above."
    fi
    for t in "${TEMPLATES[@]}"; do
        [[ -f $t ]] && process_ini "$t" pool
    done
fi

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
        echo "-- Rebuild skipped (--no-rebuild): templates are patched; run without it to regenerate the vhosts."
    else
        echo "-- Rebuild skipped: nothing changed in this run (use --force-rebuild to rebuild anyway)."
    fi
fi

echo
echo "-- Overrides in FPM pools, vhosts, templates, .user.ini and .htaccess (report only)"
OVERRIDES=$(find_files -name '*.conf' -o -name '*.conf_*' -o -name '*.vhost' \
                       -o -name '*.tpl' -o -name '*.stpl' -o -name '*.master' \
                       -o -name .user.ini -o -name .htaccess \
    | xargs -0 -r grep -lZ -F -- "$DIRECTIVE" \
    | xargs -0 -r perl -ne "$PERL_AUDIT" || true)
if [[ -n $OVERRIDES ]]; then
    echo "WARNING: these lines re-enable it. In pools with the php_admin_flag added by this script,"
    echo "         .user.ini/.htaccess lines no longer take effect; the rest must be reviewed manually:"
    echo "$OVERRIDES"
else
    echo "None."
fi

echo
if (( DRY_RUN )); then
    echo "-- Current value per PHP-FPM binary (php-fpm -t / -i; pool overrides not included)"
else
    echo "-- Configured value per PHP-FPM binary (php-fpm -t / -i; pool overrides not included)"
fi
# Distro binaries, plus panel/custom builds: Plesk /opt/plesk/php/*, HestiaCP panel,
# ISPConfig extra versions (/opt/php-*), Remi SCL, DirectAdmin /usr/local/php*, etc.
shopt -s nullglob
FPM_BINS=(/usr/sbin/php-fpm*)
shopt -u nullglob
while IFS= read -r -d '' b; do FPM_BINS+=("$b"); done \
    < <(find /opt /usr/local -maxdepth 6 -type f -path '*/sbin/php-fpm*' -perm -u+x -print0 2>/dev/null)
declare -A SEEN=()
FOUND_FPM=0
for b in "${FPM_BINS[@]}"; do
    [[ -f $b && -x $b ]] || continue
    real=$(realpath -e -- "$b") || continue
    [[ -n ${SEEN[$real]:-} ]] && continue
    SEEN[$real]=1
    # Only run binaries no other user could have planted or replaced.
    if ! trusted_path "$real"; then echo "  $b: not root-owned/trusted, not executed"; continue; fi
    FOUND_FPM=1
    info=$(timeout 15 "$b" -i 2>/dev/null || true)
    ini=$(sed -n 's/^Loaded Configuration File => //p' <<<"$info")
    val=$(sed -n 's/^session\.upload_progress\.enabled => \([^ ]*\) => .*/\1/p' <<<"$info")
    flag=""
    if [[ ${val,,} == on || $val == 1 ]]; then
        if (( DRY_RUN )); then flag="  <-- ON"; else flag="  <-- STILL ON"; fi
    fi
    if ! timeout 15 "$b" -t >/dev/null 2>&1; then flag+="  <-- CONFIG TEST FAILED (run: $b -t)"; fi
    printf '  %-42s %-38s %s%s\n' "$b" "${ini:-?}" "${val:-?}" "$flag"
done
(( FOUND_FPM )) || echo "  No PHP-FPM binaries found."

echo
if (( DRY_RUN )); then
    echo "Dry run finished. Would change: $CHANGED   Skipped: $SKIPPED   Errors: $ERRORS"
else
    echo "Done. Modified: $CHANGED   Skipped: $SKIPPED   Errors: $ERRORS"
fi

if (( LIVE_CHANGED && DRY_RUN == 0 && REBUILT_ANY == 0 )); then
    units=()
    if command -v systemctl >/dev/null 2>&1; then
        mapfile -t units < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
            | awk '{print $1}' | grep -E '^([^ ]*php[^ ]*-fpm|apache2|httpd)\.service$')
    fi
    if (( ${#units[@]} )); then
        echo "To apply: systemctl reload ${units[*]}"
    else
        echo "To apply: reload the PHP-FPM / Apache services (or restart the containers) using these files."
    fi
fi
if (( PANEL_CHANGED && DRY_RUN == 0 )); then
    echo "HestiaCP panel PHP changed: systemctl restart hestia"
fi

exit $(( ERRORS > 0 || SITES_FAIL > 0 ))
