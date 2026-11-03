#!/usr/bin/env bash
# =============================================================================
#  Linux CIS Hardening Multitool v1.0
#  Автор: ilyabem
#  Описание: Интерактивный харденинг Linux-серверов по CIS Benchmark
#            (Level 1 / Level 2 Server, Debian/Ubuntu/Astra и RHEL-семейство).
#
#  Это «прокачанная» версия security_audit_linux: тот же движок применения
#  (add_fix → apply_password_policy / safe_apply_batch / simple_remediation),
#  тот же предохранитель от самоблокировки, но:
#    • опросник профиля сервера (роль, IPv6, GUI, USB, порты, SSH-доступ...),
#      от ответов зависит, какие пункты CIS применимы;
#    • ~200 проверок по разделам CIS 1–7, каждая с номером пункта и уровнем;
#    • бэкап и откат есть у ВСЕХ исправлений, включая «simple»: права, юниты
#      systemd, sysctl, пакеты — всё пишется в MANIFEST и откатывается;
#    • в каждом каталоге бэкапа лежит самодостаточный rollback.sh;
#    • сторож автоотката запускается через systemd-run (переживает обрыв
#      SSH и KillUserProcesses), с откатом на setsid-подпроцесс;
#    • новая критичная категория sudo (visudo -c + предохранитель);
#    • повторный аудит после исправлений и оценка соответствия в процентах;
#    • сохранение/загрузка ответов (--save-profile / --profile) для флота.
# =============================================================================

set -uo pipefail

if [[ -z "${BASH_VERSINFO[0]:-}" ]] || (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
    echo "Нужен Bash 4.3+ (ассоциативные массивы и nameref). Текущая версия: ${BASH_VERSION:-неизвестна}" >&2
    exit 1
fi

# ─────────────────────────── Цвета и форматирование ─────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

PASS="${GREEN}[✔ PASS]${RESET}"
FAIL="${RED}[✘ FAIL]${RESET}"
WARN="${YELLOW}[⚠ WARN]${RESET}"
INFO="${CYAN}[ℹ INFO]${RESET}"
SECTION="${BLUE}${BOLD}"

# ─────────────────────────── Глобальные переменные ──────────────────────────
VERSION="1.0"
REPORT_FILE="/tmp/cis_hardening_$(hostname -s 2>/dev/null || echo host)_$(date +%Y%m%d_%H%M%S).txt"
ISSUES=0
WARNINGS=0
PASSES=0
LAST_SCORE=""
NONINTERACTIVE=0
REPORT_ONLY=0
REAUDIT=0

# Отчёт может содержать имена пользователей, открытые порты и пути — создаём
# его сразу с правами 600, чтобы он не читался всей системой из /tmp.
if ( umask 077; : > "$REPORT_FILE" ) 2>/dev/null; then
    chmod 600 "$REPORT_FILE" 2>/dev/null || true
else
    REPORT_FILE="$(mktemp -t cis_hardening.XXXXXX 2>/dev/null)" || REPORT_FILE=/dev/null
    [[ "$REPORT_FILE" != /dev/null ]] && chmod 600 "$REPORT_FILE" 2>/dev/null
fi

# Пороговые значения. Дефолты — рекомендации CIS; при интерактивной настройке
# вместо них подставляются ТЕКУЩИЕ значения системы (seed_defaults_from_system),
# а рекомендация CIS показывается рядом.
CIS_LEVEL=1
MIN_PASS_LEN=14
PASS_MAX_AGE=365
PASS_MIN_AGE=1
PASS_WARN_AGE=7
PASS_HISTORY=24
PASS_INACTIVE=45
REQUIRE_UPPERCASE=1
REQUIRE_LOWERCASE=1
REQUIRE_DIGITS=1
REQUIRE_SPECIAL=1
SSH_IDLE_TIMEOUT=300
SHELL_TIMEOUT=900
MAX_AUTH_TRIES=4
FAIL_DENY=5                 # неудачных попыток до блокировки (pam_faillock)
FAIL_UNLOCK_MINUTES=15      # время блокировки, минут
UID_MIN=1000                # мин. UID, к которому применяется старение паролей
AUDIT_MAX_LOG_MB=32         # max_log_file в auditd.conf
CONFIRM_TIMEOUT=180         # сек. на подтверждение до авто-отката safe-apply
DO_ROLLBACK_GUARD=1         # 1 — включён предохранитель (авто-откат по таймауту)

# Рекомендации CIS для порогов: "ge" — значение должно быть не меньше, "le" — не больше
declare -A CIS_REF=(
    [MIN_PASS_LEN]="ge 14"   [PASS_MAX_AGE]="le 365"  [PASS_MIN_AGE]="ge 1"
    [PASS_WARN_AGE]="ge 7"   [PASS_HISTORY]="ge 24"   [PASS_INACTIVE]="le 45"
    [FAIL_DENY]="le 5"       [FAIL_UNLOCK_MINUTES]="ge 15"
    [SHELL_TIMEOUT]="le 900" [SSH_IDLE_TIMEOUT]="le 900" [MAX_AUTH_TRIES]="le 4"
)

# Переменные, которые попадают в файл профиля (--save-profile / --profile)
PROFILE_VARS=(CIS_LEVEL MIN_PASS_LEN PASS_MAX_AGE PASS_MIN_AGE PASS_WARN_AGE PASS_HISTORY
    PASS_INACTIVE REQUIRE_UPPERCASE REQUIRE_LOWERCASE REQUIRE_DIGITS REQUIRE_SPECIAL
    SSH_IDLE_TIMEOUT SHELL_TIMEOUT MAX_AUTH_TRIES FAIL_DENY FAIL_UNLOCK_MINUTES UID_MIN
    AUDIT_MAX_LOG_MB CONFIRM_TIMEOUT DO_ROLLBACK_GUARD)

# Ответы опросника: ключ → y/n или строка. Кэшируются, чтобы повторный аудит
# и повторный прогон меню не задавали те же вопросы.
declare -A ANS=()
STR_RESULT=""
# Список портов: "80", "443/tcp", "53/udp" через запятую или пробел (пусто — ничего)
PORTS_RE='^([0-9]{1,5}(/(tcp|udp))?([, ]+[0-9]{1,5}(/(tcp|udp))?)*)?$'

SYSCTL_FILE="/etc/sysctl.d/99-security-audit.conf"   # общий с security_audit.sh
MODPROBE_FILE="/etc/modprobe.d/cis-hardening.conf"
ROLLBACK_LOG="/var/log/security_toolkit_autorollback.log"

# ─────────────────────────── Вспомогательные функции ────────────────────────

# ANSI-последовательности нужны только терминалу; в файл отчёта пишем чистый
# текст, иначе отчёт нечитаем в любом редакторе/грепе.
strip_ansi() { sed -E $'s/\033\\[[0-9;]*[A-Za-z]//g'; }

log() {
    echo -e "$*"
    echo -e "$*" | strip_ansi >> "$REPORT_FILE"
}

log_only() {
    echo -e "$*" | strip_ansi >> "$REPORT_FILE"
}

print_banner() {
    [[ -t 1 ]] && clear 2>/dev/null
    log ""
    log "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    log "${CYAN}${BOLD}║        🛡  Linux CIS Hardening Multitool v${VERSION}  🛡                ║${RESET}"
    log "${CYAN}${BOLD}║      CIS Benchmark L1/L2 · github: ilyabem/security_audit_linux  ║${RESET}"
    log "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    log ""
    log "  ${DIM}Хост:     ${WHITE}$(hostname -f 2>/dev/null || hostname 2>/dev/null)${RESET}"
    log "  ${DIM}ОС:       ${WHITE}${OS_PRETTY}${RESET}  ${DIM}(семейство: ${OS_FAMILY})${RESET}"
    log "  ${DIM}Ядро:     ${WHITE}$(uname -r)${RESET}"
    log "  ${DIM}Дата:     ${WHITE}$(date '+%d.%m.%Y %H:%M:%S')${RESET}"
    log "  ${DIM}Отчёт:    ${WHITE}${REPORT_FILE}${RESET}"
    log ""
}

section() {
    local title="$1"
    log ""
    log "${SECTION}══════════════════════════════════════════════════════════════════${RESET}"
    log "${SECTION}  ▶  ${title}${RESET}"
    log "${SECTION}══════════════════════════════════════════════════════════════════${RESET}"
}

result_pass() { log "  ${PASS} $*"; PASSES=$((PASSES+1)); return 0; }
result_fail() { log "  ${FAIL} $*"; ISSUES=$((ISSUES+1)); return 0; }
result_warn() { log "  ${WARN} $*"; WARNINGS=$((WARNINGS+1)); return 0; }
result_info() { log "  ${INFO} $*"; return 0; }

# Сообщения движка отката: в основном скрипте — обычный INFO, в rollback.sh
# переопределяется на echo с меткой времени.
rb_log() { result_info "$*"; }

# Значения из конфигов могут оказаться мусором — перед (( )) всегда проверяем.
is_num() { [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }

# Пункт CIS применим к выбранному уровню профиля?
lvl() { (( CIS_LEVEL >= $1 )); }
skip_l2() { result_info "${DIM}[CIS $1] $2 — пункт Level 2, пропущен (профиль Level 1)${RESET}"; }

# Экранирование для построения команд, которые потом выполняются через eval.
q() { printf '%q' "$1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}${BOLD}[⚠] Внимание: запуск без root. Часть проверок будет недоступна, исправления — тоже.${RESET}"
        echo -e "${DIM}    Рекомендуется: sudo $0${RESET}"
        echo ""
        (( NONINTERACTIVE )) || sleep 2
    fi
}

HAVE_TTY=0
( : </dev/tty ) 2>/dev/null && HAVE_TTY=1

confirm() {
    local prompt="$1"
    local default="${2:-y}"
    local yn=""
    if [[ "$default" == "y" ]]; then
        printf "%b" "${YELLOW}${prompt} [Y/n]: ${RESET}" >/dev/tty
        read -r yn </dev/tty || yn=""
        [[ -z "$yn" || "$yn" =~ ^([Yy]|[Дд])$ ]]
    else
        printf "%b" "${YELLOW}${prompt} [y/N]: ${RESET}" >/dev/tty
        read -r yn </dev/tty || yn=""
        [[ "$yn" =~ ^([Yy]|[Дд])$ ]]
    fi
}

INT_RESULT=""
read_int() {
    local prompt="$1"
    local default="$2"
    local min="${3:-0}"
    local max="${4:-99999}"
    local val
    # Дефолт подставляется из системы и может выйти за диапазон — тогда Enter
    # никогда не проходил бы валидацию и пользователь застревал в цикле.
    is_num "$default" || default="$min"
    (( default < min )) && default="$min"
    (( default > max )) && default="$max"
    while true; do
        printf "%b" "${CYAN}${prompt} [по умолчанию: ${default}]: ${RESET}" >/dev/tty
        read -r val </dev/tty || val=""
        [[ -z "$val" ]] && val="$default"
        if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= min && val <= max )); then
            INT_RESULT="$val"
            return
        fi
        printf "%b\n" "${RED}  Введите число от $min до $max${RESET}" >/dev/tty
    done
}

# read_int + сравнение с рекомендацией CIS. Если введённое значение слабее,
# спрашиваем, оставить ли его; «нет» — подставляем значение CIS.
read_cis_int() {
    local var="$1" prompt="$2" min="$3" max="$4"
    local op ref sign weak
    read -r op ref <<< "${CIS_REF[$var]}"
    [[ "$op" == "ge" ]] && sign="≥" || sign="≤"
    while true; do
        read_int "${prompt} ${DIM}(CIS: ${sign}${ref})${RESET}${CYAN}" "${!var}" "$min" "$max"
        weak=0
        if [[ "$op" == "ge" ]]; then (( INT_RESULT < ref )) && weak=1; else (( INT_RESULT > ref )) && weak=1; fi
        if (( weak == 1 )) && ! confirm "  ${INT_RESULT} слабее рекомендации CIS (${sign}${ref}). Оставить?" n; then
            printf -v "$var" '%s' "$ref"
            continue
        fi
        printf -v "$var" '%s' "$INT_RESULT"
        return 0
    done
}

# Вопрос да/нет с кэшированием ответа в ANS[ключ].
# В --no-interactive берётся дефолт (он выбран консервативно — «не ломать»).
ask_yn() {
    local key="$1" prompt="$2" def="${3:-n}" hint="${4:-}"
    if [[ -z "${ANS[$key]:-}" ]]; then
        if (( NONINTERACTIVE )); then
            ANS[$key]="$def"
        else
            [[ -n "$hint" ]] && printf "%b\n" "${DIM}    ${hint}${RESET}" >/dev/tty
            if confirm "$prompt" "$def"; then ANS[$key]=y; else ANS[$key]=n; fi
        fi
    fi
    [[ "${ANS[$key]}" == "y" ]]
}

# Строковый вопрос с проверкой регулярным выражением. «-» — пустое значение.
ask_str() {
    local key="$1" prompt="$2" def="${3:-}" re="${4:-^.*$}" val
    if [[ -z "${ANS[$key]+set}" ]]; then
        if (( NONINTERACTIVE )); then
            ANS[$key]="$def"
        else
            while true; do
                printf "%b" "${CYAN}${prompt} [по умолчанию: ${def:-пусто}; «-» — пусто]: ${RESET}" >/dev/tty
                read -r val </dev/tty || val=""
                [[ -z "$val" ]] && val="$def"
                [[ "$val" == "-" ]] && val=""
                # shellcheck disable=SC1003  # '' здесь — шаблон «обратная косая черта»
                case "$val" in *'`'*|*'$'*|*'\'*|*'"'*) printf "%b\n" "${RED}  Символы \` \$ \\ \" недопустимы${RESET}" >/dev/tty; continue ;; esac
                [[ "$val" =~ $re ]] && break
                printf "%b\n" "${RED}  Недопустимое значение${RESET}" >/dev/tty
            done
            ANS[$key]="$val"
        fi
    fi
    STR_RESULT="${ANS[$key]}"
}

# Читает "key = value" / "key value" из конфиг-файла (pwquality.conf, faillock.conf,
# login.defs и т.п.). Возвращает пусто, если ключ не найден.
sys_kv() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    grep -E "^[[:space:]]*${key}[[:space:]]*[=]?[[:space:]]*-?[0-9]+" "$file" 2>/dev/null \
        | tail -1 | grep -oE -- '-?[0-9]+' | tail -1
    return 0
}

# Строковое значение "key value" / "key=value" (последнее активное вхождение).
# Всегда возвращает 0: вызывается как v="$(conf_get ...)" внутри `set -e`.
conf_get() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    grep -E "^[[:space:]]*${key}([[:space:]]|=)" "$file" 2>/dev/null | tail -1 \
        | sed -E "s/^[[:space:]]*${key}[[:space:]]*=?[[:space:]]*//; s/[[:space:]]+$//; s/^\"(.*)\"$/\\1/"
    return 0
}

detect_os_family() {
    if [[ -f /etc/os-release ]]; then
        local ID="" ID_LIKE=""
        # shellcheck disable=SC1091
        . /etc/os-release
        if [[ "${ID_LIKE:-}" =~ (debian|ubuntu) || "${ID:-}" =~ ^(debian|ubuntu|astra)$ ]]; then
            echo "debian"
        elif [[ "${ID_LIKE:-}" =~ (rhel|fedora|centos) || "${ID:-}" =~ ^(centos|rhel|rocky|almalinux|fedora|ol)$ ]]; then
            echo "rhel"
        else
            echo "unknown"
        fi
    else
        echo "unknown"
    fi
}

OS_FAMILY="$(detect_os_family)"
# shellcheck disable=SC1091
OS_ID="$(. /etc/os-release 2>/dev/null; echo "${ID:-unknown}")"
# shellcheck disable=SC1091
OS_PRETTY="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-$(uname -sr)}")"
if [[ "$OS_FAMILY" == "debian" ]]; then
    PAM_LIST=(/etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/common-account)
else
    PAM_LIST=(/etc/pam.d/system-auth /etc/pam.d/password-auth)
fi
PKG_MGR=""
for _pm in apt-get dnf yum; do command -v "$_pm" &>/dev/null && { PKG_MGR="$_pm"; break; }; done
unset _pm
ADMIN_USER="${SUDO_USER:-$(logname 2>/dev/null || id -un)}"
HAS_SYSTEMD=0
[[ -d /run/systemd/system ]] && HAS_SYSTEMD=1

# shellcheck disable=SC2016  # ${Status} — формат dpkg-query, а не переменная shell
pkg_installed() {
    case "$PKG_MGR" in
        apt-get) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'ok installed' ;;
        dnf|yum) rpm -q "$1" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

unit_exists() {
    (( HAS_SYSTEMD )) || return 1
    [[ -n "$(systemctl list-unit-files "$1" --no-legend 2>/dev/null)" ]]
}

unit_on() {  # включён или запущен
    systemctl is-enabled --quiet "$1" 2>/dev/null || systemctl is-active --quiet "$1" 2>/dev/null
}

user_home() { getent passwd "$1" 2>/dev/null | cut -d: -f6; }

# ═════════════════════════════════════════════════════════════════════════════
#  БЭКАП И ОТКАТ
#
#  Каждое применение получает каталог /root/security-toolkit-backup-<дата>-<кат>
#  (как в security_audit.sh). В нём:
#     CATEGORY     — категория (password/ssh/sudo/firewall/simple)
#     MANIFEST     — журнал того, что менялось, по строке на объект:
#                      F|путь|present|absent   — файл/каталог (копия в files/)
#                      M|путь|mode|uid|gid     — права до изменения
#                      U|юнит|enabled-state|active-state
#                      S|ключ sysctl|старое значение
#                      P|пакет                 — удалён, при откате переустановить
#                      A|feature               — включённая фича authselect
#                      R|сервис                — перезапустить после отката
#     files/       — копии файлов с полными путями
#     rollback.sh  — самодостаточный скрипт отката (ручной и для сторожа)
#  Для simple каждое исправление пишет в свой подкаталог NNN — его можно
#  откатить отдельно, если команда упала.
# ═════════════════════════════════════════════════════════════════════════════

CUR_BK_DIR=""
BK_NEW_RESULT=""

bk_new_dir() {
    local category="$1" base="/root" d
    [[ -d /root && -w /root ]] || base="/var/tmp"
    d="${base}/security-toolkit-backup-$(date +%Y%m%d-%H%M%S)-${category}"
    [[ -e "$d" ]] && d="${d}-$$-${RANDOM}"
    if ! mkdir -p "$d" 2>/dev/null; then
        d="/var/tmp/security-toolkit-backup-$(date +%Y%m%d-%H%M%S)-${category}-$$"
        mkdir -p "$d" 2>/dev/null || { result_fail "Не удалось создать каталог бэкапа"; return 1; }
    fi
    chmod 700 "$d" 2>/dev/null || true
    echo "$category" > "$d/CATEGORY"
    write_rollback_script "$d"
    BK_NEW_RESULT="$d"
    return 0
}

bk_sub_dir() {  # подкаталог для одного simple-исправления
    local parent="$1" idx="$2" d
    d="$parent/$(printf '%03d' "$idx")"
    mkdir -p "$d/files" || return 1
    : > "$d/MANIFEST"
    echo "simple" > "$d/CATEGORY"
    CUR_BK_DIR="$d"
}

bk_init_manifest() {
    mkdir -p "$1/files" && : > "$1/MANIFEST"
    CUR_BK_DIR="$1"
}

bk_has() { [[ -f "$CUR_BK_DIR/MANIFEST" ]] && awk -F'|' -v t="$1" -v p="$2" '$1==t && $2==p {f=1} END{exit !f}' "$CUR_BK_DIR/MANIFEST"; }

bk_file() {
    local p
    [[ -n "$CUR_BK_DIR" ]] || return 0
    for p in "$@"; do
        [[ -n "$p" ]] || continue
        bk_has F "$p" && continue
        if [[ -e "$p" || -L "$p" ]]; then
            cp -a --parents "$p" "$CUR_BK_DIR/files/" 2>/dev/null || return 1
            echo "F|${p}|present" >> "$CUR_BK_DIR/MANIFEST"
        else
            echo "F|${p}|absent" >> "$CUR_BK_DIR/MANIFEST"
        fi
    done
    return 0
}

bk_mode() {
    local p st
    [[ -n "$CUR_BK_DIR" ]] || return 0
    for p in "$@"; do
        [[ -e "$p" ]] || continue
        bk_has M "$p" && continue
        st="$(stat -c '%a|%u|%g' "$p" 2>/dev/null)" || continue
        echo "M|${p}|${st}" >> "$CUR_BK_DIR/MANIFEST"
    done
    return 0
}

bk_unit() {
    local u en ac
    [[ -n "$CUR_BK_DIR" ]] || return 0
    for u in "$@"; do
        bk_has U "$u" && continue
        # is-enabled/is-active возвращают 1 для выключенных юнитов — под set -e это не ошибка
        en="$(systemctl is-enabled "$u" 2>/dev/null)" || true; en="${en:-none}"
        ac="$(systemctl is-active "$u" 2>/dev/null)" || true; ac="${ac:-inactive}"
        echo "U|${u}|${en%%$'\n'*}|${ac%%$'\n'*}" >> "$CUR_BK_DIR/MANIFEST"
    done
    return 0
}

bk_sysctl() {
    local key="$1" old
    [[ -n "$CUR_BK_DIR" ]] || return 0
    bk_has S "$key" && return 0
    old="$(sysctl -n "$key" 2>/dev/null)" || return 0
    echo "S|${key}|${old//$'\t'/ }" >> "$CUR_BK_DIR/MANIFEST"
}

# Создать каталог; если его не было — записать в бэкап как absent, чтобы откат
# убрал и сам каталог, а не только файлы в нём.
bk_mkdir() {
    local d="$1" top="$1"
    [[ -d "$d" ]] && return 0
    while [[ ! -d "$(dirname "$top")" ]]; do top="$(dirname "$top")"; done
    bk_file "$top"
    mkdir -p "$d"
}

bk_note() {  # bk_note R|P|A значение
    [[ -n "$CUR_BK_DIR" ]] || return 0
    bk_has "$1" "$2" || echo "${1}|${2}" >> "$CUR_BK_DIR/MANIFEST"
}

# ── Функции отката. Они же целиком копируются в rollback.sh, поэтому
#    зависят только друг от друга и от rb_log.
pkg_reinstall() {
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q "$@"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q "$@"
    fi
}

ssh_reload() {
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null \
        || service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || true
}

fw_restore() {
    local d="$1" ufw_was="none" fwd_was="none" st
    [[ -f "$d/fw.state" ]] || return 0
    while IFS='=' read -r k st; do
        case "$k" in ufw) ufw_was="$st" ;; firewalld) fwd_was="$st" ;; esac
    done < "$d/fw.state"
    if command -v ufw >/dev/null 2>&1; then
        if [[ "$ufw_was" == "active" ]]; then
            ufw --force enable >/dev/null 2>&1; ufw reload >/dev/null 2>&1
        else
            ufw --force disable >/dev/null 2>&1
        fi
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        if [[ "$fwd_was" == "active" ]]; then
            systemctl start firewalld 2>/dev/null; firewall-cmd --reload >/dev/null 2>&1
        else
            systemctl stop firewalld 2>/dev/null
        fi
    fi
    # Ни ufw, ни firewalld не работали — значит, правила были «сырыми»
    if [[ "$ufw_was" != "active" && "$fwd_was" != "active" ]]; then
        if [[ -s "$d/nft.ruleset" ]] && command -v nft >/dev/null 2>&1; then
            nft flush ruleset 2>/dev/null && nft -f "$d/nft.ruleset" 2>/dev/null
        elif [[ -s "$d/iptables.rules" ]] && command -v iptables-restore >/dev/null 2>&1; then
            iptables-restore < "$d/iptables.rules" 2>/dev/null
            [[ -s "$d/ip6tables.rules" ]] && ip6tables-restore < "$d/ip6tables.rules" 2>/dev/null
        fi
    fi
    rb_log "Брандмауэр возвращён в исходное состояние (ufw=${ufw_was}, firewalld=${fwd_was})"
}

restore_dir() {
    local d="$1" i subs typ p a b c cat_name authsel=0
    [[ -d "$d" ]] || { rb_log "Каталог бэкапа не найден: $d"; return 1; }
    if [[ ! -f "$d/MANIFEST" ]]; then
        # simple: подкаталоги NNN откатываются в обратном порядке
        subs=("$d"/[0-9][0-9][0-9])
        for (( i=${#subs[@]}-1; i>=0; i-- )); do
            [[ -d "${subs[i]}" ]] && restore_dir "${subs[i]}"
        done
        return 0
    fi
    cat_name="$(cat "$d/CATEGORY" 2>/dev/null)"
    local -a restarts=()
    while IFS='|' read -r typ p a b c; do
        case "$typ" in
            F)
                if [[ "$a" == "present" ]]; then
                    mkdir -p "$(dirname "$p")"
                    if [[ -d "$d/files$p" && ! -L "$d/files$p" ]]; then
                        rm -rf "$p" && cp -a "$d/files$p" "$(dirname "$p")/"
                    else
                        rm -f "$p" 2>/dev/null; cp -a "$d/files$p" "$p"
                    fi
                else
                    rm -rf "$p"
                fi ;;
            M) chown "${b}:${c}" "$p" 2>/dev/null; chmod "$a" "$p" 2>/dev/null ;;
            U)
                systemctl unmask "$p" >/dev/null 2>&1
                case "$a" in
                    enabled|enabled-runtime) systemctl enable "$p" >/dev/null 2>&1 ;;
                    masked) systemctl mask "$p" >/dev/null 2>&1 ;;
                    disabled|none) systemctl disable "$p" >/dev/null 2>&1 ;;
                esac
                if [[ "$b" == "active" ]]; then
                    systemctl start "$p" >/dev/null 2>&1
                elif [[ "$a" != "masked" ]]; then
                    systemctl stop "$p" >/dev/null 2>&1
                fi ;;
            S) sysctl -qw "${p}=${a}" >/dev/null 2>&1 ;;
            P) pkg_reinstall "$p" >/dev/null 2>&1 || rb_log "Не удалось переустановить пакет $p" ;;
            A) command -v authselect >/dev/null 2>&1 && authselect disable-feature "$p" >/dev/null 2>&1; authsel=1 ;;
            R) restarts+=("$p") ;;
        esac
    done < <(tac "$d/MANIFEST")
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1
    (( authsel )) && authselect apply-changes -b >/dev/null 2>&1
    case "$cat_name" in
        ssh) ssh_reload ;;
        firewall) fw_restore "$d" ;;
        password) command -v faillock >/dev/null 2>&1 && faillock --reset >/dev/null 2>&1 ;;
    esac
    for p in ${restarts[@]+"${restarts[@]}"}; do
        case "$p" in
            auditd) pkill -HUP -x auditd 2>/dev/null || service auditd restart >/dev/null 2>&1 ;;
            augenrules) command -v augenrules >/dev/null 2>&1 && augenrules --load >/dev/null 2>&1 ;;
            sysctl) sysctl --system >/dev/null 2>&1 ;;
            *) systemctl try-restart "$p" >/dev/null 2>&1 ;;
        esac
    done
    rb_log "Восстановлено из ${d} (категория: ${cat_name:-?})"
    return 0
}

write_rollback_script() {
    local d="$1"
    {
        echo '#!/usr/bin/env bash'
        echo "# Откат изменений linux_cis_hardening.sh ($(date '+%F %T'))."
        echo "# Ручной запуск:  sudo bash ${d}/rollback.sh"
        echo 'set -uo pipefail'
        printf 'BK_DIR=%q\n' "$d"
        printf 'ROLLBACK_LOG=%q\n' "$ROLLBACK_LOG"
        # shellcheck disable=SC2016
        echo 'rb_log() { echo "[$(date "+%F %T")] $*"; }'
        declare -f pkg_reinstall ssh_reload fw_restore restore_dir
        cat <<'EOF'
MARKER="$BK_DIR/PENDING"
if [[ "${1:-}" == "--auto" ]]; then
    # Атомарно «забираем» маркер: если его уже снял основной скрипт
    # (пользователь ввёл YES) — откатывать нечего.
    mv "$MARKER" "$MARKER.taken" 2>/dev/null || exit 0
    exec >> "$ROLLBACK_LOG" 2>&1
    rb_log "АВТО-ОТКАТ ($(cat "$BK_DIR/CATEGORY" 2>/dev/null)): подтверждение не получено вовремя"
fi
restore_dir "$BK_DIR"
rm -f "$MARKER" "$MARKER.taken"
rb_log "Откат из $BK_DIR завершён"
EOF
    } > "$d/rollback.sh"
    chmod 700 "$d/rollback.sh" 2>/dev/null || true
}

# ═════════════════════════════════════════════════════════════════════════════
#  ПРИМИТИВЫ ИСПРАВЛЕНИЙ (все сами пишут бэкап в CUR_BK_DIR)
# ═════════════════════════════════════════════════════════════════════════════

pkg_install() {
    case "$PKG_MGR" in
        apt-get)
            # Индекс старше часа — обновляем, иначе install может не найти пакет
            if [[ -z "$(find /var/lib/apt/lists -maxdepth 0 -mmin -60 2>/dev/null)" ]]; then
                apt-get update -qq || echo "apt-get update: часть репозиториев недоступна"
            fi
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
        dnf|yum) "$PKG_MGR" install -y -q "$@" ;;
        *) echo "Пакетный менеджер не найден"; return 1 ;;
    esac
}

pkg_remove() {
    local p
    for p in "$@"; do
        pkg_installed "$p" || continue
        bk_note P "$p"
        case "$PKG_MGR" in
            apt-get) DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq "$p" ;;
            dnf|yum) "$PKG_MGR" remove -y -q "$p" ;;
        esac
    done
    return 0
}

svc_disable() {  # stop + disable + mask, с записью исходного состояния
    local u
    for u in "$@"; do
        unit_exists "$u" || continue
        bk_unit "$u"
        systemctl stop "$u" 2>/dev/null || true
        systemctl disable "$u" 2>/dev/null || true
        systemctl mask "$u" >/dev/null
    done
    return 0
}

svc_enable() {
    local u="$1"
    bk_unit "$u"
    systemctl unmask "$u" >/dev/null 2>&1 || true
    systemctl enable --now "$u"
}

# key = value в конфиге: активные строки с ключом удаляются, новая дописывается.
# sep: " = " (pwquality), " " (login.defs), "=" (dnf.conf). Пустое value → флаг.
conf_set() {
    local file="$1" key="$2" val="$3" sep="${4:- = }"
    bk_file "$file"
    bk_mkdir "$(dirname "$file")"
    [[ -f "$file" ]] || : > "$file"
    sed -i -E "/^[[:space:]]*${key}([[:space:]]|=|$)/d" "$file"
    if [[ -n "$val" ]]; then
        printf '%s%s%s\n' "$key" "$sep" "$val" >> "$file"
    else
        printf '%s\n' "$key" >> "$file"
    fi
    return 0
}

write_file() {  # путь, права, содержимое
    local p="$1" mode="$2" content="$3"
    bk_file "$p"
    bk_mkdir "$(dirname "$p")"
    printf '%s\n' "$content" > "$p"
    chmod "$mode" "$p"
    chown root:root "$p" 2>/dev/null || true
    return 0
}

# Права «не шире» max: оставляем существующие запреты, срезаем лишние биты.
fix_perm() {
    local p="$1" max="$2" owner="$3" group="$4" cur new
    [[ -e "$p" ]] || return 0
    bk_mode "$p"
    cur="$(stat -c '%a' "$p")"
    new="$(printf '%o' $(( 8#$cur & 8#$max )))"
    [[ -n "$owner" ]] && chown "$owner" "$p"
    [[ -n "$group" ]] && chgrp "$group" "$p"
    chmod "$new" "$p"
    return 0
}

sysctl_persist() {
    local key="$1" val="$2" file="$SYSCTL_FILE" esc f real
    esc="${key//./\\.}"
    bk_mkdir /etc/sysctl.d || return 1
    bk_file "$file"
    [[ -f "$file" ]] || printf '# Создан security_audit.sh / linux_cis_hardening.sh\n' > "$file"
    sed -i -E "/^[[:space:]]*#?[[:space:]]*${esc}[[:space:]]*=/d" "$file"
    printf '%s = %s\n' "$key" "$val" >> "$file"
    # Конфликтующие строки в sysctl.conf и в чужих файлах sysctl.d
    # (99-sysctl.conf сортируется ПОСЛЕ 99-security-audit.conf) нейтрализуем,
    # иначе «исправление» не переживёт перезагрузку.
    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
        [[ -f "$f" ]] || continue
        real="$(readlink -f "$f")"
        [[ "$real" == "$(readlink -f "$file")" ]] && continue
        grep -Eq "^[[:space:]]*${esc}[[:space:]]*=" "$real" 2>/dev/null || continue
        bk_file "$real"
        sed -i -E "s|^([[:space:]]*${esc}[[:space:]]*=.*)$|# disabled by security_audit: \\1|" "$real"
    done
    return 0
}

sysctl_set() {
    local key="$1" val="$2"
    bk_sysctl "$key"
    sysctl -qw "${key}=${val}"
    sysctl_persist "$key" "$val"
}

kmod_disable() {
    local m
    bk_file "$MODPROBE_FILE"
    bk_mkdir /etc/modprobe.d
    [[ -f "$MODPROBE_FILE" ]] || printf '# Создан linux_cis_hardening.sh (CIS 1.1.1.x / 3.2.x)\n' > "$MODPROBE_FILE"
    for m in "$@"; do
        sed -i -E "/^(install|blacklist)[[:space:]]+${m}([[:space:]]|$)/d" "$MODPROBE_FILE"
        printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m" >> "$MODPROBE_FILE"
        modprobe -r "$m" 2>/dev/null || rmmod "${m//-/_}" 2>/dev/null || true
    done
    return 0
}

grub_cfg_path() {
    local f
    for f in /boot/grub2/grub.cfg /boot/grub/grub.cfg; do
        [[ -f "$f" ]] && { echo "$f"; return 0; }
    done
    return 1
}

grub_regen() {
    local cfg
    cfg="$(grub_cfg_path)" || { echo "grub.cfg не найден"; return 1; }
    bk_file "$cfg"
    if command -v update-grub &>/dev/null; then
        update-grub
    elif command -v grub2-mkconfig &>/dev/null; then
        grub2-mkconfig -o "$cfg"
    else
        echo "Нет update-grub/grub2-mkconfig"; return 1
    fi
}

# Добавляет параметры ядра: в /etc/default/grub (для будущих ядер) и через
# grubby в BLS-записи RHEL. Вступает в силу после перезагрузки.
grub_add_args() {
    local a cur
    [[ -f /etc/default/grub ]] || { echo "/etc/default/grub не найден"; return 1; }
    bk_file /etc/default/grub
    cur="$(conf_get /etc/default/grub GRUB_CMDLINE_LINUX)"
    for a in "$@"; do
        [[ " $cur " == *" ${a%%=*}="* || " $cur " == *" $a "* ]] && cur="$(sed -E "s/(^| )${a%%=*}(=[^ ]*)?( |$)/\\1\\3/; s/  +/ /g" <<< "$cur")"
        cur="${cur:+$cur }$a"
    done
    sed -i -E '/^[[:space:]]*GRUB_CMDLINE_LINUX=/d' /etc/default/grub
    printf 'GRUB_CMDLINE_LINUX="%s"\n' "$cur" >> /etc/default/grub
    if command -v grubby &>/dev/null && [[ -d /boot/loader/entries ]]; then
        bk_file /boot/loader/entries
        grubby --update-kernel=ALL --args="$*"
    else
        grub_regen
    fi
}

fstab_add_opts() {
    local mnt="$1" opts="$2" tmp
    bk_file /etc/fstab
    tmp="$(mktemp)"
    awk -v m="$mnt" -v o="$opts" '
        BEGIN { n = split(o, want, ",") }
        /^[[:space:]]*#/ || NF < 4 { print; next }
        $2 == m {
            cur = $4
            for (i = 1; i <= n; i++) if (("," cur ",") !~ ("," want[i] ",")) cur = cur "," want[i]
            $4 = cur
        }
        { print }' /etc/fstab > "$tmp"
    cat "$tmp" > /etc/fstab
    rm -f "$tmp"
    if findmnt --help 2>/dev/null | grep -q -- '--verify'; then
        findmnt --verify --tab-file /etc/fstab 2>&1 | grep -Eq '(^|[^0-9])0 errors' \
            || { echo "findmnt --verify: /etc/fstab содержит ошибки"; return 1; }
    fi
    mount -o remount "$mnt"
}

devshm_harden() {
    if grep -Eq '^[^#[:space:]]+[[:space:]]+/dev/shm[[:space:]]' /etc/fstab; then
        fstab_add_opts /dev/shm nodev,nosuid,noexec
    else
        bk_file /etc/fstab
        printf 'tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0\n' >> /etc/fstab
        mount -o remount,nodev,nosuid,noexec /dev/shm
    fi
}

tmp_mount_enable() {
    local unit=/etc/systemd/system/tmp.mount
    bk_file "$unit"
    bk_unit tmp.mount
    cat > "$unit" <<'EOF'
# Создан linux_cis_hardening.sh (CIS 1.1.2.1)
[Unit]
Description=Temporary Directory /tmp
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nosuid,nodev,noexec,size=50%%,nr_inodes=1m

[Install]
WantedBy=local-fs.target
EOF
    systemctl daemon-reload
    systemctl unmask tmp.mount >/dev/null 2>&1 || true
    systemctl enable tmp.mount
    echo "tmp.mount включён — /tmp станет tmpfs после перезагрузки"
}

fix_sticky_dirs() {
    local dd
    fs_scan
    while read -r dd; do
        [[ -d "$dd" ]] || continue
        bk_mode "$dd"
        chmod a+t "$dd"
    done < <(awk '$1=="SD"{ sub(/^SD /,""); print }' <<< "$FS_SCAN")
    return 0
}

fix_world_writable() {
    local f
    fs_scan
    while read -r f; do
        [[ -f "$f" ]] || continue
        bk_mode "$f"
        chmod o-w "$f"
    done < <(awk '$1=="WW"{ sub(/^WW /,""); print }' <<< "$FS_SCAN")
    return 0
}

fix_varlog_perms() {
    local f base
    while read -r f; do
        base="${f##*/}"
        bk_mode "$f"
        case "$base" in
            wtmp*|btmp*|lastlog*) chmod ug-x,o-wx "$f" ;;   # ≤ 664
            *) chmod g-wx,o-rwx "$f" ;;                       # ≤ 640
        esac
    done < <(varlog_bad_files)
    return 0
}

varlog_bad_files() {
    find /var/log -type f \( -perm /0137 -o -perm /0011 \) 2>/dev/null | while read -r f; do
        case "${f##*/}" in
            wtmp*|btmp*|lastlog*) [[ -n "$(find "$f" -perm /0113 2>/dev/null)" ]] && echo "$f" ;;
            *) echo "$f" ;;
        esac
    done
}

banner_write() {  # путь, текст
    write_file "$1" 644 "$2"
}

# ── SSH (логика security_audit.sh: в OpenSSH побеждает ПЕРВОЕ вхождение) ──
SSHD_EFFECTIVE=""
SSHD_SOURCE=""

sshd_bin() {
    local b
    for b in /usr/sbin/sshd /sbin/sshd "$(command -v sshd 2>/dev/null || true)"; do
        [[ -n "$b" && -x "$b" ]] && { echo "$b"; return 0; }
    done
    return 1
}

build_sshd_effective() {
    SSHD_EFFECTIVE=""; SSHD_SOURCE=""
    local main="/etc/ssh/sshd_config" bin
    [[ -f "$main" ]] || return 1

    if [[ $EUID -eq 0 ]] && bin="$(sshd_bin)"; then
        SSHD_EFFECTIVE="$("$bin" -T 2>/dev/null)"
        if [[ -n "$SSHD_EFFECTIVE" ]]; then
            SSHD_SOURCE="sshd -T"
            return 0
        fi
    fi

    # Include раскрывается НА МЕСТЕ: в OpenSSH выигрывает первое вхождение
    # ключа, поэтому порядок строк принципиален.
    local line pat inc f
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*[Ii]nclude[[:space:]]+(.*)$ ]]; then
            pat="${BASH_REMATCH[1]}"
            for inc in $pat; do
                [[ "$inc" != /* ]] && inc="/etc/ssh/${inc}"
                for f in $inc; do
                    [[ -f "$f" ]] && SSHD_EFFECTIVE+="$(cat "$f" 2>/dev/null)"$'\n'
                done
            done
        else
            SSHD_EFFECTIVE+="${line}"$'\n'
        fi
    done < "$main" 2>/dev/null
    SSHD_SOURCE="sshd_config + Include"
    return 0
}

# Значения OpenSSH по умолчанию: без root (нет sshd -T) незаданный параметр
# иначе выглядел бы как нарушение, хотя действует безопасный дефолт.
declare -A SSH_DEFAULTS=(
    [x11forwarding]=no [hostbasedauthentication]=no [ignorerhosts]=yes [permitemptypasswords]=no
    [permituserenvironment]=no [gssapiauthentication]=no [loglevel]=INFO [allowtcpforwarding]=yes
    [allowagentforwarding]=yes [disableforwarding]=no [usepam]=no [maxauthtries]=6 [maxsessions]=10
    [logingracetime]=120 [maxstartups]=10:30:100 [permitrootlogin]=prohibit-password
    [passwordauthentication]=yes [clientaliveinterval]=0 [clientalivecountmax]=3
)

get_ssh_param() {
    local param="$1" v
    if [[ "$SSHD_SOURCE" == "sshd -T" ]]; then
        awk -v p="${param,,}" 'tolower($1)==p {v=$2} END{ if (v!="") print v }' <<< "$SSHD_EFFECTIVE"
    else
        v="$(grep -Ei "^[[:space:]]*${param}[[:space:]]" <<< "$SSHD_EFFECTIVE" \
            | grep -v "^[[:space:]]*#" | head -1 | awk '{print $2}')"
        echo "${v:-${SSH_DEFAULTS[${param,,}]:-}}"
    fi
}

# DisableForwarding появился в OpenSSH 7.4
ssh_has_disableforwarding() {
    local ver
    if [[ "$SSHD_SOURCE" == "sshd -T" ]]; then
        grep -qi '^disableforwarding ' <<< "$SSHD_EFFECTIVE"
        return
    fi
    ver="$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | head -1 | cut -d_ -f2)"
    [[ -n "$ver" ]] && { (( ${ver%%.*} > 7 )) || (( ${ver%%.*} == 7 && ${ver#*.} >= 4 )); }
}

get_ssh_param_full() {
    local param="$1"
    if [[ "$SSHD_SOURCE" == "sshd -T" ]]; then
        awk -v p="${param,,}" 'tolower($1)==p { $1=""; sub(/^[[:space:]]+/,""); v=$0 } END{ if (v!="") print v }' <<< "$SSHD_EFFECTIVE"
    else
        grep -Ei "^[[:space:]]*${param}[[:space:]]" <<< "$SSHD_EFFECTIVE" \
            | grep -v "^[[:space:]]*#" | head -1 | sed -E 's/^[[:space:]]*[^[:space:]]+[[:space:]]+//'
    fi
}

# Записывает директиву так, чтобы она гарантированно победила: конфликтующие
# строки в drop-in'ах комментируются, а наша вставляется первой строкой
# основного файла (до Include и до любого Match).
# БЫЛО (security_audit.sh): бэкап брал только sshd_config, а функция правит
# и sshd_config.d/*.conf — при откате drop-in'ы оставались закомментированными.
ssh_set_param() {
    local key="$1" val="$2" main="/etc/ssh/sshd_config" f
    [[ -f "$main" ]] || return 1
    bk_file "$main"
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$f" ]] || continue
        grep -Eqi "^[[:space:]]*${key}[[:space:]]" "$f" || continue
        bk_file "$f"
        sed -i -E "s|^([[:space:]]*${key}[[:space:]].*)$|# disabled by security_audit: \\1|I" "$f"
    done
    sed -i -E "/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]/Id" "$main"
    sed -i "1i ${key} ${val}" "$main"
}

ssh_disable_hostkey() {  # закомментировать HostKey с заданным типом
    local kind="$1" main="/etc/ssh/sshd_config"
    bk_file "$main"
    sed -i -E "s|^([[:space:]]*HostKey[[:space:]].*_${kind}_key.*)$|# disabled by linux_cis_hardening: \\1|I" "$main"
}

ssh_banner_set() {
    if [[ ! -s /etc/issue.net ]]; then
        banner_write /etc/issue.net "$BANNER_TEXT"
    fi
    ssh_set_param Banner /etc/issue.net
}

# Из предпочтительного списка алгоритмов оставляет поддерживаемые этим OpenSSH
ssh_supported() {
    local kind="$1"; shift
    local have out="" a
    # Без ssh -Q не знаем, что поддерживает эта сборка, — лучше не предлагать
    # фикс, чем вписать алгоритм, на котором sshd -t упадёт
    have="$(ssh -Q "$kind" 2>/dev/null)" || return 0
    for a in "$@"; do
        grep -qxF "$a" <<< "$have" && out+="${out:+,}$a"
    done
    echo "$out"
}

# ── Брандмауэр ──
SSH_PORTS=()
detect_ssh_ports() {
    local p
    SSH_PORTS=()
    [[ -n "$SSHD_EFFECTIVE" ]] || build_sshd_effective
    if [[ "$SSHD_SOURCE" == "sshd -T" ]]; then
        while read -r p; do is_num "$p" && SSH_PORTS+=("$p"); done < <(awk 'tolower($1)=="port"{print $2}' <<< "$SSHD_EFFECTIVE")
    else
        while read -r p; do is_num "$p" && SSH_PORTS+=("$p"); done < <(grep -Ei '^[[:space:]]*port[[:space:]]+[0-9]+' <<< "$SSHD_EFFECTIVE" | awk '{print $2}')
    fi
    while read -r p; do is_num "$p" && SSH_PORTS+=("$p"); done < <(listening_ports | awk '$3 ~ /^sshd/ {print $2}')
    (( ${#SSH_PORTS[@]} )) || SSH_PORTS=(22)
    mapfile -t SSH_PORTS < <(printf '%s\n' "${SSH_PORTS[@]}" | sort -un)
}

# "proto порт процесс" для сокетов, слушающих не только loopback
listening_ports() {
    ss -Hlntup 2>/dev/null | awk '{
        loc=$5; n=split(loc, a, ":"); port=a[n]; addr=substr(loc, 1, length(loc)-length(port)-1)
        if (addr ~ /^(127\.|\[::1\]|::1|\[::ffff:127\.)/ || addr ~ /%lo$/) next
        p="?"; if (match($0, /\("[^"]+"/)) p=substr($0, RSTART+2, RLENGTH-3)
        proto=($1 ~ /^udp/) ? "udp" : "tcp"
        print proto, port, p
    }' | sort -u
}

fw_snapshot() {
    local d="$CUR_BK_DIR" ufw_st="none" fwd_st="none"
    if command -v ufw &>/dev/null; then
        ufw status 2>/dev/null | grep -q 'Status: active' && ufw_st=active || ufw_st=inactive
        bk_file /etc/ufw /etc/default/ufw
        bk_unit ufw.service
    fi
    if command -v firewall-cmd &>/dev/null; then
        systemctl is-active --quiet firewalld 2>/dev/null && fwd_st=active || fwd_st=inactive
        bk_file /etc/firewalld
        bk_unit firewalld.service
    fi
    printf 'ufw=%s\nfirewalld=%s\n' "$ufw_st" "$fwd_st" > "$d/fw.state"
    command -v iptables-save &>/dev/null && iptables-save > "$d/iptables.rules" 2>/dev/null
    command -v ip6tables-save &>/dev/null && ip6tables-save > "$d/ip6tables.rules" 2>/dev/null
    command -v nft &>/dev/null && nft list ruleset > "$d/nft.ruleset" 2>/dev/null
    return 0
}

# allow_in/allow_out — списки "порт/proto" через пробел
fw_ufw_configure() {
    local allow_in="$1" allow_out="$2" deny_out="$3" deny_routed="$4" r
    command -v ufw &>/dev/null || pkg_install ufw
    pkg_installed iptables-persistent && pkg_remove iptables-persistent
    bk_file /etc/ufw /etc/default/ufw
    # SSH-порты — ПЕРВЫМИ, до смены политики по умолчанию
    for r in $allow_in; do ufw allow in "$r" >/dev/null; done
    ufw allow in on lo >/dev/null
    ufw allow out on lo >/dev/null
    ufw deny in from 127.0.0.0/8 >/dev/null
    if grep -qi '^IPV6=yes' /etc/default/ufw 2>/dev/null; then ufw deny in from ::1 >/dev/null; fi
    ufw default deny incoming >/dev/null
    if [[ "$deny_out" == "y" ]]; then
        for r in $allow_out; do ufw allow out "$r" >/dev/null; done
        ufw default deny outgoing >/dev/null
    else
        ufw default allow outgoing >/dev/null
    fi
    [[ "$deny_routed" == "y" ]] && ufw default deny routed >/dev/null
    ufw --force enable >/dev/null
    systemctl enable ufw >/dev/null 2>&1 || true
}

fw_firewalld_configure() {
    local allow_in="$1" remove_svcs="$2" zone r s
    command -v firewall-cmd &>/dev/null || pkg_install firewalld
    bk_file /etc/firewalld
    systemctl unmask firewalld >/dev/null 2>&1 || true
    # CIS: одновременно должна работать только одна утилита
    unit_exists nftables.service && systemctl is-enabled --quiet nftables 2>/dev/null && svc_disable nftables.service
    unit_exists iptables.service && systemctl is-enabled --quiet iptables 2>/dev/null && svc_disable iptables.service
    bk_unit firewalld.service
    systemctl enable --now firewalld
    zone="$(firewall-cmd --get-default-zone)"
    for r in $allow_in; do firewall-cmd --permanent --zone="$zone" --add-port="$r" >/dev/null; done
    firewall-cmd --permanent --zone=trusted --add-interface=lo >/dev/null 2>&1 || true
    for s in $remove_svcs; do firewall-cmd --permanent --zone="$zone" --remove-service="$s" >/dev/null; done
    firewall-cmd --reload >/dev/null
}

# Разрешённые входящие порты активного/настроенного брандмауэра: "порт/proto"
fw_allowed_ports() {
    local backend="$1" zone s
    case "$backend" in
        ufw)
            ufw show added 2>/dev/null | awk '/^ufw (allow|limit)/ && !/ out / {
                for (i=3; i<=NF; i++) if ($i ~ /^[0-9]+(\/(tcp|udp))?$/) { print $i } else if ($i == "port" && $(i+1) ~ /^[0-9]+$/) print $(i+1) }'
            ufw show added 2>/dev/null | grep -qE "allow (in )?OpenSSH" && echo "22/tcp" ;;
        firewalld)
            zone="$(firewall-cmd --get-default-zone 2>/dev/null)"
            firewall-cmd --permanent --zone="$zone" --list-ports 2>/dev/null | tr ' ' '\n'
            for s in $(firewall-cmd --permanent --zone="$zone" --list-services 2>/dev/null); do
                firewall-cmd --permanent --service="$s" --get-ports 2>/dev/null | tr ' ' '\n'
            done ;;
    esac
}

port_allowed() {  # список, порт, proto
    grep -Eq "^${2}(/${3})?$" <<< "$1"
}

fw_validate_ssh() {
    local backend p allowed
    backend="$(fw_backend)"
    allowed="$(fw_allowed_ports "$backend")"
    for p in "${SSH_PORTS[@]}"; do
        if ! port_allowed "$allowed" "$p" tcp; then
            result_fail "SSH-порт ${p}/tcp не разрешён в ${backend} — это отрезало бы доступ"
            return 1
        fi
    done
    result_pass "SSH-порты (${SSH_PORTS[*]}) разрешены в ${backend}"
}

fw_backend() {
    if systemctl is-active --quiet firewalld 2>/dev/null; then echo firewalld
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then echo ufw
    elif command -v firewall-cmd &>/dev/null; then echo firewalld
    elif command -v ufw &>/dev/null; then echo ufw
    elif [[ "$OS_FAMILY" == "rhel" ]]; then echo firewalld
    else echo ufw
    fi
}

# ── sudo ──
SUDO_DROPIN="/etc/sudoers.d/60-cis-hardening"
sudo_files() { printf '%s\n' /etc/sudoers; find /etc/sudoers.d -maxdepth 1 -type f ! -name '*~' ! -name '*.*' 2>/dev/null; return 0; }
sudo_grep() {
    local -a files=()
    mapfile -t files < <(sudo_files)
    grep -hsE "$1" "${files[@]}" 2>/dev/null | grep -v '^[[:space:]]*#'
}

sudo_set_defaults() {
    local log_file="$1" ts="$2"
    bk_file "$SUDO_DROPIN"
    ( umask 0227
      cat > "$SUDO_DROPIN" <<EOF
# Создан linux_cis_hardening.sh (CIS 5.2.2–5.2.6)
Defaults use_pty
Defaults logfile="${log_file}"
Defaults timestamp_timeout=${ts}
EOF
    )
    chmod 440 "$SUDO_DROPIN"
    visudo -cq -f "$SUDO_DROPIN"
}

# ── Учётные записи ──
lock_accounts() { local u; bk_file /etc/shadow; for u in "$@"; do passwd -l "$u" >/dev/null; done; return 0; }

set_nologin() {
    local u nologin
    nologin="$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)"
    bk_file /etc/passwd /etc/shadow
    for u in "$@"; do usermod -s "$nologin" "$u"; passwd -l "$u" >/dev/null 2>&1 || true; done
    return 0
}

fix_home_dirs() {
    local u h
    while IFS=: read -r u h; do
        [[ -d "$h" ]] || continue
        bk_mode "$h"
        chown "$u" "$h"
        chmod g-w,o-rwx "$h"
    done < <(login_users_homes)
    return 0
}

fix_dotfiles() {
    local u h f
    while IFS=: read -r u h; do
        [[ -d "$h" ]] || continue
        for f in "$h"/.[!.]*; do
            [[ -f "$f" && ! -L "$f" ]] || continue
            case "${f##*/}" in
                .netrc|.rhosts|.forward|.shosts) bk_file "$f"; rm -f "$f" ;;
                .bash_history) bk_mode "$f"; chmod 600 "$f" ;;
                *) bk_mode "$f"; chmod go-w "$f" ;;
            esac
        done
    done < <(login_users_homes)
    return 0
}

login_users_homes() {
    awk -F: -v min="$UID_MIN" '($3 >= min || $3 == 0) && $7 !~ /(nologin|false|sync|shutdown|halt)$/ && $1 != "nobody" {print $1 ":" $6}' /etc/passwd 2>/dev/null
}

# ── Аудит (auditd) ──
auditd_reload() {
    if systemctl is-active --quiet auditd 2>/dev/null; then
        service auditd reload 2>/dev/null || pkill -HUP -x auditd 2>/dev/null || true
    fi
    return 0
}

# Оставляет только системные вызовы, известные этой архитектуре
sc_filter() {
    local arch="$1" machine; shift
    local out="" s
    # ausyscall понимает имена машин, а не b64/b32 auditctl
    machine="$(uname -m)"
    [[ "$arch" == "b32" ]] && machine="i386"
    for s in "$@"; do
        if ! command -v ausyscall &>/dev/null || ausyscall "$machine" "$s" --exact >/dev/null 2>&1; then
            out+="${out:+,}$s"
        fi
    done
    echo "$out"
}

audit_rules_content() {
    local archs=(b64) a sc uid_min="$UID_MIN" sudo_log p
    [[ "$(uname -m)" == "x86_64" ]] && archs=(b64 b32)
    sudo_log="$(sudo_logfile)"
    echo "## Создан linux_cis_hardening.sh — CIS 6.2.3.x (правила аудита)"
    echo "-w /etc/sudoers -p wa -k scope"
    echo "-w /etc/sudoers.d -p wa -k scope"
    for a in "${archs[@]}"; do
        echo "-a always,exit -F arch=$a -C euid!=uid -F auid!=unset -S execve -k user_emulation"
        sc="$(sc_filter "$a" adjtimex settimeofday clock_settime stime)"
        [[ -n "$sc" ]] && echo "-a always,exit -F arch=$a -S $sc -k time-change"
        sc="$(sc_filter "$a" sethostname setdomainname)"
        [[ -n "$sc" ]] && echo "-a always,exit -F arch=$a -S $sc -k system-locale"
        echo "-a always,exit -F arch=$a -S mount -F auid>=${uid_min} -F auid!=unset -k mounts"
        sc="$(sc_filter "$a" unlink unlinkat rename renameat)"
        [[ -n "$sc" ]] && echo "-a always,exit -F arch=$a -S $sc -F auid>=${uid_min} -F auid!=unset -k delete"
        sc="$(sc_filter "$a" creat open openat truncate ftruncate)"
        if [[ -n "$sc" ]]; then
            echo "-a always,exit -F arch=$a -S $sc -F exit=-EACCES -F auid>=${uid_min} -F auid!=unset -k access"
            echo "-a always,exit -F arch=$a -S $sc -F exit=-EPERM -F auid>=${uid_min} -F auid!=unset -k access"
        fi
        sc="$(sc_filter "$a" chmod fchmod fchmodat)"
        [[ -n "$sc" ]] && echo "-a always,exit -F arch=$a -S $sc -F auid>=${uid_min} -F auid!=unset -k perm_mod"
        sc="$(sc_filter "$a" chown fchown lchown fchownat)"
        [[ -n "$sc" ]] && echo "-a always,exit -F arch=$a -S $sc -F auid>=${uid_min} -F auid!=unset -k perm_mod"
        sc="$(sc_filter "$a" setxattr lsetxattr fsetxattr removexattr lremovexattr fremovexattr)"
        [[ -n "$sc" ]] && echo "-a always,exit -F arch=$a -S $sc -F auid>=${uid_min} -F auid!=unset -k perm_mod"
        sc="$(sc_filter "$a" init_module finit_module delete_module create_module query_module)"
        [[ -n "$sc" ]] && echo "-a always,exit -F arch=$a -S $sc -F auid>=${uid_min} -F auid!=unset -k kernel_modules"
    done
    [[ -n "$sudo_log" && -d "$(dirname "$sudo_log")" ]] && echo "-w ${sudo_log} -p wa -k sudo_log_file"
    [[ -e /etc/localtime ]] && echo "-w /etc/localtime -p wa -k time-change"
    for p in /etc/issue /etc/issue.net /etc/hosts /etc/networks /etc/network /etc/netplan /etc/hostname /etc/sysconfig/network /etc/NetworkManager; do
        [[ -e "$p" ]] && echo "-w $p -p wa -k system-locale"
    done
    for p in /etc/group /etc/passwd /etc/gshadow /etc/shadow /etc/security/opasswd /etc/nsswitch.conf /etc/pam.conf /etc/pam.d; do
        [[ -e "$p" ]] && echo "-w $p -p wa -k identity"
    done
    for p in /var/run/utmp /var/log/wtmp /var/log/btmp; do [[ -d "$(dirname "$p")" ]] && echo "-w $p -p wa -k session"; done
    for p in /var/log/lastlog /var/run/faillock; do [[ -d "$(dirname "$p")" ]] && echo "-w $p -p wa -k logins"; done
    for p in /etc/apparmor /etc/apparmor.d /etc/selinux /usr/share/selinux; do [[ -d "$p" ]] && echo "-w $p/ -p wa -k MAC-policy"; done
    for p in /usr/bin/chcon /usr/bin/setfacl /usr/bin/chacl; do
        [[ -x "$p" ]] && echo "-a always,exit -F path=$p -F perm=x -F auid>=${uid_min} -F auid!=unset -k perm_chng"
    done
    [[ -x /usr/sbin/usermod ]] && echo "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${uid_min} -F auid!=unset -k usermod"
    [[ -x /usr/bin/kmod ]] && echo "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${uid_min} -F auid!=unset -k kernel_modules"
    # 6.2.3.6: все SUID/SGID-бинарники на локальных ФС
    fs_scan
    while read -r p; do
        [[ -x "$p" ]] && echo "-a always,exit -F path=$p -F perm=x -F auid>=${uid_min} -F auid!=unset -k privileged"
    done < <(fs_list SU | sort -u)
    return 0
}

audit_rules_install() {
    local f=/etc/audit/rules.d/50-cis-hardening.rules immutable="$1"
    command -v auditctl &>/dev/null || return 1
    bk_file "$f" /etc/audit/rules.d/99-finalize.rules
    bk_note R augenrules
    bk_mkdir /etc/audit/rules.d
    audit_rules_content > "$f"
    chmod 640 "$f"
    if [[ "$immutable" == "y" ]]; then
        printf '## CIS 6.2.3.20: правила неизменяемы до перезагрузки\n-e 2\n' > /etc/audit/rules.d/99-finalize.rules
        chmod 640 /etc/audit/rules.d/99-finalize.rules
    fi
    if auditctl -s 2>/dev/null | grep -q 'enabled 2'; then
        echo "Правила аудита уже неизменяемы (enabled 2) — новые применятся после перезагрузки"
    else
        augenrules --load
    fi
}

auditd_conf_apply() {
    local strict="$1" c=/etc/audit/auditd.conf
    [[ -f "$c" ]] || return 1
    bk_note R auditd
    conf_set "$c" max_log_file "$AUDIT_MAX_LOG_MB"
    conf_set "$c" max_log_file_action keep_logs
    conf_set "$c" space_left_action email
    conf_set "$c" action_mail_acct root
    if [[ "$strict" == "y" ]]; then
        conf_set "$c" admin_space_left_action single
        conf_set "$c" disk_full_action halt
        conf_set "$c" disk_error_action halt
    fi
    auditd_reload
}

auditd_install() {
    if [[ "$PKG_MGR" == "apt-get" ]]; then
        pkg_install auditd audispd-plugins || pkg_install auditd
    else
        pkg_install audit
    fi
    svc_enable auditd
}

sudo_logfile() {
    local v
    v="$(sudo_grep '^[[:space:]]*Defaults.*logfile' | grep -oE 'logfile[[:space:]]*=[[:space:]]*"?[^",[:space:]]+' | tail -1 | sed -E 's/.*=[[:space:]]*"?//')"
    echo "${v:-/var/log/sudo.log}"
}

aide_setup() {
    if [[ "$PKG_MGR" == "apt-get" ]]; then
        pkg_install aide aide-common
    else
        pkg_install aide
    fi
    local conf t p
    for conf in /etc/aide/aide.conf /etc/aide.conf; do [[ -f "$conf" ]] && break; done
    if [[ -f "$conf" ]] && ! grep -q 'auditctl' "$conf"; then
        bk_file "$conf"
        {
            echo "# CIS 6.3.3: целостность инструментов аудита"
            for t in auditctl auditd ausearch aureport autrace augenrules; do
                for p in /sbin /usr/sbin; do
                    if [[ -x "$p/$t" ]]; then echo "$p/$t p+i+n+u+g+s+b+acl+xattrs+sha512"; break; fi
                done
            done
        } >> "$conf"
    fi
    echo "Инициализация базы AIDE (может занять несколько минут)..."
    if command -v aideinit &>/dev/null; then
        aideinit -y -f
    else
        aide --init
        [[ -f /var/lib/aide/aide.db.new.gz ]] && mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
    if unit_exists dailyaidecheck.timer; then
        svc_enable dailyaidecheck.timer
    else
        write_file /etc/cron.d/cis-aide 644 "# CIS 6.3.2: ежедневная проверка целостности
0 5 * * * root $(command -v aide || echo /usr/sbin/aide) --check"
    fi
}

journald_apply() {
    local fwd="$1"
    write_file /etc/systemd/journald.conf.d/60-cis-hardening.conf 644 "# Создан linux_cis_hardening.sh (CIS 6.1.x)
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=${fwd}"
    bk_note R systemd-journald
    systemctl restart systemd-journald
}

rsyslog_apply() {
    local remote="$1" host port=514
    local content="# Создан linux_cis_hardening.sh (CIS 6.1.3.x)
\$FileCreateMode 0640"
    if [[ -n "$remote" ]]; then
        host="${remote%%:*}"
        [[ "$remote" == *:* ]] && port="${remote##*:}"
        content+=$'\n'"*.* action(type=\"omfwd\" target=\"${host}\" port=\"${port}\" protocol=\"tcp\" action.resumeRetryCount=\"100\" queue.type=\"LinkedList\" queue.size=\"1000\")"
    fi
    write_file /etc/rsyslog.d/60-cis-hardening.conf 644 "$content"
    bk_note R rsyslog
    rsyslogd -N1 >/dev/null 2>&1 || { echo "rsyslogd -N1: конфигурация невалидна"; return 1; }
    systemctl restart rsyslog
}

grub_set_password() {
    local p1 p2 hash cfg_user=/etc/grub.d/01_cis_password
    if [[ "$OS_FAMILY" == "rhel" ]] && command -v grub2-setpassword &>/dev/null; then
        bk_file /boot/grub2/user.cfg
        grub2-setpassword </dev/tty >/dev/tty
        return
    fi
    printf "Пароль загрузчика (пользователь root GRUB): " >/dev/tty; read -rs p1 </dev/tty; echo >/dev/tty
    printf "Повторите пароль: " >/dev/tty; read -rs p2 </dev/tty; echo >/dev/tty
    [[ -n "$p1" && "$p1" == "$p2" ]] || { echo "Пароли не совпадают или пусты"; return 1; }
    hash="$(printf '%s\n%s\n' "$p1" "$p1" | grub-mkpasswd-pbkdf2 2>/dev/null | grep -oE 'grub\.pbkdf2\.[^[:space:]]+')" || true
    unset p1 p2
    [[ -n "$hash" ]] || { echo "grub-mkpasswd-pbkdf2 не вернул хэш"; return 1; }
    bk_file "$cfg_user" /etc/grub.d/10_linux
    printf '#!/bin/sh\n# Создан linux_cis_hardening.sh (CIS 1.4.1)\ncat <<EOF\nset superusers="root"\npassword_pbkdf2 root %s\nEOF\n' "$hash" > "$cfg_user"
    chmod 700 "$cfg_user"
    # Обычная загрузка без пароля, пароль — только на редактирование/консоль
    grep -q -- '--unrestricted' /etc/grub.d/10_linux || sed -i -E 's/^(CLASS="--class gnu-linux --class gnu --class os)/\1 --unrestricted/' /etc/grub.d/10_linux
    grub_regen
}

# ═════════════════════════════════════════════════════════════════════════════
#  ОДИН ОБХОД ФС на все проверки (SUID/SGID, world-writable, sticky, unowned)
# ═════════════════════════════════════════════════════════════════════════════
FS_SCAN=""
FS_SCAN_DONE=0
fs_scan() {
    (( FS_SCAN_DONE == 1 )) && return 0
    local -a mounts=()
    mapfile -t mounts < <(findmnt -rn -l -k -o TARGET,FSTYPE 2>/dev/null \
        | awk '$2 ~ /^(ext[234]|xfs|btrfs|zfs|jfs|f2fs|reiserfs)$/ {print $1}')
    (( ${#mounts[@]} )) || mounts=(/)
    # find возвращает 1 на нечитаемых каталогах — это не ошибка (вызов бывает под set -e)
    FS_SCAN="$(find "${mounts[@]}" -xdev \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o \
        \( \( -type f \( -perm -4000 -o -perm -2000 \) -printf 'SU %p\n' \) , \
           \( -type f -perm -0002 -printf 'WW %p\n' \) , \
           \( -type d -perm -0002 ! -perm -1000 -printf 'SD %p\n' \) , \
           \( -nouser -printf 'NU %p\n' \) , \
           \( -nogroup -printf 'NG %p\n' \) \) 2>/dev/null)" || true
    FS_SCAN_DONE=1
    return 0
}
fs_list() { awk -v t="$1" '$1==t { sub(/^[A-Z][A-Z] /,""); print }' <<< "$FS_SCAN"; }

# ═════════════════════════════════════════════════════════════════════════════
#  МЕХАНИЗМ ИСПРАВЛЕНИЙ (как в security_audit.sh)
# ═════════════════════════════════════════════════════════════════════════════

# Элемент = "описание|||команда|||файлы для бэкапа"
FIXES=()
FIXES_SSH=()
FIXES_FW=()
FIXES_SUDO=()
PASS_POLICY_ISSUES=0

# Категории:
#   password  — команды нет: при наличии проблем запускается apply_password_policy()
#   ssh       — safe_apply_batch "ssh" (бэкап, sshd -t, предохранитель)
#   firewall  — safe_apply_batch "firewall" (бэкап правил, проверка SSH-портов, предохранитель)
#   sudo      — safe_apply_batch "sudo" (бэкап, visudo -c, предохранитель)
#   simple    — показать команду, применить по одиночному подтверждению (с бэкапом)
add_fix() {
    local desc="$1"
    local category="$2"
    local cmd="${3:-}"
    local bk_paths="${4:-}"
    (( REAUDIT == 1 )) && return 0
    case "$category" in
        password) PASS_POLICY_ISSUES=$((PASS_POLICY_ISSUES+1)) ;;
        ssh)      FIXES_SSH+=("${desc}|||${cmd}|||${bk_paths}") ;;
        firewall) FIXES_FW+=("${desc}|||${cmd}|||${bk_paths}") ;;
        sudo)     FIXES_SUDO+=("${desc}|||${cmd}|||${bk_paths}") ;;
        *)        FIXES+=("${desc}|||${cmd}|||${bk_paths}") ;;
    esac
}

fix_desc()  { echo "${1%%|||*}"; }
fix_cmd()   { local r="${1#*|||}"; echo "${r%%|||*}"; }
fix_files() { local r="${1#*|||}"; echo "${r#*|||}"; }

# ══════════════════════════════════════════════════════════════════════════
# БЕЗОПАСНЫЙ ДВИЖОК ПРИМЕНЕНИЯ
#   1) бэкап затронутых файлов/правил/юнитов
#   2) изменения — в защищённом подпроцессе с `set -e`
#   3) при ошибке или проваленной валидации — немедленный откат
#   4) при успехе — предохранитель: подтверждение из НОВОГО сеанса,
#      иначе автооткат по таймауту (systemd-run / setsid-сторож)
# ══════════════════════════════════════════════════════════════════════════

SAFE_BACKUP_DIR=""
SAFE_MARKER=""
SAFE_GUARD_PID=""
SAFE_GUARD_UNIT=""
SAFE_PENDING_CATEGORY=""

# Если скрипт завершится (в т.ч. по Ctrl-C или обрыву SSH) с неподтверждёнными
# изменениями — откатываем их сами, не дожидаясь фонового сторожа.
cleanup_pending() {
    local rc=$?
    stop_guard
    # rm без -f: успех означает, что маркер «наш», а не уже забран сторожем
    if [[ -n "$SAFE_MARKER" ]] && rm "$SAFE_MARKER" 2>/dev/null; then
        SAFE_MARKER=""
        echo ""
        result_warn "Выход с неподтверждёнными изменениями (${SAFE_PENDING_CATEGORY}) — откатываю."
        restore_dir "$SAFE_BACKUP_DIR"
    fi
    return $rc
}
trap cleanup_pending EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

stop_guard() {
    [[ -n "$SAFE_GUARD_UNIT" ]] && systemctl stop "${SAFE_GUARD_UNIT}.timer" "${SAFE_GUARD_UNIT}.service" >/dev/null 2>&1
    [[ -n "$SAFE_GUARD_PID" ]] && kill "$SAFE_GUARD_PID" >/dev/null 2>&1
    SAFE_GUARD_UNIT=""
    SAFE_GUARD_PID=""
    return 0
}

safe_tracked_files() {
    case "$1" in
        password) echo "/etc/security/pwquality.conf /etc/security/pwquality.conf.d /etc/security/faillock.conf /etc/security/pwhistory.conf /etc/login.defs /etc/default/useradd /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/su /etc/shadow /etc/group /etc/gshadow" ;;
        ssh)      echo "/etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/issue.net" ;;
        sudo)     echo "$SUDO_DROPIN" ;;
        firewall) echo "" ;;
    esac
}

safe_make_backup() {
    local category="$1" f
    bk_new_dir "$category" || return 1
    SAFE_BACKUP_DIR="$BK_NEW_RESULT"
    bk_init_manifest "$SAFE_BACKUP_DIR"
    for f in $(safe_tracked_files "$category"); do
        bk_file "$f" || { result_fail "Не удалось сохранить $f"; return 1; }
    done
    [[ "$category" == "firewall" ]] && fw_snapshot
    result_info "Бэкап (${category}) создан: $SAFE_BACKUP_DIR"
    return 0
}

safe_restore_backup() {
    local category="$1"
    [[ -d "$SAFE_BACKUP_DIR" ]] || return 0
    restore_dir "$SAFE_BACKUP_DIR"
    result_warn "Изменения категории '${category}' откатаны из ${SAFE_BACKUP_DIR}"
}

start_guard() {
    local guard_timeout="$1" script="$SAFE_BACKUP_DIR/rollback.sh" unit
    SAFE_GUARD_UNIT=""; SAFE_GUARD_PID=""
    # systemd-run: сторож живёт в system.slice и переживает и обрыв SSH,
    # и KillUserProcesses=yes, которые убили бы обычный фоновый процесс.
    if (( HAS_SYSTEMD )) && command -v systemd-run &>/dev/null; then
        unit="security-toolkit-rollback-$(date +%s)-$$"
        if systemd-run --quiet --unit "$unit" --on-active="${guard_timeout}s" \
               --timer-property=AccuracySec=1s /bin/bash "$script" --auto >/dev/null 2>&1; then
            SAFE_GUARD_UNIT="$unit"
            return 0
        fi
    fi
    # Запасной вариант: отдельная сессия, игнорирует SIGHUP
    if command -v setsid &>/dev/null; then
        # shellcheck disable=SC2016  # $1/$2 раскрывает дочерний bash
        setsid bash -c 'trap "" HUP; sleep "$1"; exec /bin/bash "$2" --auto' _ "$guard_timeout" "$script" </dev/null >/dev/null 2>&1 &
    else
        ( trap '' HUP INT; sleep "$guard_timeout"; exec /bin/bash "$script" --auto ) </dev/null >/dev/null 2>&1 &
    fi
    SAFE_GUARD_PID=$!
    disown "$SAFE_GUARD_PID" 2>/dev/null || true
}

# Предохранитель: ждём подтверждения из НОВОГО сеанса, иначе — автооткат по таймауту.
safe_confirm_or_rollback() {
    local category="$1"
    if [[ "$DO_ROLLBACK_GUARD" -ne 1 ]]; then
        result_warn "Предохранитель отключён — изменения применены без окна отката. Бэкап: ${SAFE_BACKUP_DIR}"
        return 0
    fi
    SAFE_MARKER="$SAFE_BACKUP_DIR/PENDING"
    : > "$SAFE_MARKER"
    SAFE_PENDING_CATEGORY="$category"
    # Сторож срабатывает с запасом после read -t, чтобы не было гонки с вводом «YES».
    start_guard $(( CONFIRM_TIMEOUT + 15 ))

    echo ""
    echo -e "${RED}${BOLD}============================ ВАЖНО ============================${RESET}"
    echo -e "${YELLOW}Изменения (${category}) применены, но ЕЩЁ НЕ ЗАФИКСИРОВАНЫ.${RESET}"
    echo "  1) Откройте НОВОЕ SSH-подключение к серверу, не закрывая текущее."
    echo "  2) Убедитесь, что вход и sudo всё ещё работают."
    echo "  3) Вернитесь сюда и подтвердите."
    echo ""
    echo -e "У вас ${YELLOW}${CONFIRM_TIMEOUT} сек${RESET}. Иначе — автоматический откат из ${SAFE_BACKUP_DIR}."
    echo -e "${DIM}Сторож: ${SAFE_GUARD_UNIT:+systemd-unit ${SAFE_GUARD_UNIT}.timer}${SAFE_GUARD_PID:+PID ${SAFE_GUARD_PID}}; ручной откат: bash ${SAFE_BACKUP_DIR}/rollback.sh${RESET}"
    echo -e "${RED}=================================================================${RESET}"

    local answer=""
    read -r -t "$CONFIRM_TIMEOUT" -p "Введите YES для фиксации: " answer </dev/tty || answer=""
    # Снимаем «неподтверждённое» состояние до любых действий. Если маркер уже
    # забрал сторож (rollback.sh --auto), откат идёт в фоне — сообщаем об этом.
    local owned=0
    rm "$SAFE_MARKER" 2>/dev/null && owned=1
    SAFE_MARKER=""
    stop_guard
    if (( owned == 0 )); then
        result_warn "Сторож уже начал автооткат (${category}) — см. ${ROLLBACK_LOG}"
        return 1
    fi
    if [[ "${answer^^}" == "YES" ]]; then
        result_pass "Изменения (${category}) зафиксированы. Бэкап сохранён в ${SAFE_BACKUP_DIR}"
        return 0
    fi
    echo ""
    result_warn "Подтверждение не получено — откатываю немедленно."
    safe_restore_backup "$category"
    return 1
}

# ── Помощники специально для password/PAM-модуля ──
pam_module_exists() {
    find /lib /lib64 /usr/lib /usr/lib64 -name "$1" 2>/dev/null | grep -q .
}

is_simple_faillock_wrappable() {
    [[ -f "$1" ]] && grep -Eq '^auth[[:space:]]+\[success=1 default=ignore\][[:space:]]+pam_unix\.so' "$1"
}

authselect_feature_enabled() {
    authselect current 2>/dev/null | grep -qE "^[[:space:]]*-[[:space:]]+${1}[[:space:]]*$"
}

# Все мутирующие шаги парольной/PAM-политики. Выполняется в защищённом
# подпроцессе с `set -e` — см. apply_password_policy().
apply_password_policy_body() {
    local os_family="$1"
    local fail_unlock_seconds=$(( FAIL_UNLOCK_MINUTES * 60 ))
    local pwq=/etc/security/pwquality.conf fl=/etc/security/faillock.conf

    if [[ "$os_family" == "debian" ]]; then
        pkg_install libpam-pwquality libpam-modules \
            || result_warn "Не все пакеты установлены (проверьте libpam-pwquality/libpam-modules)"
        pkg_install pamtester >/dev/null 2>&1 || true
    else
        pkg_install libpwquality pam authselect || result_warn "dnf install завершился с предупреждением"
        pkg_install pamtester >/dev/null 2>&1 || true
    fi

    # ── 5.3.3.2 pwquality (ответы REQUIRE_* учитываются: в security_audit.sh
    #    все *credit писались в -1 независимо от ответов) ──
    conf_set "$pwq" minlen "$MIN_PASS_LEN"
    local key var
    for key in ucredit:REQUIRE_UPPERCASE lcredit:REQUIRE_LOWERCASE dcredit:REQUIRE_DIGITS ocredit:REQUIRE_SPECIAL; do
        var="${key#*:}"
        if [[ "${!var}" == "1" ]]; then conf_set "$pwq" "${key%%:*}" -1; else conf_set "$pwq" "${key%%:*}" 0; fi
    done
    conf_set "$pwq" difok 2
    conf_set "$pwq" maxrepeat 3
    conf_set "$pwq" maxsequence 3
    conf_set "$pwq" dictcheck 1
    conf_set "$pwq" usercheck 1
    conf_set "$pwq" retry 3
    conf_set "$pwq" enforce_for_root ""
    result_pass "pwquality.conf: minlen=${MIN_PASS_LEN}, difok=2, maxrepeat=3, maxsequence=3, enforce_for_root"

    # ── 5.3.3.1 faillock ──
    [[ -f "$fl" ]] || printf '# Управляется linux_cis_hardening.sh\n' > "$fl"
    conf_set "$fl" deny "$FAIL_DENY"
    conf_set "$fl" unlock_time "$fail_unlock_seconds"
    conf_set "$fl" fail_interval 900
    if [[ "${ANS[pam.even_deny_root]:-n}" == "y" ]]; then
        conf_set "$fl" even_deny_root ""
        conf_set "$fl" root_unlock_time 60
    fi
    result_pass "faillock.conf: deny=${FAIL_DENY}, unlock_time=${fail_unlock_seconds}"

    if [[ "$os_family" == "rhel" ]]; then
        local cur_profile
        cur_profile="$(authselect current 2>/dev/null | awk -F': ' '/Profile/{print $2; exit}')" || true
        if [[ -z "$cur_profile" ]]; then
            result_warn "authselect: активный профиль не найден — faillock/pwhistory в auth-стек не включаю (риск сломать SSSD/AD)"
        else
            result_info "Активный профиль authselect: ${cur_profile}"
            local feat avail
            avail="$(authselect list-features "${cur_profile%% *}" 2>/dev/null)" || true
            for feat in with-faillock with-pwhistory without-nullok; do
                if [[ -n "$avail" ]] && ! grep -qx "$feat" <<< "$avail"; then
                    result_info "authselect: профиль не поддерживает ${feat} — пропускаю"
                    continue
                fi
                if authselect_feature_enabled "$feat"; then
                    result_info "authselect: ${feat} уже включён — оставляю как есть"
                    continue
                fi
                authselect enable-feature "$feat"
                bk_note A "$feat"
            done
            authselect apply-changes -b
            result_pass "authselect: применены изменения (with-faillock/with-pwhistory/without-nullok)"
        fi
        conf_set /etc/security/pwhistory.conf remember "$PASS_HISTORY"
        conf_set /etc/security/pwhistory.conf enforce_for_root ""
        result_pass "pwhistory.conf: remember=${PASS_HISTORY}, enforce_for_root"
    else
        local common_password=/etc/pam.d/common-password
        local common_auth=/etc/pam.d/common-auth
        local common_account=/etc/pam.d/common-account

        [[ -f "$common_password" ]] || { result_fail "$common_password не найден"; return 1; }
        sed -i '/pam_pwquality\.so/d; /pam_pwhistory\.so/d' "$common_password"
        if pam_module_exists pam_pwquality.so; then
            sed -i "/^password[[:space:]].*pam_unix\.so/i password requisite pam_pwquality.so retry=3 enforce_for_root" "$common_password"
            result_pass "pam_pwquality добавлен в $common_password"
        else
            result_warn "pam_pwquality.so не найден на диске — строку не добавляю (нужен libpam-pwquality)"
        fi
        if pam_module_exists pam_pwhistory.so; then
            sed -i "/^password[[:space:]].*pam_unix\.so/i password requisite pam_pwhistory.so remember=${PASS_HISTORY} enforce_for_root use_authtok" "$common_password"
            result_pass "pam_pwhistory добавлен (remember=${PASS_HISTORY}, enforce_for_root)"
        else
            result_warn "pam_pwhistory.so не найден на диске — строку не добавляю (нужен libpam-modules)"
        fi

        [[ -f "$common_auth" ]] || { result_fail "$common_auth не найден"; return 1; }
        if ! pam_module_exists pam_faillock.so; then
            result_warn "pam_faillock.so не найден на диске (типично для старых Astra/Debian с pam_tally2) — не трогаю auth-стек"
        elif ! is_simple_faillock_wrappable "$common_auth"; then
            result_warn "$common_auth не в штатной идиоме pam_unix success=1 — автоматическую вставку faillock пропускаю (похоже на SSSD/LDAP/AD или нестандартный стек)"
        else
            sed -i '/pam_faillock\.so/d' "$common_auth"
            local wrap_tmp; wrap_tmp="$(mktemp)"
            awk '
                /^auth[[:space:]]+\[success=1 default=ignore\][[:space:]]+pam_unix\.so/ && !d {
                    print "auth    required        pam_faillock.so preauth"
                    print $0
                    print "auth    [default=die]   pam_faillock.so authfail"
                    print "auth    sufficient      pam_faillock.so authsucc"
                    d=1; next
                }
                { print }
            ' "$common_auth" > "$wrap_tmp"
            cat "$wrap_tmp" > "$common_auth"; rm -f "$wrap_tmp"
            if [[ -f "$common_account" ]]; then
                sed -i '/pam_faillock\.so/d' "$common_account"
                echo "account required pam_faillock.so" >> "$common_account"
            fi
            result_pass "faillock настроен в $common_auth (+account в $common_account)"
        fi
        # 5.3.3.4.1: nullok разрешает вход с пустым паролем
        sed -i -E '/pam_unix\.so/ s/[[:space:]]+nullok(_secure)?([[:space:]]|$)/\2/' "$common_auth" "$common_password"
        result_pass "nullok удалён из pam_unix"
    fi

    # ── 5.2.7 su только для группы sugroup ──
    if [[ "${ANS[pam.su_wheel]:-n}" == "y" && -f /etc/pam.d/su ]]; then
        getent group sugroup >/dev/null 2>&1 || groupadd sugroup
        if ! grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*use_uid' /etc/pam.d/su; then
            if grep -Eq '^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so' /etc/pam.d/su; then
                sed -i -E '/^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so/a auth required pam_wheel.so use_uid group=sugroup' /etc/pam.d/su
            else
                sed -i '1i auth required pam_wheel.so use_uid group=sugroup' /etc/pam.d/su
            fi
        fi
        result_pass "su разрешён только членам (пустой) группы sugroup; root и sudo не затронуты"
    fi

    # ── 5.4.1.x старение паролей + неактивность ──
    local user uid shell
    while IFS=: read -r user _ uid _ _ _ shell; do
        [[ "$user" == "root" || "$user" == "nobody" ]] && continue
        case "$shell" in *nologin|*false|*sync|*shutdown|*halt) continue ;; esac
        is_num "$uid" || continue
        (( uid >= UID_MIN )) || continue
        chage -M "$PASS_MAX_AGE" -m "$PASS_MIN_AGE" -W "$PASS_WARN_AGE" -I "$PASS_INACTIVE" "$user" \
            || result_warn "chage не применился для $user (пропускаю)"
    done < /etc/passwd
    result_pass "Старение паролей применено (UID >= ${UID_MIN}, INACTIVE=${PASS_INACTIVE})"
    useradd -D -f "$PASS_INACTIVE" >/dev/null
    result_pass "useradd -D: INACTIVE=${PASS_INACTIVE}"

    if [[ -f /etc/login.defs ]]; then
        conf_set /etc/login.defs PASS_MAX_DAYS "$PASS_MAX_AGE" "   "
        conf_set /etc/login.defs PASS_MIN_DAYS "$PASS_MIN_AGE" "   "
        conf_set /etc/login.defs PASS_WARN_AGE "$PASS_WARN_AGE" "   "
        conf_set /etc/login.defs UMASK 027 "   "
        local enc; enc="$(conf_get /etc/login.defs ENCRYPT_METHOD)"
        [[ "${enc^^}" =~ ^(SHA512|YESCRYPT)$ ]] || conf_set /etc/login.defs ENCRYPT_METHOD SHA512 " "
        result_pass "login.defs: PASS_*, UMASK 027, ENCRYPT_METHOD ${enc:-SHA512}"
    fi
}

validate_pam_stack() {
    local os_family="$1" f pam_ok=1 auth_files=()
    if [[ "$os_family" == "debian" ]]; then
        auth_files=(/etc/pam.d/common-auth /etc/pam.d/common-password)
    else
        auth_files=(/etc/pam.d/system-auth /etc/pam.d/password-auth)
    fi
    for f in "${auth_files[@]}"; do
        [[ -f "$f" ]] || continue
        [[ -s "$f" ]] || { result_fail "$f пуст!"; pam_ok=0; }
        grep -q 'pam_unix\.so' "$f" || { result_fail "$f не содержит pam_unix.so!"; pam_ok=0; }
    done
    if [[ -f /etc/pam.d/su ]] && ! grep -Eq 'pam_rootok\.so|include|substack|@include' /etc/pam.d/su; then
        result_fail "/etc/pam.d/su потерял pam_rootok/include!"; pam_ok=0
    fi
    if command -v pamtester &>/dev/null; then
        if pamtester -v login "$(id -un)" account >/dev/null 2>&1; then
            result_pass "pamtester: базовая проверка account-фазы прошла"
        else
            result_warn "pamtester: account-фаза вернула ошибку — проверьте стек вручную"
        fi
    fi
    [[ "$pam_ok" -eq 1 ]]
}

# Точка входа: полноценный безопасный модуль парольной/PAM-политики
apply_password_policy() {
    if [[ $EUID -ne 0 ]]; then
        result_warn "Для применения парольной/PAM-политики нужен root. Запустите через sudo."
        return 1
    fi

    echo ""
    log "${BOLD}${MAGENTA}══════════ Безопасное применение парольной/PAM-политики ══════════${RESET}"
    log "  minlen=${MIN_PASS_LEN}  remember=${PASS_HISTORY}  deny=${FAIL_DENY}  unlock=${FAIL_UNLOCK_MINUTES}мин"
    log "  PASS_MAX_DAYS=${PASS_MAX_AGE}  PASS_MIN_DAYS=${PASS_MIN_AGE}  PASS_WARN_AGE=${PASS_WARN_AGE}  INACTIVE=${PASS_INACTIVE}  UID_MIN=${UID_MIN}"

    if (( PASS_MIN_AGE >= PASS_MAX_AGE )); then
        result_fail "PASS_MIN_AGE (${PASS_MIN_AGE}) не может быть >= PASS_MAX_AGE (${PASS_MAX_AGE}) — отменено"
        return 1
    fi
    if ! confirm "Применить парольную/PAM-политику с этими параметрами (бэкап + окно отката ${CONFIRM_TIMEOUT}с)?" n; then
        result_info "Отменено пользователем."
        return 0
    fi

    local os_family="$OS_FAMILY"
    if [[ "$os_family" == "unknown" ]]; then
        result_fail "Не удалось определить семейство ОС — модуль поддерживает Debian/Ubuntu/Astra и RHEL/CentOS/Rocky/Alma"
        return 1
    fi
    result_info "Семейство ОС: ${os_family}"

    safe_make_backup "password" || return 1

    ( set -e -o pipefail; apply_password_policy_body "$os_family" )
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        result_fail "Применение парольной/PAM-политики не удалось — откатываю."
        safe_restore_backup "password"
        return 1
    fi

    if ! validate_pam_stack "$os_family"; then
        result_fail "Структурная проверка PAM не пройдена — откатываю."
        safe_restore_backup "password"
        return 1
    fi
    result_pass "Структурная проверка PAM пройдена"

    safe_confirm_or_rollback "password"
}

safe_apply_batch_body() {
    local -n fixes_ref="$1"
    local entry desc cmd
    for entry in "${fixes_ref[@]}"; do
        desc="$(fix_desc "$entry")"; cmd="$(fix_cmd "$entry")"
        result_info "Применяю: ${desc}"
        eval "$cmd"
    done
}

safe_apply_batch() {
    local category="$1" arrname="$2"
    local -n fixes_ref="$arrname"
    [[ ${#fixes_ref[@]} -eq 0 ]] && return 0

    if [[ $EUID -ne 0 ]]; then
        result_warn "Для безопасного применения (${category}) нужен root. Запустите через sudo."
        return 1
    fi

    echo ""
    log "${BOLD}${MAGENTA}══════════ Безопасное применение: ${category} ══════════${RESET}"
    local entry f
    for entry in "${fixes_ref[@]}"; do
        log "  • $(fix_desc "$entry")"
        log "    ${DIM}$(fix_cmd "$entry")${RESET}"
    done
    if ! confirm "Применить все ${#fixes_ref[@]} исправлений категории '${category}' (бэкап + окно отката ${CONFIRM_TIMEOUT}с)?" n; then
        result_info "Отменено пользователем."
        return 0
    fi

    safe_make_backup "$category" || return 1
    for entry in "${fixes_ref[@]}"; do
        for f in $(fix_files "$entry"); do bk_file "$f"; done
    done

    ( set -e -o pipefail; safe_apply_batch_body "$arrname" ) 2>&1 | tee -a "$REPORT_FILE"
    local rc=${PIPESTATUS[0]}
    if [[ $rc -ne 0 ]]; then
        result_fail "Ошибка применения (${category}) — откатываю."
        safe_restore_backup "$category"
        return 1
    fi

    case "$category" in
        ssh)
            local bin errf
            errf="$(mktemp)"
            if bin="$(sshd_bin)" && ! "$bin" -t 2>"$errf"; then
                result_fail "sshd -t не прошла проверку: $(cat "$errf" 2>/dev/null)"
                rm -f "$errf"
                safe_restore_backup "ssh"
                return 1
            fi
            rm -f "$errf"
            ssh_reload
            result_pass "sshd -t пройдена, конфигурация перезагружена"
            ;;
        sudo)
            if ! visudo -cq >/dev/null 2>&1; then
                result_fail "visudo -c: конфигурация sudo невалидна"
                safe_restore_backup "sudo"
                return 1
            fi
            result_pass "visudo -c пройдена"
            ;;
        firewall)
            if ! fw_validate_ssh; then
                safe_restore_backup "firewall"
                return 1
            fi
            ;;
    esac

    safe_confirm_or_rollback "$category"
}

# Диспетчер: password → модуль; ssh/sudo/firewall → safe_apply_batch; прочее → simple
offer_remediation() {
    if (( PASS_POLICY_ISSUES == 0 && ${#FIXES_SSH[@]} == 0 && ${#FIXES_FW[@]} == 0 && ${#FIXES_SUDO[@]} == 0 && ${#FIXES[@]} == 0 )); then
        return
    fi

    if [[ $EUID -ne 0 ]]; then
        echo ""
        log "${YELLOW}${BOLD}⚠ Для применения исправлений требуется root.${RESET}"
        log "  Запустите скрипт через: ${WHITE}sudo $0${RESET}"
        return
    fi
    if (( HAVE_TTY == 0 )); then
        log "${YELLOW}${BOLD}⚠ Нет терминала (/dev/tty) — исправления требуют подтверждений, пропускаю.${RESET}"
        return
    fi

    if (( PASS_POLICY_ISSUES > 0 )); then
        echo ""
        log "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════════╗${RESET}"
        log "${BOLD}${MAGENTA}║   ПАРОЛЬНАЯ/PAM-ПОЛИТИКА: найдено расхождений — ${PASS_POLICY_ISSUES}${RESET}"
        log "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════════╝${RESET}"
        log "  Точечные sed-фиксы для этого раздела не предлагаются — вместо них"
        log "  запускается полноценный безопасный модуль (бэкап/валидация/откат)."
        apply_password_policy
    fi

    safe_apply_batch "ssh" FIXES_SSH
    safe_apply_batch "sudo" FIXES_SUDO
    safe_apply_batch "firewall" FIXES_FW

    simple_remediation
}

# Показать команду, применить по одиночному подтверждению. В отличие от
# security_audit.sh — с бэкапом каждого исправления и откатом при ошибке.
simple_remediation() {
    [[ ${#FIXES[@]} -eq 0 ]] && return

    echo ""
    log "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    log "${BOLD}${MAGENTA}║           🔧  АВТОМАТИЧЕСКОЕ ИСПРАВЛЕНИЕ ПРОБЛЕМ  🔧             ║${RESET}"
    log "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    log ""
    log "  Найдено ${#FIXES[@]} исправлений. Каждое требует вашего подтверждения."
    log "  ${DIM}y — применить, N — пропустить, a — применить все оставшиеся, q — выход${RESET}"
    log ""

    local applied=0 skipped=0 failed=0 all=0 idx=0 simple_dir="" entry desc cmd files f rc ans
    for entry in "${FIXES[@]}"; do
        desc="$(fix_desc "$entry")"; cmd="$(fix_cmd "$entry")"; files="$(fix_files "$entry")"

        echo ""
        echo -e "${CYAN}${BOLD}┌─ Исправление ─────────────────────────────────────────────────${RESET}"
        echo -e "${CYAN}│${RESET} ${WHITE}${desc}${RESET}"
        echo -e "${CYAN}│${RESET} ${DIM}Команда: ${cmd}${RESET}"
        echo -e "${CYAN}└───────────────────────────────────────────────────────────────${RESET}"

        if (( all == 1 )); then
            ans="y"
        else
            printf "%b" "${YELLOW}  Применить? [y/N/a(все)/q(выход)]: ${RESET}" >/dev/tty
            read -r ans </dev/tty || ans="q"
            ans="${ans//[[:space:]]/}"
        fi

        case "${ans,,}" in
            a|ф) all=1; ans="y" ;;
        esac
        case "${ans,,}" in
            y|yes|д|да)
                if [[ -z "$simple_dir" ]]; then
                    bk_new_dir "simple" || return
                    simple_dir="$BK_NEW_RESULT"
                fi
                idx=$((idx+1))
                bk_sub_dir "$simple_dir" "$idx"
                for f in $files; do bk_file "$f"; done
                echo -e "  ${DIM}Выполняю: ${cmd}${RESET}"
                ( set -e -o pipefail; eval "$cmd" ) >> "$REPORT_FILE" 2>&1
                rc=$?
                if (( rc == 0 )); then
                    echo -e "  ${GREEN}${BOLD}✔ Применено успешно${RESET}"
                    log "  [REMEDIATION OK] ${desc}"
                    applied=$((applied+1))
                else
                    echo -e "  ${RED}${BOLD}✘ Ошибка при выполнении — откатываю это исправление (подробности в отчёте)${RESET}"
                    restore_dir "$CUR_BK_DIR" >> "$REPORT_FILE" 2>&1
                    log "  [REMEDIATION FAIL] ${desc}"
                    failed=$((failed+1))
                fi
                CUR_BK_DIR=""
                ;;
            q|й)
                echo -e "  ${DIM}Выход из режима исправлений.${RESET}"
                break
                ;;
            *)
                echo -e "  ${DIM}Пропущено.${RESET}"
                skipped=$((skipped+1))
                ;;
        esac
    done

    echo ""
    echo -e "${BOLD}  Итог исправлений: ${GREEN}применено: ${applied}${RESET}  ${YELLOW}пропущено: ${skipped}${RESET}  ${RED}ошибок: ${failed}${RESET}"
    log ""
    log "  [REMEDIATION SUMMARY] Применено: ${applied}, Пропущено: ${skipped}, Ошибок: ${failed}"
    if [[ -n "$simple_dir" ]]; then
        log "  Бэкап: ${simple_dir}  (откат всех: ${WHITE}sudo bash ${simple_dir}/rollback.sh${RESET})"
    fi

    if (( applied > 0 )); then
        echo ""
        echo -e "  ${YELLOW}${BOLD}⚠ Часть изменений (параметры ядра в GRUB, /tmp, модули, auditd -e 2) вступит в силу после перезагрузки.${RESET}"
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
#  ОБЩИЕ ПРОВЕРКИ
# ═════════════════════════════════════════════════════════════════════════════

# Права «не шире max» и владелец. group — регулярка ("root|shadow"), первый вариант — для фикса.
check_perm() {
    local id="$1" p="$2" max="$3" owner="$4" group="$5" cur uo go
    [[ -e "$p" ]] || return 0
    cur="$(stat -Lc '%a' "$p" 2>/dev/null)" || return 0
    uo="$(stat -Lc '%U' "$p" 2>/dev/null)"
    go="$(stat -Lc '%G' "$p" 2>/dev/null)"
    if (( (8#$cur & ~8#$max) == 0 )) && [[ "$uo" == "$owner" ]] && [[ "$go" =~ ^(${group})$ ]]; then
        result_pass "[CIS $id] $p: ${cur} ${uo}:${go}"
    else
        result_fail "[CIS $id] $p: ${cur} ${uo}:${go} (нужно ≤${max} ${owner}:${group%%|*})"
        add_fix "[CIS $id] Права ${p} → ≤${max}, ${owner}:${group%%|*}" "simple" \
            "fix_perm $(q "$p") $max $owner $(q "${group%%|*}")"
    fi
}

# sysctl: и текущее значение, и сохранение в конфиге (иначе не переживёт reboot)
check_sysctl() {
    local id="$1" key="$2" want="$3" desc="$4" cur persisted
    cur="$(sysctl -n "$key" 2>/dev/null)" || { result_info "[CIS $id] $key недоступен в этом ядре"; return 0; }
    cur="${cur//$'\t'/ }"
    persisted="$(grep -hsE "^[[:space:]]*${key//./\\.}[[:space:]]*=" /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null \
        | tail -1 | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]+$//')"
    if [[ "$cur" == "$want" && "$persisted" == "$want" ]]; then
        result_pass "[CIS $id] $desc ($key = $cur)"
    elif [[ "$cur" == "$want" ]]; then
        result_fail "[CIS $id] $desc: $key = $cur сейчас, но не сохранён в /etc/sysctl.d (сбросится после перезагрузки)"
        add_fix "[CIS $id] Сохранить ${key}=${want} в ${SYSCTL_FILE}" "simple" "sysctl_set $(q "$key") $(q "$want")"
    else
        result_fail "[CIS $id] $desc — $key = $cur (нужно $want)"
        add_fix "[CIS $id] Установить ${key}=${want} (${desc})" "simple" "sysctl_set $(q "$key") $(q "$want")"
    fi
}

kmod_is_disabled() {
    local m="$1" out
    out="$(modprobe -n -v "$m" 2>/dev/null)"
    grep -Eq "^install[[:space:]]+(/bin/(true|false)|/usr/bin/(true|false))" <<< "$out" \
        && grep -rqsE "^[[:space:]]*blacklist[[:space:]]+${m}([[:space:]]|$)" /etc/modprobe.d /lib/modprobe.d /usr/lib/modprobe.d
}

kmod_available() {
    local m="$1"
    modinfo "$m" >/dev/null 2>&1 || modinfo "${m//-/_}" >/dev/null 2>&1
}

check_kmod() {
    local id="$1" m="$2" desc="$3"
    if lsmod 2>/dev/null | grep -q "^${m//-/_}[[:space:]]"; then
        result_fail "[CIS $id] Модуль ${m} (${desc}) ЗАГРУЖЕН"
        add_fix "[CIS $id] Запретить и выгрузить модуль ${m} (${desc})" "simple" "kmod_disable $(q "$m")"
    elif ! kmod_available "$m"; then
        result_pass "[CIS $id] Модуль ${m} отсутствует в ядре"
    elif kmod_is_disabled "$m"; then
        result_pass "[CIS $id] Модуль ${m} запрещён (install /bin/false + blacklist)"
    else
        result_fail "[CIS $id] Модуль ${m} (${desc}) может быть загружен"
        add_fix "[CIS $id] Запретить модуль ${m} (${desc})" "simple" "kmod_disable $(q "$m")"
    fi
}

check_mount_opts() {
    local id="$1" mnt="$2" want="$3" opts o missing=()
    opts="$(findmnt -kn -o OPTIONS "$mnt" 2>/dev/null)"
    [[ -n "$opts" ]] || return 1
    for o in ${want//,/ }; do
        [[ ",$opts," == *",$o,"* ]] || missing+=("$o")
    done
    if (( ${#missing[@]} == 0 )); then
        result_pass "[CIS $id] $mnt смонтирован с ${want}"
        return 0
    fi
    result_fail "[CIS $id] $mnt без опций: ${missing[*]}"
    if grep -Eq "^[^#[:space:]]+[[:space:]]+${mnt}[[:space:]]" /etc/fstab 2>/dev/null; then
        add_fix "[CIS $id] Добавить ${want} для ${mnt} в /etc/fstab и перемонтировать" "simple" \
            "fstab_add_opts $(q "$mnt") $(q "$want")"
    elif [[ "$mnt" == "/dev/shm" ]]; then
        add_fix "[CIS $id] /dev/shm: nodev,nosuid,noexec (fstab + remount)" "simple" "devshm_harden"
    elif [[ "$mnt" == "/tmp" ]] && systemctl is-enabled --quiet tmp.mount 2>/dev/null; then
        add_fix "[CIS $id] /tmp (tmp.mount): nodev,nosuid,noexec — после перезагрузки" "simple" "tmp_mount_enable"
    else
        result_info "  ${mnt} не описан в /etc/fstab — опции нужно задать вручную"
    fi
    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
#  РАЗДЕЛЫ CIS
# ═════════════════════════════════════════════════════════════════════════════

# ── 1.1 Файловые системы ────────────────────────────────────────────────────
cis_filesystems() {
    section "1.1 ФАЙЛОВЫЕ СИСТЕМЫ, МОДУЛИ ЯДРА, /tmp, /dev/shm"

    result_info "${BOLD}1.1.1 Неиспользуемые файловые системы:${RESET}"
    local m
    for m in cramfs freevxfs hfs hfsplus jffs2; do
        check_kmod "1.1.1.x" "$m" "файловая система $m"
    done
    if lvl 2; then
        if command -v snap &>/dev/null && [[ -n "$(snap list 2>/dev/null | tail -n +2)" ]]; then
            result_info "[CIS 1.1.1.x] squashfs нужен для snap-пакетов — оставлен"
        else
            check_kmod "1.1.1.x" squashfs "файловая система squashfs"
        fi
        if ask_yn fs.udf "Нужна ли поддержка UDF (ISO/DVD; в Azure — для provisioning)?" n; then
            result_info "[CIS 1.1.1.x] udf оставлен по ответу"
        else
            check_kmod "1.1.1.x" udf "файловая система udf"
        fi
    else
        skip_l2 "1.1.1.x" "squashfs/udf"
    fi
    if [[ "${ANS[role.usb]:-n}" == "y" ]]; then
        result_info "[CIS 1.1.1.x] usb-storage оставлен (по ответу: USB-накопители используются)"
    else
        check_kmod "1.1.1.x" usb-storage "USB-накопители"
    fi

    echo ""
    result_info "${BOLD}1.1.2 Разделы и опции монтирования:${RESET}"
    if findmnt -kn /tmp >/dev/null 2>&1; then
        result_pass "[CIS 1.1.2.1.1] /tmp — отдельная точка монтирования"
        check_mount_opts "1.1.2.1.2-4" /tmp nodev,nosuid,noexec
    else
        result_fail "[CIS 1.1.2.1.1] /tmp не является отдельным разделом"
        if (( HAS_SYSTEMD )); then
            if ask_yn fs.tmp_tmpfs "Смонтировать /tmp как tmpfs (до 50% RAM, nodev,nosuid,noexec) после перезагрузки?" y \
                "noexec на /tmp изредка мешает установщикам, которые запускают скрипты из /tmp"; then
                add_fix "[CIS 1.1.2.1] /tmp → tmpfs (nodev,nosuid,noexec) через tmp.mount, после перезагрузки" "simple" "tmp_mount_enable"
            fi
        fi
    fi
    if findmnt -kn /dev/shm >/dev/null 2>&1; then
        check_mount_opts "1.1.2.2.2-4" /dev/shm nodev,nosuid,noexec
    fi
    local p
    for p in /home /var /var/tmp /var/log /var/log/audit; do
        if findmnt -kn "$p" >/dev/null 2>&1; then
            result_pass "[CIS 1.1.2.x] $p — отдельный раздел"
            case "$p" in
                /home|/var|/var/log|/var/log/audit) check_mount_opts "1.1.2.x" "$p" nodev,nosuid ;;
                /var/tmp) check_mount_opts "1.1.2.x" "$p" nodev,nosuid,noexec ;;
            esac
        elif lvl 2; then
            result_warn "[CIS 1.1.2.x] $p не на отдельном разделе (L2; переразметка — только вручную)"
        fi
    done

    echo ""
    result_info "${BOLD}1.1.3 Прочее:${RESET}"
    fs_scan
    local sd_count
    sd_count="$(fs_list SD | grep -c . || true)"
    if (( sd_count == 0 )); then
        result_pass "[CIS 1.1.x] Все world-writable каталоги имеют sticky bit"
    else
        result_fail "[CIS 1.1.x] World-writable каталогов без sticky bit: ${sd_count}"
        fs_list SD | head -10 | while read -r p; do log "    ${DIM}${p}${RESET}"; done
        add_fix "[CIS 1.1.x] Установить sticky bit на ${sd_count} world-writable каталогов" "simple" "fix_sticky_dirs"
    fi
    if unit_exists autofs.service && unit_on autofs.service; then
        if ask_yn svc.autofs "autofs (автомонтирование) включён. Нужен ли он?" n; then
            result_info "[CIS 1.1.x] autofs оставлен по ответу"
        else
            result_fail "[CIS 1.1.x] autofs включён"
            add_fix "[CIS 1.1.x] Отключить autofs" "simple" "svc_disable autofs.service"
        fi
    else
        result_pass "[CIS 1.1.x] autofs не используется"
    fi
}

# ── 1.2–1.7 Загрузчик, процессы, MAC, баннеры, обновления ───────────────────
cis_boot_process() {
    section "1.2–1.5 ОБНОВЛЕНИЯ, ЗАГРУЗЧИК, ЗАЩИТА ПРОЦЕССОВ"

    result_info "${BOLD}1.2 Пакетный менеджер и обновления:${RESET}"
    if [[ "$PKG_MGR" == "apt-get" ]]; then
        if grep -rqsE '^[[:space:]]*deb.*\[.*trusted=yes' /etc/apt/sources.list /etc/apt/sources.list.d/; then
            result_fail "[CIS 1.2.1.x] Есть репозитории с trusted=yes (без проверки подписи)"
        else
            result_pass "[CIS 1.2.1.x] Все репозитории apt проверяются по подписи"
        fi
        if pkg_installed unattended-upgrades && grep -rqs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/; then
            result_pass "[CIS 1.2.2] Автоматические обновления безопасности включены"
        elif ask_yn upd.auto "Включить автоматическую установку обновлений безопасности (unattended-upgrades)?" y; then
            result_fail "[CIS 1.2.2] Автоматические обновления безопасности не включены"
            add_fix "[CIS 1.2.2] Установить и включить unattended-upgrades" "simple" \
                "pkg_install unattended-upgrades && write_file /etc/apt/apt.conf.d/20auto-upgrades 644 $(q $'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";')"
        else
            result_warn "[CIS 1.2.2] Автообновления не включены (по ответу) — ставьте патчи вручную"
        fi
    elif [[ "$PKG_MGR" == "dnf" || "$PKG_MGR" == "yum" ]]; then
        local gpg; gpg="$(conf_get /etc/dnf/dnf.conf gpgcheck)"
        [[ -z "$gpg" && -f /etc/yum.conf ]] && gpg="$(conf_get /etc/yum.conf gpgcheck)"
        if [[ "${gpg,,}" =~ ^(1|true|yes)$ ]]; then
            result_pass "[CIS 1.2.1.2] gpgcheck=1 глобально"
        else
            result_fail "[CIS 1.2.1.2] gpgcheck не включён глобально"
            add_fix "[CIS 1.2.1.2] gpgcheck=1 в /etc/dnf/dnf.conf" "simple" "conf_set /etc/dnf/dnf.conf gpgcheck 1 ="
        fi
        if grep -rqsE '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*0' /etc/yum.repos.d/; then
            result_fail "[CIS 1.2.1.2] Есть репозитории с gpgcheck=0: $(grep -rlsE '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*0' /etc/yum.repos.d/ | tr '\n' ' ')"
        fi
        if systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null || systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null; then
            result_pass "[CIS 1.2.2] dnf-automatic включён"
        elif [[ "$PKG_MGR" == "dnf" ]] && ask_yn upd.auto "Включить автоматическую установку обновлений безопасности (dnf-automatic)?" y; then
            result_fail "[CIS 1.2.2] Автоматические обновления безопасности не включены"
            add_fix "[CIS 1.2.2] dnf-automatic: только security, с установкой" "simple" \
                "pkg_install dnf-automatic && conf_set /etc/dnf/automatic.conf upgrade_type security ' = ' && conf_set /etc/dnf/automatic.conf apply_updates yes ' = ' && svc_enable dnf-automatic.timer" \
                "/etc/dnf/automatic.conf"
        fi
    fi

    echo ""
    result_info "${BOLD}1.4 Загрузчик:${RESET}"
    local cfg
    if cfg="$(grub_cfg_path)"; then
        check_perm "1.4.2" "$cfg" 600 root root
        [[ -f /boot/grub2/user.cfg ]] && check_perm "1.4.2" /boot/grub2/user.cfg 600 root root
        if { grep -qs '^[[:space:]]*set superusers' "$cfg" && grep -qs 'password_pbkdf2' "$cfg"; } \
           || grep -qs 'GRUB2_PASSWORD' /boot/grub2/user.cfg; then
            result_pass "[CIS 1.4.1] Пароль загрузчика установлен"
        else
            result_fail "[CIS 1.4.1] Пароль загрузчика не установлен (параметры ядра можно изменить с консоли)"
            if ask_yn boot.password "Установить пароль GRUB? Обычная загрузка останется без пароля, он нужен для редактирования записей" n \
                "Пароль понадобится при доступе к консоли (KVM/IPMI). Сохраните его в менеджере паролей."; then
                add_fix "[CIS 1.4.1] Установить пароль загрузчика (запросит пароль)" "simple" "grub_set_password"
            fi
        fi
    else
        result_info "[CIS 1.4] grub.cfg не найден (контейнер, EFI-stub или другой загрузчик)"
    fi
    if [[ "$OS_FAMILY" == "debian" ]] && [[ -n "$(passwd -S root 2>/dev/null | awk '$2=="L" || $2=="NP"')" ]]; then
        result_info "[CIS 1.4.3] root без пароля/заблокирован — rescue-режим потребует доступа с live-носителя"
    fi

    echo ""
    result_info "${BOLD}1.5 Защита процессов:${RESET}"
    check_sysctl "1.5.1" kernel.randomize_va_space 2 "ASLR полный"
    check_sysctl "1.5.2" kernel.yama.ptrace_scope 1 "ptrace только для родителя"
    check_sysctl "1.5.3" fs.suid_dumpable 0 "Без core dump для SUID-программ"
    check_sysctl "1.5.x" kernel.dmesg_restrict 1 "dmesg ограничен для обычных пользователей"
    check_sysctl "1.5.x" kernel.kptr_restrict 2 "Указатели ядра скрыты"
    check_sysctl "1.5.x" fs.protected_hardlinks 1 "Защита жёстких ссылок"
    check_sysctl "1.5.x" fs.protected_symlinks 1 "Защита символических ссылок"
    if grep -rqsE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d/; then
        result_pass "[CIS 1.5.3] Core dump запрещены (limits: * hard core 0)"
    else
        result_fail "[CIS 1.5.3] Core dump не ограничены в limits.conf"
        add_fix "[CIS 1.5.3] * hard core 0 в /etc/security/limits.d/60-cis-hardening.conf" "simple" \
            "write_file /etc/security/limits.d/60-cis-hardening.conf 644 '* hard core 0'"
    fi
    if [[ -d /etc/systemd ]] && command -v coredumpctl &>/dev/null; then
        if grep -rqsE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*none' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/ \
           && grep -rqsE '^[[:space:]]*ProcessSizeMax[[:space:]]*=[[:space:]]*0' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/; then
            result_pass "[CIS 1.5.3] systemd-coredump: Storage=none, ProcessSizeMax=0"
        else
            result_fail "[CIS 1.5.3] systemd-coredump сохраняет дампы"
            add_fix "[CIS 1.5.3] systemd-coredump: Storage=none, ProcessSizeMax=0" "simple" \
                "write_file /etc/systemd/coredump.conf.d/60-cis-hardening.conf 644 $(q $'[Coredump]\nStorage=none\nProcessSizeMax=0')"
        fi
    fi
    if pkg_installed prelink; then
        result_fail "[CIS 1.5.4] prelink установлен (мешает проверке целостности AIDE)"
        add_fix "[CIS 1.5.4] Удалить prelink (с восстановлением бинарников)" "simple" "prelink -ua; pkg_remove prelink"
    else
        result_pass "[CIS 1.5.4] prelink не установлен"
    fi
    if unit_exists apport.service && unit_on apport.service; then
        result_fail "[CIS 1.5.5] apport (автоотправка отчётов о сбоях) включён"
        add_fix "[CIS 1.5.5] Отключить apport" "simple" \
            "conf_set /etc/default/apport enabled 0 = && svc_disable apport.service" "/etc/default/apport"
    fi
}

cis_mac_banners() {
    section "1.6–1.7 МАНДАТНЫЙ КОНТРОЛЬ ДОСТУПА И БАННЕРЫ"

    if [[ "$OS_FAMILY" == "rhel" ]] || command -v getenforce &>/dev/null; then
        local mode cfg_mode
        if ! command -v getenforce &>/dev/null; then
            result_fail "[CIS 1.6.1.1] SELinux (libselinux-utils) не установлен"
            add_fix "[CIS 1.6.1.1] Установить libselinux" "simple" "pkg_install libselinux libselinux-utils"
        else
            mode="$(getenforce 2>/dev/null)"
            cfg_mode="$(conf_get /etc/selinux/config SELINUX)"
            if grep -qsE '(^| )(selinux=0|enforcing=0)( |$)' /proc/cmdline; then
                result_fail "[CIS 1.6.1.2] SELinux отключён параметром ядра"
                add_fix "[CIS 1.6.1.2] Убрать selinux=0/enforcing=0 из параметров ядра" "simple" \
                    "grubby --update-kernel=ALL --remove-args='selinux=0 enforcing=0'" "/boot/loader/entries"
            fi
            case "$mode" in
                Enforcing) result_pass "[CIS 1.6.1.4-5] SELinux: Enforcing" ;;
                Permissive)
                    if lvl 2; then
                        result_fail "[CIS 1.6.1.5] SELinux: Permissive (L2 требует Enforcing)"
                        add_fix "[CIS 1.6.1.5] SELinux → Enforcing (setenforce 1 + /etc/selinux/config)" "simple" \
                            "setenforce 1 && conf_set /etc/selinux/config SELINUX enforcing ="
                    else
                        result_pass "[CIS 1.6.1.4] SELinux: Permissive (L1 допускает; L2 требует Enforcing)"
                    fi ;;
                *)
                    result_fail "[CIS 1.6.1.4] SELinux отключён (config: ${cfg_mode:-?})"
                    if ask_yn mac.selinux_enable "Включить SELinux в режиме Permissive с полной переразметкой ФС при следующей загрузке?" n \
                        "Переразметка занимает от минут до часов на больших ФС. Enforcing — отдельным шагом после проверки журналов."; then
                        add_fix "[CIS 1.6.1.4] SELINUX=permissive + /.autorelabel (после перезагрузки)" "simple" \
                            "conf_set /etc/selinux/config SELINUX permissive = && bk_file /.autorelabel && touch /.autorelabel"
                    fi ;;
            esac
            local stype; stype="$(conf_get /etc/selinux/config SELINUXTYPE)"
            if [[ "$stype" =~ ^(targeted|mls)$ ]]; then
                result_pass "[CIS 1.6.1.3] SELINUXTYPE=${stype}"
            elif [[ -f /etc/selinux/config ]]; then
                result_fail "[CIS 1.6.1.3] SELINUXTYPE=${stype:-не задан}"
                add_fix "[CIS 1.6.1.3] SELINUXTYPE=targeted" "simple" "conf_set /etc/selinux/config SELINUXTYPE targeted ="
            fi
            local p
            for p in setroubleshoot mcstrans; do
                if pkg_installed "$p"; then
                    result_fail "[CIS 1.6.1.x] Установлен ${p} (не нужен на сервере)"
                    add_fix "[CIS 1.6.1.x] Удалить ${p}" "simple" "pkg_remove $p"
                fi
            done
        fi
    elif [[ "$OS_FAMILY" == "debian" ]]; then
        if ! command -v aa-status &>/dev/null || ! pkg_installed apparmor; then
            result_fail "[CIS 1.6.1.1] AppArmor не установлен"
            add_fix "[CIS 1.6.1.1] Установить apparmor и apparmor-utils" "simple" "pkg_install apparmor apparmor-utils"
        elif aa-status --enabled 2>/dev/null; then
            result_pass "[CIS 1.6.1.2] AppArmor включён в ядре"
            local loaded enforce complain unconfined
            loaded="$(aa-status 2>/dev/null | awk '/profiles are loaded/{print $1}')"
            enforce="$(aa-status 2>/dev/null | awk '/profiles are in enforce mode/{print $1}')"
            complain="$(aa-status 2>/dev/null | awk '/profiles are in complain mode/{print $1}')"
            unconfined="$(aa-status 2>/dev/null | awk '/processes are unconfined but have a profile defined/{print $1}')"
            result_info "  Профилей: ${loaded:-?}, enforce: ${enforce:-?}, complain: ${complain:-?}"
            if is_num "$unconfined" && (( unconfined > 0 )); then
                result_warn "[CIS 1.6.1.3] Процессов без применённого профиля: ${unconfined} (перезапустите их)"
            fi
            if lvl 2 && is_num "$complain" && (( complain > 0 )); then
                result_fail "[CIS 1.6.1.4] Профилей в complain-режиме: ${complain} (L2 требует enforce)"
                if ask_yn mac.aa_enforce "Перевести ВСЕ профили AppArmor в enforce? (может заблокировать приложения с неполными профилями)" n; then
                    add_fix "[CIS 1.6.1.4] aa-enforce /etc/apparmor.d/*" "simple" \
                        "pkg_installed apparmor-utils || pkg_install apparmor-utils; aa-enforce /etc/apparmor.d/* >/dev/null" "/etc/apparmor.d"
                fi
            fi
        else
            result_fail "[CIS 1.6.1.2] AppArmor установлен, но не активен в ядре"
            add_fix "[CIS 1.6.1.2] apparmor=1 security=apparmor в параметрах ядра (после перезагрузки)" "simple" \
                "grub_add_args apparmor=1 security=apparmor"
        fi
    else
        result_warn "[CIS 1.6] Семейство ОС не распознано — MAC не проверяется"
    fi

    echo ""
    result_info "${BOLD}1.7 Баннеры:${RESET}"
    local f txt
    for f in /etc/motd /etc/issue /etc/issue.net; do
        if [[ -f "$f" ]]; then
            txt="$(cat "$f" 2>/dev/null)"
            if grep -Eq '\\[mrsv]' <<< "$txt" || { [[ "$OS_ID" != "unknown" ]] && grep -qi "$OS_ID" <<< "$txt"; }; then
                result_fail "[CIS 1.7.x] $f раскрывает сведения об ОС"
                add_fix "[CIS 1.7.x] Заменить содержимое $f предупреждающим баннером" "simple" \
                    "banner_write $(q "$f") $(q "$BANNER_TEXT")"
            elif [[ "$f" != /etc/motd && -z "${txt//[[:space:]]/}" ]]; then
                result_fail "[CIS 1.7.x] $f пуст — нет предупреждения о мониторинге"
                add_fix "[CIS 1.7.x] Записать баннер в $f" "simple" "banner_write $(q "$f") $(q "$BANNER_TEXT")"
            else
                result_pass "[CIS 1.7.x] $f не раскрывает сведения об ОС"
            fi
            check_perm "1.7.x" "$f" 644 root root
        elif [[ "$f" != /etc/motd ]]; then
            result_fail "[CIS 1.7.x] $f отсутствует"
            add_fix "[CIS 1.7.x] Создать $f с баннером" "simple" "banner_write $(q "$f") $(q "$BANNER_TEXT")"
        fi
    done
}

# ── 2.x Сервисы ─────────────────────────────────────────────────────────────
# "ключ|название|юниты через запятую|уровень|дефолт «нужен?»|подсказка"
SERVICE_TABLE=(
    "avahi|Avahi (mDNS/Zeroconf)|avahi-daemon.service,avahi-daemon.socket|1|n|"
    "dhcpd|DHCP-сервер|isc-dhcp-server.service,isc-dhcp-server6.service,dhcpd.service,dhcpd6.service,kea-dhcp4-server.service,kea-dhcp6-server.service|1|n|"
    "dns|DNS-сервер (BIND)|named.service,bind9.service|1|n|"
    "dnsmasq|dnsmasq|dnsmasq.service|1|n|libvirt запускает свои dnsmasq отдельно — их это не затронет"
    "ftp|FTP-сервер|vsftpd.service,proftpd.service,pure-ftpd.service|1|n|"
    "ldap|LDAP-сервер (slapd)|slapd.service|1|n|"
    "imap|IMAP/POP3 (dovecot)|dovecot.service,dovecot.socket|1|n|"
    "nfs|NFS-сервер|nfs-server.service,nfs-kernel-server.service|1|n|"
    "nis|NIS-сервер|ypserv.service|1|n|"
    "cups|Печать (CUPS)|cups.service,cups.socket,cups.path|1|n|"
    "rpcbind|rpcbind|rpcbind.service,rpcbind.socket|1|n|Нужен NFS-клиентам v3 и NIS"
    "rsyncd|rsync-демон|rsync.service,rsyncd.service,rsyncd.socket|1|n|Клиент rsync это не затрагивает"
    "samba|Samba (SMB)|smbd.service,smb.service,nmbd.service,nmb.service|1|n|"
    "snmp|SNMP-агент|snmpd.service|1|n|Нужен, если сервер мониторится по SNMP"
    "tftp|TFTP-сервер|tftpd-hpa.service,tftp.socket,tftp.service|1|n|"
    "squid|Web-прокси (squid)|squid.service|1|n|"
    "http|Веб-сервер (apache/nginx/lighttpd)|apache2.service,httpd.service,nginx.service,lighttpd.service|1|y|"
    "inetd|xinetd/inetd (telnet, rsh, ...)|xinetd.service,inetd.service,openbsd-inetd.service,inetutils-inetd.service|1|n|"
    "telnetd|Telnet-сервер|telnet.socket|1|n|"
    "bluetooth|Bluetooth|bluetooth.service|1|n|"
    "gui|Графический вход (display manager)|display-manager.service,gdm.service,gdm3.service,lightdm.service,sddm.service|1|n|"
)

cis_services() {
    section "2.x СЕРВИСЫ, СИНХРОНИЗАЦИЯ ВРЕМЕНИ, CRON"

    result_info "${BOLD}2.1–2.2 Серверные сервисы (спрашиваю только про найденные):${RESET}"
    local row key label units level def hint u found=""
    local -a active_units=()
    for row in "${SERVICE_TABLE[@]}"; do
        IFS='|' read -r key label units level def hint <<< "$row"
        if [[ "$key" == "gui" ]]; then
            def="${ANS[role.gui]:-n}"
            ANS[svc.gui]="$def"
        fi
        active_units=()
        for u in ${units//,/ }; do
            unit_exists "$u" && unit_on "$u" && active_units+=("$u")
        done
        (( ${#active_units[@]} )) || continue
        if (( level > CIS_LEVEL )); then
            skip_l2 "2.x" "$label"
            continue
        fi
        found=1
        if ask_yn "svc.$key" "Обнаружен ${label} (${active_units[*]}). Нужен ли он на этом сервере?" "$def" "$hint"; then
            result_info "[CIS 2.x] ${label}: оставлен (используется)"
        else
            result_fail "[CIS 2.x] ${label} включён, но не нужен"
            add_fix "[CIS 2.x] Остановить, отключить и замаскировать: ${label}" "simple" "svc_disable ${active_units[*]}"
        fi
    done
    [[ -z "$found" ]] && result_pass "[CIS 2.x] Лишних серверных сервисов не обнаружено"

    # 2.1.x MTA только на loopback
    local smtp
    smtp="$(listening_ports | awk '$1=="tcp" && ($2=="25" || $2=="465" || $2=="587") {print $2"/"$3}' | tr '\n' ' ')"
    if [[ -n "$smtp" ]]; then
        result_fail "[CIS 2.1.21] Почтовый агент слушает внешние интерфейсы: ${smtp}"
        if command -v postconf &>/dev/null && ! ask_yn svc.mta_external "Этот сервер принимает почту из сети (MX/релей)?" n; then
            add_fix "[CIS 2.1.21] postfix: inet_interfaces = loopback-only" "simple" \
                "bk_note R postfix && postconf -e 'inet_interfaces = loopback-only' && systemctl restart postfix" "/etc/postfix/main.cf"
        fi
    else
        result_pass "[CIS 2.1.21] MTA не слушает внешние интерфейсы"
    fi

    echo ""
    result_info "${BOLD}2.3 Небезопасные клиенты:${RESET}"
    local clients=() p
    for p in telnet inetutils-telnet rsh-client rsh talk ldap-utils openldap-clients nis ypbind ftp tnftp; do
        pkg_installed "$p" && clients+=("$p")
    done
    if (( ${#clients[@]} == 0 )); then
        result_pass "[CIS 2.2.x] Небезопасные клиенты (telnet, rsh, talk, ftp, nis, ldap) не установлены"
    else
        result_fail "[CIS 2.2.x] Установлены: ${clients[*]}"
        if ask_yn svc.remove_clients "Удалить пакеты ${clients[*]}?" y "Пакеты ldap-utils/openldap-clients иногда нужны для диагностики LDAP/AD"; then
            add_fix "[CIS 2.2.x] Удалить небезопасные клиенты: ${clients[*]}" "simple" "pkg_remove ${clients[*]}"
        fi
    fi

    echo ""
    result_info "${BOLD}2.3 Синхронизация времени:${RESET}"
    local ts_on=() t
    for t in chrony.service chronyd.service systemd-timesyncd.service ntp.service ntpd.service ntpsec.service; do
        unit_exists "$t" && systemctl is-active --quiet "$t" 2>/dev/null && ts_on+=("$t")
    done
    if (( ${#ts_on[@]} == 1 )); then
        result_pass "[CIS 2.3.1.1] Работает один демон времени: ${ts_on[0]}"
        if [[ "${ts_on[0]}" == chrony* ]]; then
            local cu; cu="$(ps -o user= -C chronyd 2>/dev/null | head -1)"
            if [[ "$cu" == "root" ]]; then
                result_fail "[CIS 2.3.3.2] chronyd работает от root"
            elif [[ -n "$cu" ]]; then
                result_pass "[CIS 2.3.3.2] chronyd работает от ${cu}"
            fi
        fi
    elif (( ${#ts_on[@]} > 1 )); then
        result_fail "[CIS 2.3.1.1] Одновременно работают: ${ts_on[*]}"
        if [[ " ${ts_on[*]} " == *" systemd-timesyncd.service "* ]]; then
            add_fix "[CIS 2.3.1.1] Отключить systemd-timesyncd (оставить chrony/ntp)" "simple" "svc_disable systemd-timesyncd.service"
        fi
    else
        result_fail "[CIS 2.3.1.1] Синхронизация времени не работает"
        if unit_exists systemd-timesyncd.service; then
            add_fix "[CIS 2.3.1.1] Включить systemd-timesyncd" "simple" "svc_enable systemd-timesyncd.service"
        elif [[ "$OS_FAMILY" == "rhel" ]]; then
            add_fix "[CIS 2.3.1.1] Установить и включить chrony" "simple" "pkg_install chrony && svc_enable chronyd.service"
        else
            add_fix "[CIS 2.3.1.1] Установить и включить chrony" "simple" "pkg_install chrony && svc_enable chrony.service"
        fi
    fi

    echo ""
    result_info "${BOLD}2.4 Планировщики cron/at:${RESET}"
    local cron_unit=""
    for u in cron.service crond.service; do unit_exists "$u" && cron_unit="$u"; done
    if [[ -n "$cron_unit" ]]; then
        if systemctl is-enabled --quiet "$cron_unit" 2>/dev/null && systemctl is-active --quiet "$cron_unit" 2>/dev/null; then
            result_pass "[CIS 2.4.1.1] ${cron_unit} включён и работает"
        else
            result_fail "[CIS 2.4.1.1] ${cron_unit} не включён"
            add_fix "[CIS 2.4.1.1] Включить ${cron_unit}" "simple" "svc_enable $cron_unit"
        fi
        check_perm "2.4.1.2" /etc/crontab 600 root root
        local cd
        for cd in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
            check_perm "2.4.1.3-7" "$cd" 700 root root
        done
        cis_allow_file cron /etc/cron.allow /etc/cron.deny "2.4.1.8"
    fi
    if command -v at &>/dev/null; then
        cis_allow_file at /etc/at.allow /etc/at.deny "2.4.2.1"
    fi
}

# cron.allow / at.allow: существует, ≤640, root:(root|crontab|daemon)
cis_allow_file() {
    local kind="$1" allow="$2" deny="$3" id="$4" grp="root" users=() ff
    getent group crontab >/dev/null 2>&1 && [[ "$kind" == "cron" ]] && grp="root|crontab"
    getent group daemon >/dev/null 2>&1 && [[ "$kind" == "at" ]] && grp="root|daemon"
    if [[ -f "$allow" ]]; then
        check_perm "$id" "$allow" 640 root "$grp"
    else
        # Пользователи, у которых уже есть crontab, — иначе их задачи перестанут работать
        if [[ "$kind" == "cron" ]]; then
            for ff in /var/spool/cron/crontabs/* /var/spool/cron/*; do
                [[ -f "$ff" ]] && users+=("${ff##*/}")
            done
        fi
        result_fail "[CIS $id] ${allow} отсутствует — ${kind} доступен всем пользователям"
        local -a list=()
        mapfile -t list < <(printf '%s\n' root ${users[@]+"${users[@]}"} | sort -u)
        if ask_yn "sched.${kind}_allow" "Создать ${allow} (разрешить только: ${list[*]})?" y \
            "Пользователи с существующими crontab добавлены, чтобы их задачи не перестали работать"; then
            add_fix "[CIS $id] Создать ${allow} (${list[*]})" "simple" \
                "write_file $(q "$allow") 640 $(q "$(printf '%s\n' "${list[@]}")")"
        fi
    fi
    [[ -f "$deny" ]] && check_perm "$id" "$deny" 640 root "$grp"
}

# ── 3.x Сеть ────────────────────────────────────────────────────────────────
cis_network() {
    section "3.x СЕТЬ: ПАРАМЕТРЫ ЯДРА И ПРОТОКОЛЫ"

    result_info "${BOLD}3.1 Устройства и IPv6:${RESET}"
    if [[ "${ANS[role.ipv6]:-y}" == "n" ]]; then
        local v6; v6="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)"
        if [[ "$v6" == "1" ]]; then
            result_pass "[CIS 3.1.1] IPv6 отключён (не используется)"
        else
            result_fail "[CIS 3.1.1] IPv6 включён, хотя по ответу не используется"
            add_fix "[CIS 3.1.1] Отключить IPv6 (all, default)" "simple" \
                "sysctl_set net.ipv6.conf.all.disable_ipv6 1 && sysctl_set net.ipv6.conf.default.disable_ipv6 1"
        fi
    else
        result_info "[CIS 3.1.1] IPv6 используется — проверяю параметры IPv6"
    fi
    local wl=() i
    for i in /sys/class/net/*/wireless; do [[ -d "$i" ]] && { i="${i%/wireless}"; wl+=("${i##*/}"); }; done
    if (( ${#wl[@]} )); then
        if ask_yn net.wireless "Обнаружены Wi-Fi-интерфейсы (${wl[*]}). Нужны ли они?" n; then
            result_info "[CIS 3.1.2] Wi-Fi оставлен по ответу"
        else
            result_fail "[CIS 3.1.2] Wi-Fi-интерфейсы активны: ${wl[*]}"
            if command -v nmcli &>/dev/null; then
                add_fix "[CIS 3.1.2] Выключить радиомодули (nmcli radio all off)" "simple" "nmcli radio all off"
            fi
        fi
    else
        result_pass "[CIS 3.1.2] Беспроводных интерфейсов нет"
    fi

    echo ""
    result_info "${BOLD}3.2 Редкие сетевые протоколы:${RESET}"
    if lvl 2; then
        local m
        for m in dccp tipc rds sctp; do check_kmod "3.2.x" "$m" "протокол ${m^^}"; done
    else
        skip_l2 "3.2.x" "dccp/tipc/rds/sctp"
    fi

    echo ""
    result_info "${BOLD}3.3 Параметры сети ядра:${RESET}"
    if [[ "${ANS[role.router]:-n}" == "y" ]]; then
        result_info "[CIS 3.3.1] ip_forward не трогаю: хост маршрутизирует трафик (Docker/K8s/VPN/роутер)"
    else
        check_sysctl "3.3.1" net.ipv4.ip_forward 0 "IPv4-маршрутизация отключена"
        [[ "${ANS[role.ipv6]:-y}" == "y" ]] && check_sysctl "3.3.1" net.ipv6.conf.all.forwarding 0 "IPv6-маршрутизация отключена"
    fi
    check_sysctl "3.3.2" net.ipv4.conf.all.send_redirects 0 "Отправка ICMP-редиректов отключена"
    check_sysctl "3.3.2" net.ipv4.conf.default.send_redirects 0 "Отправка ICMP-редиректов отключена (default)"
    check_sysctl "3.3.3" net.ipv4.icmp_ignore_bogus_error_responses 1 "Ложные ICMP-ошибки игнорируются"
    check_sysctl "3.3.4" net.ipv4.icmp_echo_ignore_broadcasts 1 "Broadcast ping игнорируется"
    check_sysctl "3.3.5" net.ipv4.conf.all.accept_redirects 0 "ICMP-редиректы отклоняются"
    check_sysctl "3.3.5" net.ipv4.conf.default.accept_redirects 0 "ICMP-редиректы отклоняются (default)"
    check_sysctl "3.3.6" net.ipv4.conf.all.secure_redirects 0 "Secure-редиректы отклоняются"
    check_sysctl "3.3.6" net.ipv4.conf.default.secure_redirects 0 "Secure-редиректы отклоняются (default)"
    check_sysctl "3.3.7" net.ipv4.conf.all.rp_filter 1 "Reverse path filtering"
    check_sysctl "3.3.7" net.ipv4.conf.default.rp_filter 1 "Reverse path filtering (default)"
    check_sysctl "3.3.8" net.ipv4.conf.all.accept_source_route 0 "Source routing отключён"
    check_sysctl "3.3.8" net.ipv4.conf.default.accept_source_route 0 "Source routing отключён (default)"
    check_sysctl "3.3.9" net.ipv4.conf.all.log_martians 1 "Логирование martian-пакетов"
    check_sysctl "3.3.9" net.ipv4.conf.default.log_martians 1 "Логирование martian-пакетов (default)"
    check_sysctl "3.3.10" net.ipv4.tcp_syncookies 1 "SYN cookies"
    if [[ "${ANS[role.ipv6]:-y}" == "y" ]]; then
        check_sysctl "3.3.5" net.ipv6.conf.all.accept_redirects 0 "IPv6 ICMP-редиректы отклоняются"
        check_sysctl "3.3.5" net.ipv6.conf.default.accept_redirects 0 "IPv6 ICMP-редиректы отклоняются (default)"
        check_sysctl "3.3.8" net.ipv6.conf.all.accept_source_route 0 "IPv6 source routing отключён"
        check_sysctl "3.3.8" net.ipv6.conf.default.accept_source_route 0 "IPv6 source routing отключён (default)"
        if ask_yn net.slaac "IPv6-адрес/маршрут получается через SLAAC (Router Advertisement)?" n \
            "Типично для облаков и домашних сетей. Если да — accept_ra оставляю, иначе IPv6 пропадёт."; then
            result_info "[CIS 3.3.11] accept_ra оставлен (адресация через SLAAC)"
        else
            check_sysctl "3.3.11" net.ipv6.conf.all.accept_ra 0 "IPv6 Router Advertisement не принимаются"
            check_sysctl "3.3.11" net.ipv6.conf.default.accept_ra 0 "IPv6 Router Advertisement не принимаются (default)"
        fi
    fi
}

# ── 4.x Брандмауэр ──────────────────────────────────────────────────────────
cis_firewall() {
    section "4.x БРАНДМАУЭР"

    detect_ssh_ports
    result_info "SSH-порты (будут разрешены всегда): ${SSH_PORTS[*]}"
    local backend allowed active=0 p proto port proc
    backend="$(fw_backend)"
    result_info "Утилита: ${backend}"

    # 4.1 одна утилита
    local n_active=0
    command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q 'Status: active' && n_active=$((n_active+1))
    systemctl is-active --quiet firewalld 2>/dev/null && n_active=$((n_active+1))
    systemctl is-active --quiet nftables 2>/dev/null && [[ "$backend" != "firewalld" ]] && n_active=$((n_active+1))
    if (( n_active > 1 )); then
        result_fail "[CIS 4.1.1] Одновременно активны несколько утилит брандмауэра — правила конфликтуют"
    fi

    local allow_in=() allow_out=() remove_svcs=()
    for p in "${SSH_PORTS[@]}"; do allow_in+=("${p}/tcp"); done

    case "$backend" in
        ufw)
            if command -v ufw &>/dev/null; then
                result_pass "[CIS 4.2.1] ufw установлен"
                if ufw status 2>/dev/null | grep -q 'Status: active'; then
                    active=1
                    result_pass "[CIS 4.2.3] ufw активен"
                    local verbose
                    verbose="$(ufw status verbose 2>/dev/null)"
                    if grep -q 'deny (incoming)' <<< "$verbose"; then result_pass "[CIS 4.2.7] Входящие: deny по умолчанию"
                    else result_fail "[CIS 4.2.7] Входящие не запрещены по умолчанию"; fi
                    if ufw show added 2>/dev/null | grep -q 'allow in on lo'; then
                        result_pass "[CIS 4.2.4] Loopback-трафик разрешён, подмена 127.0.0.0/8 запрещена"
                    else
                        result_fail "[CIS 4.2.4] Не настроены правила loopback"
                    fi
                else
                    result_fail "[CIS 4.2.3] ufw установлен, но не активен"
                fi
            else
                result_fail "[CIS 4.2.1] ufw не установлен, брандмауэр не настроен"
            fi
            if pkg_installed iptables-persistent; then
                result_fail "[CIS 4.2.2] iptables-persistent конфликтует с ufw"
            fi
            ;;
        firewalld)
            if command -v firewall-cmd &>/dev/null; then
                result_pass "[CIS 4.1.x] firewalld установлен"
                if systemctl is-active --quiet firewalld 2>/dev/null; then
                    active=1
                    result_pass "[CIS 4.1.x] firewalld работает"
                    local zone s
                    zone="$(firewall-cmd --get-default-zone 2>/dev/null)"
                    result_info "  Зона по умолчанию: ${zone}; интерфейсы: $(firewall-cmd --zone="$zone" --list-interfaces 2>/dev/null)"
                    for s in $(firewall-cmd --permanent --zone="$zone" --list-services 2>/dev/null); do
                        [[ "$s" == "ssh" || "$s" == "dhcpv6-client" ]] && continue
                        if ! ask_yn "fw.svc.$s" "В зоне ${zone} открыт сервис «${s}». Оставить?" y; then
                            remove_svcs+=("$s")
                            result_fail "[CIS 4.1.x] Лишний сервис в зоне: ${s}"
                        fi
                    done
                else
                    result_fail "[CIS 4.1.x] firewalld не запущен"
                fi
            else
                result_fail "[CIS 4.1.x] firewalld не установлен, брандмауэр не настроен"
            fi
            ;;
    esac

    # Открытые порты без правил: спрашиваем, какие из них должны быть доступны
    allowed="$(fw_allowed_ports "$backend")"
    while read -r proto port proc; do
        [[ -n "$port" ]] || continue
        port_allowed "$allowed" "$port" "$proto" && continue
        [[ " ${allow_in[*]} " == *" ${port}/${proto} "* ]] && continue
        if ask_yn "fw.port.${port}_${proto}" "Порт ${port}/${proto} (${proc}) слушает сеть, но не разрешён в брандмауэре. Должен быть доступен извне?" y; then
            allow_in+=("${port}/${proto}")
            result_fail "[CIS 4.x.x] Нет правила для открытого порта ${port}/${proto} (${proc})"
        else
            result_info "  ${port}/${proto} (${proc}) останется закрытым снаружи"
        fi
    done < <(listening_ports)

    # Порты из опросника
    local extra="${ANS[fw.extra_ports]:-}" e
    for e in ${extra//,/ }; do
        [[ "$e" == */* ]] || e="${e}/tcp"
        port_allowed "$allowed" "${e%/*}" "${e#*/}" || allow_in+=("$e")
    done
    mapfile -t allow_in < <(printf '%s\n' "${allow_in[@]}" | sort -u)

    local deny_out="n" deny_routed="y"
    [[ "${ANS[role.router]:-n}" == "y" ]] && deny_routed="n"
    if [[ "$backend" == "ufw" ]]; then
        if ask_yn fw.deny_out "Запретить исходящий трафик по умолчанию (CIS 4.2.7, разрешу DNS/HTTP(S)/NTP + ваш список)?" n \
            "Строже, но apt-зеркала, мониторинг, LDAP и т.п. придётся разрешать явно"; then
            deny_out="y"
            ask_str fw.out_ports "Дополнительные разрешённые исходящие порты (например 25/tcp,389/tcp)" "" "$PORTS_RE"
            allow_out=(53/udp 53/tcp 80/tcp 443/tcp 123/udp)
            for e in ${STR_RESULT//,/ }; do [[ "$e" == */* ]] || e="${e}/tcp"; allow_out+=("$e"); done
            [[ "$(ufw status verbose 2>/dev/null)" == *"deny (outgoing)"* ]] || result_fail "[CIS 4.2.7] Исходящие не запрещены по умолчанию"
        else
            result_warn "[CIS 4.2.7] Исходящий трафик разрешён по умолчанию (по ответу)"
        fi
    fi

    local need_fix=0
    (( active == 0 )) && need_fix=1
    allowed="$(fw_allowed_ports "$backend")"
    for e in "${allow_in[@]}"; do port_allowed "$allowed" "${e%/*}" "${e#*/}" || need_fix=1; done
    (( ${#remove_svcs[@]} )) && need_fix=1
    [[ "$backend" == "ufw" && $active -eq 1 ]] && ! ufw show added 2>/dev/null | grep -q 'allow in on lo' && need_fix=1
    [[ "$deny_out" == "y" ]] && [[ "$(ufw status verbose 2>/dev/null)" != *"deny (outgoing)"* ]] && need_fix=1

    if (( need_fix == 0 )); then
        result_pass "[CIS 4.x] Брандмауэр включён, правила для всех нужных портов есть"
        return
    fi
    if [[ "$backend" == "ufw" ]]; then
        local out_desc=""
        [[ "$deny_out" == "y" ]] && out_desc="; deny outgoing кроме ${allow_out[*]}"
        add_fix "[CIS 4.2.x] ufw: deny incoming, loopback, разрешить ${allow_in[*]}${out_desc}" "firewall" \
            "fw_ufw_configure $(q "${allow_in[*]}") $(q "${allow_out[*]:-}") $deny_out $deny_routed"
    else
        add_fix "[CIS 4.1.x] firewalld: включить, разрешить ${allow_in[*]}${remove_svcs[*]:+; убрать сервисы ${remove_svcs[*]}}" "firewall" \
            "fw_firewalld_configure $(q "${allow_in[*]}") $(q "${remove_svcs[*]:-}")"
    fi
}

# ── 5.1 SSH ─────────────────────────────────────────────────────────────────
ssh_expect() {  # id ключ регулярка-допустимых значение-для-фикса описание
    local id="$1" key="$2" re="$3" val="$4" desc="$5" cur
    cur="$(get_ssh_param "$key")"
    if [[ "${cur,,}" =~ ^(${re})$ ]]; then
        result_pass "[CIS $id] ${key} = ${cur}"
    else
        result_fail "[CIS $id] ${key} = ${cur:-не задан} (${desc})"
        add_fix "[CIS $id] ${key} ${val}" "ssh" "ssh_set_param ${key} $(q "$val")"
    fi
}

ssh_expect_max() {  # id ключ максимум значение-для-фикса
    local id="$1" key="$2" max="$3" val="$4" cur
    cur="$(get_ssh_param "$key")"; cur="${cur%s}"
    if is_num "$cur" && (( cur > 0 && cur <= max )); then
        result_pass "[CIS $id] ${key} = ${cur} (≤ ${max})"
    else
        result_fail "[CIS $id] ${key} = ${cur:-по умолчанию} (нужно 1..${max})"
        add_fix "[CIS $id] ${key} ${val}" "ssh" "ssh_set_param ${key} ${val}"
    fi
}

ssh_algos() {  # id ключ тип-для-ssh-Q регулярка-слабых список-предпочтительных
    local id="$1" key="$2" kind="$3" weak="$4"; shift 4
    local cur want
    cur="$(get_ssh_param_full "$key")"
    want="$(ssh_supported "$kind" "$@")"
    if [[ -n "$cur" ]] && ! grep -Eqi "$weak" <<< "$cur"; then
        result_pass "[CIS $id] ${key}: только стойкие алгоритмы"
    else
        result_fail "[CIS $id] ${key}: ${cur:-по умолчанию (включает устаревшие)}"
        if [[ -n "$want" ]]; then
            add_fix "[CIS $id] ${key} ${want}" "ssh" "ssh_set_param ${key} $(q "$want")"
        else
            result_info "  ssh -Q недоступен — список ${key} задайте вручную"
        fi
    fi
}

cis_ssh() {
    section "5.1 SSH-СЕРВЕР"

    if [[ ! -f /etc/ssh/sshd_config ]]; then
        result_info "OpenSSH-сервер не установлен — раздел пропущен"
        return
    fi
    build_sshd_effective || { result_warn "Не удалось прочитать конфигурацию sshd"; return; }
    result_info "Источник конфигурации: ${SSHD_SOURCE}"
    [[ "$SSHD_SOURCE" != "sshd -T" ]] && result_info "${DIM}  (запуск от root даёт точную эффективную конфигурацию через sshd -T)${RESET}"

    local f
    check_perm "5.1.1" /etc/ssh/sshd_config 600 root root
    for f in /etc/ssh/sshd_config.d/*.conf; do [[ -f "$f" ]] && check_perm "5.1.1" "$f" 600 root root; done
    for f in /etc/ssh/ssh_host_*_key; do
        [[ -f "$f" ]] || continue
        if getent group ssh_keys >/dev/null 2>&1; then
            check_perm "5.1.2" "$f" 640 root "root|ssh_keys"
        else
            check_perm "5.1.2" "$f" 600 root root
        fi
    done
    for f in /etc/ssh/ssh_host_*_key.pub; do [[ -f "$f" ]] && check_perm "5.1.3" "$f" 644 root root; done

    # 5.1.4 ограничение доступа
    local allow_users allow_groups
    allow_users="$(get_ssh_param_full AllowUsers)"
    allow_groups="$(get_ssh_param_full AllowGroups)"
    if [[ -n "$allow_users$allow_groups" ]]; then
        result_pass "[CIS 5.1.4] Доступ ограничен: AllowUsers='${allow_users}' AllowGroups='${allow_groups}'"
    else
        result_fail "[CIS 5.1.4] AllowUsers/AllowGroups не заданы — по SSH может войти любой пользователь"
        local allow_list="${ANS[ssh.allow_users]:-}"
        if [[ -n "$allow_list" ]]; then
            add_fix "[CIS 5.1.4] AllowUsers ${allow_list}" "ssh" "ssh_set_param AllowUsers $(q "$allow_list")"
        fi
    fi

    # 5.1.5 баннер
    local banner; banner="$(get_ssh_param_full Banner)"
    if [[ -n "$banner" && "$banner" != "none" ]]; then
        result_pass "[CIS 5.1.5] Banner ${banner}"
    else
        result_fail "[CIS 5.1.5] Banner не задан"
        add_fix "[CIS 5.1.5] Banner /etc/issue.net" "ssh" "ssh_banner_set"
    fi

    # 5.1.6 / 5.1.12 / 5.1.15 криптография
    ssh_algos "5.1.6" Ciphers cipher '3des|blowfish|arcfour|cast128|-cbc' \
        chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr
    # group16/18 стойкие, но security_audit.sh ищет «diffie-hellman-group1» подстрокой
    # и счёл бы их слабыми — не включаем, чтобы инструменты не противоречили друг другу
    ssh_algos "5.1.12" KexAlgorithms kex 'diffie-hellman-group1-|diffie-hellman-group14|group-exchange-sha1' \
        mlkem768x25519-sha256 sntrup761x25519-sha512@openssh.com sntrup761x25519-sha512 curve25519-sha256 curve25519-sha256@libssh.org \
        ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 diffie-hellman-group-exchange-sha256
    ssh_algos "5.1.15" MACs mac 'hmac-md5|hmac-sha1|umac-64|ripemd' \
        hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com hmac-sha2-512 hmac-sha2-256
    if grep -qi "HostKey.*ssh_host_dsa_key" <<< "$SSHD_EFFECTIVE" || [[ -f /etc/ssh/ssh_host_dsa_key && "$SSHD_SOURCE" != "sshd -T" ]]; then
        result_fail "[CIS 5.1.x] Используется устаревший DSA HostKey"
        add_fix "[CIS 5.1.x] Отключить DSA HostKey" "ssh" "ssh_disable_hostkey dsa"
    else
        result_pass "[CIS 5.1.x] DSA HostKey не используется"
    fi

    # 5.1.7 ClientAlive: интервал × счётчик = заданный таймаут
    local cai cac eff=0 want_int
    cai="$(get_ssh_param ClientAliveInterval)"; cac="$(get_ssh_param ClientAliveCountMax)"
    is_num "$cai" || cai=0; is_num "$cac" || cac=3
    (( cai > 0 )) && eff=$(( cai * (cac > 0 ? cac : 1) ))
    want_int=$(( SSH_IDLE_TIMEOUT / 3 )); (( want_int < 15 )) && want_int=15
    if (( cai > 0 && cac > 0 && eff <= SSH_IDLE_TIMEOUT )); then
        result_pass "[CIS 5.1.7] ClientAliveInterval=${cai} × CountMax=${cac} = ${eff}с (≤ ${SSH_IDLE_TIMEOUT}с)"
    else
        result_fail "[CIS 5.1.7] Таймаут SSH: Interval=${cai}, CountMax=${cac} (нужно > 0 и ≤ ${SSH_IDLE_TIMEOUT}с суммарно)"
        add_fix "[CIS 5.1.7] ClientAliveInterval ${want_int}, ClientAliveCountMax 3" "ssh" \
            "ssh_set_param ClientAliveCountMax 3; ssh_set_param ClientAliveInterval ${want_int}"
    fi

    # 5.1.8 проброс
    if [[ "${ANS[ssh.forwarding]:-n}" == "y" ]]; then
        result_info "[CIS 5.1.8] Проброс портов/агента нужен (по ответу) — DisableForwarding не включаю"
        ssh_expect "5.1.x" X11Forwarding "no" no "X11 не нужен на сервере"
    else
        ssh_has_disableforwarding && ssh_expect "5.1.8" DisableForwarding "yes" yes "проброс X11/агента/портов запрещён"
        ssh_expect "5.1.x" X11Forwarding "no" no "X11 не нужен на сервере"
        ssh_expect "5.1.x" AllowTcpForwarding "no" no "TCP-туннели запрещены"
        ssh_expect "5.1.x" AllowAgentForwarding "no" no "проброс агента запрещён"
    fi

    # 5.1.9 GSSAPI
    if [[ "${ANS[ssh.gssapi]:-n}" == "y" ]]; then
        result_info "[CIS 5.1.9] GSSAPIAuthentication оставлен (Kerberos/FreeIPA/AD)"
    else
        ssh_expect "5.1.9" GSSAPIAuthentication "no" no "GSSAPI не используется"
    fi

    ssh_expect "5.1.10" HostbasedAuthentication "no" no "доверие по хосту отключено"
    ssh_expect "5.1.11" IgnoreRhosts "yes" yes ".rhosts игнорируются"
    ssh_expect_max "5.1.13" LoginGraceTime 60 60
    ssh_expect "5.1.14" LogLevel "verbose|info" VERBOSE "достаточно подробное логирование"
    ssh_expect_max "5.1.16" MaxAuthTries "$MAX_AUTH_TRIES" "$MAX_AUTH_TRIES"

    local ms a b c
    ms="$(get_ssh_param MaxStartups)"
    IFS=: read -r a b c <<< "${ms:-10:30:100}"
    if is_num "$a" && is_num "${b:-x}" && is_num "${c:-x}" && (( a <= 10 && b <= 30 && c <= 60 )); then
        result_pass "[CIS 5.1.17] MaxStartups ${ms}"
    else
        result_fail "[CIS 5.1.17] MaxStartups ${ms:-10:30:100 (по умолчанию)} (нужно ≤ 10:30:60)"
        add_fix "[CIS 5.1.17] MaxStartups 10:30:60" "ssh" "ssh_set_param MaxStartups 10:30:60"
    fi
    ssh_expect_max "5.1.18" MaxSessions 10 10
    ssh_expect "5.1.19" PermitEmptyPasswords "no" no "пустые пароли запрещены"

    local root_target="${ANS[ssh.root_login]:-no}"
    if [[ "$root_target" == "no" ]]; then
        ssh_expect "5.1.20" PermitRootLogin "no" no "прямой вход root запрещён"
    else
        ssh_expect "5.1.20" PermitRootLogin "no|prohibit-password|without-password" prohibit-password \
            "root только по ключу (CIS требует no — оставлено по ответу)"
        [[ "$(get_ssh_param PermitRootLogin)" != "no" ]] && result_warn "[CIS 5.1.20] PermitRootLogin не 'no' — по вашему ответу (root входит по ключу)"
    fi
    ssh_expect "5.1.21" PermitUserEnvironment "no" no "пользователь не подменяет окружение"
    ssh_expect "5.1.22" UsePAM "yes" yes "PAM используется (faillock, лимиты)"

    # Вход по паролю — вне L1, но по запросу и только если у администратора есть ключ
    local pa; pa="$(get_ssh_param PasswordAuthentication)"
    if [[ "${pa,,}" == "no" ]]; then
        result_pass "[CIS 5.1.x] PasswordAuthentication = no"
    elif [[ "${ANS[ssh.no_password]:-n}" == "y" ]]; then
        result_fail "[CIS 5.1.x] PasswordAuthentication = ${pa:-yes} (по ответу — только ключи)"
        add_fix "[CIS 5.1.x] PasswordAuthentication no, KbdInteractiveAuthentication no" "ssh" \
            "ssh_set_param PasswordAuthentication no; ssh_set_param KbdInteractiveAuthentication no"
    else
        result_warn "[CIS 5.1.x] PasswordAuthentication = ${pa:-yes} (оставлено по ответу)"
    fi
}

# ── 5.2 sudo ────────────────────────────────────────────────────────────────
cis_sudo() {
    result_info "${BOLD}5.2 sudo:${RESET}"
    if ! command -v sudo &>/dev/null; then
        result_fail "[CIS 5.2.1] sudo не установлен"
        add_fix "[CIS 5.2.1] Установить sudo" "simple" "pkg_install sudo"
        return
    fi
    result_pass "[CIS 5.2.1] sudo установлен"
    if ! grep -Eqs '^[#@]includedir[[:space:]]+/etc/sudoers\.d' /etc/sudoers; then
        result_warn "[CIS 5.2.x] /etc/sudoers не подключает /etc/sudoers.d — Defaults нужно задать вручную через visudo"
        return
    fi
    local need=0 ts lf
    if sudo_grep '^[[:space:]]*Defaults[[:space:]]+([^#]*,)?[[:space:]]*use_pty' | grep -q . && ! sudo_grep '!use_pty' | grep -q .; then
        result_pass "[CIS 5.2.2] Defaults use_pty"
    else
        result_fail "[CIS 5.2.2] sudo не выделяет pty (use_pty)"; need=1
    fi
    if sudo_grep '^[[:space:]]*Defaults.*logfile[[:space:]]*=' | grep -q .; then
        result_pass "[CIS 5.2.3] Журнал sudo: $(sudo_logfile)"
    else
        result_fail "[CIS 5.2.3] Отдельный журнал sudo (logfile) не задан"; need=1
    fi
    ts="$(sudo_grep 'timestamp_timeout' | grep -oE 'timestamp_timeout[[:space:]]*=[[:space:]]*-?[0-9]+' | tail -1 | grep -oE -- '-?[0-9]+$')"
    if [[ -z "$ts" ]] || { is_num "$ts" && (( ts >= 0 && ts <= 15 )); }; then
        result_pass "[CIS 5.2.6] timestamp_timeout = ${ts:-по умолчанию (≤15)}"
    else
        result_fail "[CIS 5.2.6] timestamp_timeout = ${ts} (нужно 0..15)"; need=1
    fi
    if sudo_grep 'NOPASSWD' | grep -q .; then
        if lvl 2; then result_fail "[CIS 5.2.4] Есть правила NOPASSWD (L2 требует пароль): $(sudo_grep 'NOPASSWD' | head -3 | tr '\n' ';')"
        else result_warn "[CIS 5.2.4] Есть правила NOPASSWD — проверьте, нужны ли они"; fi
    else
        result_pass "[CIS 5.2.4] Все правила sudo требуют пароль"
    fi
    if sudo_grep '!authenticate' | grep -q .; then
        result_fail "[CIS 5.2.5] Есть правила с !authenticate — повторная аутентификация отключена"
    else
        result_pass "[CIS 5.2.5] Повторная аутентификация не отключена"
    fi
    lf="$(sudo_logfile)"
    (( need )) && add_fix "[CIS 5.2.2-6] ${SUDO_DROPIN}: use_pty, logfile=${lf}, timestamp_timeout=15" "sudo" \
        "sudo_set_defaults $(q "$lf") 15"
}

# ── 5.3–5.4 PAM, пароли, учётные записи ─────────────────────────────────────
pwq_value() {
    local key="$1" v="" f
    for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
        [[ -f "$f" ]] || continue
        local t; t="$(sys_kv "$f" "$key")"
        [[ -n "$t" ]] && v="$t"
    done
    if [[ -z "$v" ]]; then
        v="$(grep -hsE 'pam_(pwquality|cracklib)\.so' /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null \
            | grep -v '^[[:space:]]*#' | grep -oE "${key}=-?[0-9]+" | tail -1 | cut -d= -f2)"
    fi
    echo "$v"
}

pam_has() { grep -hsE "^[[:space:]]*[a-z]+[[:space:]].*$1" "${PAM_LIST[@]}" 2>/dev/null | grep -q .; }

cis_access() {
    section "5.2–5.4 SUDO, PAM, ПАРОЛИ, УЧЁТНЫЕ ЗАПИСИ"

    cis_sudo

    echo ""
    result_info "${BOLD}5.3 PAM:${RESET}"
    local v
    if pam_has 'pam_pwquality\.so'; then result_pass "[CIS 5.3.2.3] pam_pwquality в стеке"
    else result_fail "[CIS 5.3.2.3] pam_pwquality не подключён"; add_fix "pam_pwquality" "password"; fi
    if pam_has 'pam_faillock\.so'; then result_pass "[CIS 5.3.2.2] pam_faillock в стеке"
    else result_fail "[CIS 5.3.2.2] pam_faillock не подключён"; add_fix "pam_faillock" "password"; fi
    if pam_has 'pam_pwhistory\.so'; then result_pass "[CIS 5.3.2.4] pam_pwhistory в стеке"
    else result_fail "[CIS 5.3.2.4] pam_pwhistory не подключён"; add_fix "pam_pwhistory" "password"; fi
    if grep -hsE '^[^#]*pam_unix\.so.*nullok' "${PAM_LIST[@]}" | grep -q .; then
        result_fail "[CIS 5.3.3.4.1] pam_unix с nullok — вход с пустым паролем возможен"; add_fix "nullok" "password"
    else
        result_pass "[CIS 5.3.3.4.1] pam_unix без nullok"
    fi

    v="$(sys_kv /etc/security/faillock.conf deny)"
    if is_num "$v" && (( v > 0 && v <= FAIL_DENY )); then result_pass "[CIS 5.3.3.1.1] faillock deny = $v"
    else result_fail "[CIS 5.3.3.1.1] faillock deny = ${v:-не задан} (нужно 1..${FAIL_DENY})"; add_fix "faillock deny" "password"; fi
    v="$(sys_kv /etc/security/faillock.conf unlock_time)"
    if is_num "$v" && (( v == 0 || v >= FAIL_UNLOCK_MINUTES * 60 )); then result_pass "[CIS 5.3.3.1.2] faillock unlock_time = $v"
    else result_fail "[CIS 5.3.3.1.2] faillock unlock_time = ${v:-не задан} (нужно 0 или ≥ $((FAIL_UNLOCK_MINUTES*60)))"; add_fix "faillock unlock" "password"; fi
    if lvl 2; then
        if grep -Eqs '^[[:space:]]*even_deny_root' /etc/security/faillock.conf; then
            result_pass "[CIS 5.3.3.1.3] even_deny_root включён"
        elif ask_yn pam.even_deny_root "Блокировать и root после неудачных попыток (CIS L2; вход root с консоли тоже будет блокироваться на 60с)?" n; then
            result_fail "[CIS 5.3.3.1.3] even_deny_root не включён"; add_fix "even_deny_root" "password"
        fi
    fi

    v="$(pwq_value minlen)"
    if is_num "$v" && (( v >= MIN_PASS_LEN )); then result_pass "[CIS 5.3.3.2.2] minlen = $v"
    else result_fail "[CIS 5.3.3.2.2] minlen = ${v:-не задан} (нужно ≥ ${MIN_PASS_LEN})"; add_fix "minlen" "password"; fi
    local key label reqvar
    for key in ucredit:ЗАГЛАВНЫЕ:REQUIRE_UPPERCASE lcredit:строчные:REQUIRE_LOWERCASE dcredit:цифры:REQUIRE_DIGITS ocredit:спецсимволы:REQUIRE_SPECIAL; do
        IFS=: read -r key label reqvar <<< "$key"
        [[ "${!reqvar}" == "1" ]] || continue
        v="$(pwq_value "$key")"
        if is_num "$v" && (( v < 0 )); then result_pass "[CIS 5.3.3.2.3] ${label}: ${key}=${v}"
        else result_fail "[CIS 5.3.3.2.3] ${label} не требуются (${key}=${v:-0})"; add_fix "$key" "password"; fi
    done
    v="$(pwq_value difok)"
    if is_num "$v" && (( v >= 2 )); then result_pass "[CIS 5.3.3.2.1] difok = $v"
    else result_fail "[CIS 5.3.3.2.1] difok = ${v:-1 (по умолчанию)} (нужно ≥ 2)"; add_fix "difok" "password"; fi
    v="$(pwq_value maxrepeat)"
    if is_num "$v" && (( v > 0 && v <= 3 )); then result_pass "[CIS 5.3.3.2.4] maxrepeat = $v"
    else result_fail "[CIS 5.3.3.2.4] maxrepeat = ${v:-0} (нужно 1..3)"; add_fix "maxrepeat" "password"; fi
    v="$(pwq_value maxsequence)"
    if is_num "$v" && (( v > 0 && v <= 3 )); then result_pass "[CIS 5.3.3.2.5] maxsequence = $v"
    else result_fail "[CIS 5.3.3.2.5] maxsequence = ${v:-0} (нужно 1..3)"; add_fix "maxsequence" "password"; fi
    v="$(pwq_value dictcheck)"
    if [[ "$v" != "0" ]]; then result_pass "[CIS 5.3.3.2.6] dictcheck включён"
    else result_fail "[CIS 5.3.3.2.6] dictcheck=0"; add_fix "dictcheck" "password"; fi
    if grep -Eqs '^[[:space:]]*enforce_for_root' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf \
       || pam_has 'pam_pwquality\.so.*enforce_for_root'; then
        result_pass "[CIS 5.3.3.2.7] Политика сложности применяется и к root"
    else
        result_fail "[CIS 5.3.3.2.7] enforce_for_root для pwquality не задан"; add_fix "enforce_for_root" "password"
    fi
    v="$(grep -hsoE 'remember=[0-9]+' "${PAM_LIST[@]}" | tail -1 | cut -d= -f2)"
    [[ -z "$v" ]] && v="$(sys_kv /etc/security/pwhistory.conf remember)"
    if is_num "$v" && (( v >= PASS_HISTORY )); then result_pass "[CIS 5.3.3.3.1] История паролей: remember = $v"
    else result_fail "[CIS 5.3.3.3.1] remember = ${v:-не задан} (нужно ≥ ${PASS_HISTORY})"; add_fix "remember" "password"; fi

    if [[ -f /etc/pam.d/su ]]; then
        if grep -Eqs '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*use_uid' /etc/pam.d/su; then
            result_pass "[CIS 5.2.7] su ограничен через pam_wheel"
        elif ask_yn pam.su_wheel "Ограничить su пустой группой sugroup (CIS 5.2.7)? Root и sudo продолжат работать, «su -» для остальных — нет" y; then
            result_fail "[CIS 5.2.7] su доступен всем пользователям"; add_fix "pam_wheel" "password"
        fi
    fi

    echo ""
    result_info "${BOLD}5.4.1 Параметры паролей (login.defs, useradd):${RESET}"
    v="$(sys_kv /etc/login.defs PASS_MAX_DAYS)"
    if is_num "$v" && (( v > 0 && v <= PASS_MAX_AGE )); then result_pass "[CIS 5.4.1.1] PASS_MAX_DAYS = $v"
    else result_fail "[CIS 5.4.1.1] PASS_MAX_DAYS = ${v:-не задан} (нужно ≤ ${PASS_MAX_AGE})"; add_fix "PASS_MAX_DAYS" "password"; fi
    v="$(sys_kv /etc/login.defs PASS_MIN_DAYS)"
    if is_num "$v" && (( v >= PASS_MIN_AGE )); then result_pass "[CIS 5.4.1.2] PASS_MIN_DAYS = $v"
    else result_fail "[CIS 5.4.1.2] PASS_MIN_DAYS = ${v:-не задан} (нужно ≥ ${PASS_MIN_AGE})"; add_fix "PASS_MIN_DAYS" "password"; fi
    v="$(sys_kv /etc/login.defs PASS_WARN_AGE)"
    if is_num "$v" && (( v >= PASS_WARN_AGE )); then result_pass "[CIS 5.4.1.3] PASS_WARN_AGE = $v"
    else result_fail "[CIS 5.4.1.3] PASS_WARN_AGE = ${v:-не задан} (нужно ≥ ${PASS_WARN_AGE})"; add_fix "PASS_WARN_AGE" "password"; fi
    v="$(conf_get /etc/login.defs ENCRYPT_METHOD)"
    if [[ "${v^^}" =~ ^(SHA512|YESCRYPT)$ ]]; then result_pass "[CIS 5.4.1.4] ENCRYPT_METHOD = $v"
    else result_fail "[CIS 5.4.1.4] ENCRYPT_METHOD = ${v:-не задан} (нужно SHA512 или YESCRYPT)"; add_fix "ENCRYPT_METHOD" "password"; fi
    v="$(useradd -D 2>/dev/null | awk -F= '/^INACTIVE/{print $2}')"
    if is_num "$v" && (( v >= 0 && v <= PASS_INACTIVE )); then result_pass "[CIS 5.4.1.5] useradd INACTIVE = $v"
    else result_fail "[CIS 5.4.1.5] useradd INACTIVE = ${v:--1} (нужно 0..${PASS_INACTIVE})"; add_fix "INACTIVE" "password"; fi
    local u max mn inact bad=()
    if [[ -r /etc/shadow ]]; then
        while IFS=: read -r u _ _ mn max _ inact _; do
            getent passwd "$u" 2>/dev/null | awk -F: -v min="$UID_MIN" '$3>=min && $7 !~ /(nologin|false)$/ {f=1} END{exit !f}' || continue
            if ! is_num "$max" || (( max > PASS_MAX_AGE )) || ! is_num "$mn" || (( mn < PASS_MIN_AGE )) || ! is_num "$inact" || (( inact > PASS_INACTIVE )); then
                bad+=("$u")
            fi
        done < /etc/shadow
        if (( ${#bad[@]} )); then
            result_fail "[CIS 5.4.1.x] Пользователи с параметрами старения пароля вне политики: ${bad[*]}"; add_fix "chage" "password"
        else
            result_pass "[CIS 5.4.1.x] Старение паролей пользователей соответствует политике"
        fi
    fi
    local um; um="$(conf_get /etc/login.defs UMASK)"
    if [[ "$um" =~ ^0?[0-7]{2,3}$ ]] && (( (8#${um} & 8#027) == 8#027 )); then result_pass "[CIS 5.4.3.3] UMASK в login.defs = $um"
    else result_fail "[CIS 5.4.3.3] UMASK в login.defs = ${um:-не задан} (нужно 027 или строже)"; add_fix "UMASK" "password"; fi

    echo ""
    result_info "${BOLD}5.4.2 Системные и привилегированные учётные записи:${RESET}"
    local uid0; uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')"
    if [[ "${uid0% }" == "root" ]]; then result_pass "[CIS 5.4.2.1] UID 0 только у root"
    else result_fail "[CIS 5.4.2.1] UID 0 у нескольких записей: ${uid0}"; fi
    local gid0; gid0="$(awk -F: '$4==0 && $1!~/^(root|sync|shutdown|halt|operator)$/ {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')"
    if [[ -z "$gid0" ]]; then result_pass "[CIS 5.4.2.2] Основная группа GID 0 только у root"
    else result_fail "[CIS 5.4.2.2] GID 0 как основная группа у: ${gid0}"; fi
    if awk -F: '$1=="root" && $4!=0 {f=1} END{exit !f}' /etc/passwd 2>/dev/null; then
        result_fail "[CIS 5.4.2.3] Основная группа root — не GID 0"
        add_fix "[CIS 5.4.2.3] usermod -g 0 root" "simple" "usermod -g 0 root" "/etc/passwd"
    fi
    if awk -F: '$2!="x" {f=1} END{exit !f}' /etc/passwd 2>/dev/null; then
        result_fail "[CIS 7.2.1] В /etc/passwd есть нетеневые пароли"
        add_fix "[CIS 7.2.1] pwconv (перенести пароли в /etc/shadow)" "simple" "pwconv" "/etc/passwd /etc/shadow"
    else
        result_pass "[CIS 7.2.1] Все пароли в /etc/shadow"
    fi
    if [[ -r /etc/shadow ]]; then
        local empty; empty="$(awk -F: '$2=="" {print $1}' /etc/shadow | tr '\n' ' ')"
        if [[ -n "$empty" ]]; then
            result_fail "[CIS 7.2.2] Учётные записи с пустым паролем: ${empty}"
            add_fix "[CIS 7.2.2] Заблокировать учётные записи без пароля: ${empty}" "simple" "lock_accounts ${empty}"
        else
            result_pass "[CIS 7.2.2] Учётных записей с пустым паролем нет"
        fi
    fi
    local sys_shell=()
    mapfile -t sys_shell < <(awk -F: -v min="$UID_MIN" '$3<min && $1!~/^(root|sync|shutdown|halt)$/ && $7!~/(nologin|false)$/ && $7!="" {print $1}' /etc/passwd 2>/dev/null)
    if (( ${#sys_shell[@]} )); then
        result_fail "[CIS 5.4.2.7] Системные учётные записи с интерактивным shell: ${sys_shell[*]}"
        if ask_yn acc.sys_nologin "Назначить им nologin и заблокировать (${sys_shell[*]})? Проверьте, что среди них нет сервисов, входящих по SSH (git, backup)" y; then
            add_fix "[CIS 5.4.2.7-8] nologin + блокировка: ${sys_shell[*]}" "simple" "set_nologin ${sys_shell[*]}"
        fi
    else
        result_pass "[CIS 5.4.2.7] У системных учётных записей нет интерактивного shell"
    fi
    if [[ "$OS_FAMILY" == "debian" ]] && getent group shadow >/dev/null 2>&1; then
        local sm; sm="$(getent group shadow 2>/dev/null | cut -d: -f4)"
        if [[ -z "$sm" ]]; then result_pass "[CIS 7.2.x] Группа shadow пуста"
        else result_fail "[CIS 7.2.x] В группе shadow есть пользователи: ${sm}"; fi
    fi
    # PATH login-shell root (без sudo — он мог бы спросить пароль)
    local rp=""
    # shellcheck disable=SC2016
    [[ $EUID -eq 0 ]] && rp="$(env -i HOME=/root TERM=dumb bash -lc 'echo "$PATH"' 2>/dev/null | tail -1)"
    [[ -z "$rp" ]] && rp="$PATH"
    if [[ "$rp" =~ (^|:)\.?(:|$) ]]; then
        result_fail "[CIS 5.4.2.5] PATH root содержит пустой элемент или «.»: ${rp}"
    else
        result_pass "[CIS 5.4.2.5] PATH root без «.» и пустых элементов"
    fi

    echo ""
    result_info "${BOLD}5.4.3 Окружение пользователей:${RESET}"
    local tm_file="" tm_val="" ff
    for ff in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/*.sh; do
        [[ -f "$ff" ]] || continue
        v="$(grep -E '^[[:space:]]*(export[[:space:]]+)?(readonly[[:space:]]+)?TMOUT[[:space:]]*=' "$ff" 2>/dev/null | tail -1 | sed -E 's/.*TMOUT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')"
        is_num "$v" && { tm_val="$v"; tm_file="$ff"; }
    done
    local tm_ro=0
    grep -Eqs '^[[:space:]]*readonly[[:space:]]+TMOUT' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/*.sh && tm_ro=1
    if is_num "$tm_val" && (( tm_val > 0 && tm_val <= SHELL_TIMEOUT && tm_ro == 1 )); then
        result_pass "[CIS 5.4.3.2] TMOUT=${tm_val} (readonly) в ${tm_file}"
    else
        result_fail "[CIS 5.4.3.2] TMOUT ${tm_val:+=$tm_val }не задан как readonly ≤ ${SHELL_TIMEOUT}"
        add_fix "[CIS 5.4.3.2] TMOUT=${SHELL_TIMEOUT} (readonly) в /etc/profile.d/cis-tmout.sh" "simple" \
            "write_file /etc/profile.d/cis-tmout.sh 644 $(q "# Создан linux_cis_hardening.sh (CIS 5.4.3.2)
if ! readonly -p 2>/dev/null | grep -q ' TMOUT='; then
    TMOUT=${SHELL_TIMEOUT}
    readonly TMOUT
    export TMOUT
fi")"
    fi
    # umask XYZ: у группы должен быть снят бит записи (2,3,6,7), у прочих — всё (7)
    if grep -Eqs '^[[:space:]]*umask[[:space:]]+0?[0-7]?[2367]7([[:space:]]|$)' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/*.sh; then
        result_pass "[CIS 5.4.3.3] umask 027 (или строже) в профилях shell"
    else
        result_fail "[CIS 5.4.3.3] umask по умолчанию для shell шире 027"
        add_fix "[CIS 5.4.3.3] umask 027 в /etc/profile.d/cis-umask.sh" "simple" \
            "write_file /etc/profile.d/cis-umask.sh 644 $(q $'# Создан linux_cis_hardening.sh (CIS 5.4.3.3)\numask 027')"
    fi
    if grep -qsx '/usr/bin/nologin\|/usr/sbin/nologin\|/sbin/nologin\|/bin/nologin' /etc/shells; then
        result_fail "[CIS 5.4.3.1] nologin перечислен в /etc/shells"
        add_fix "[CIS 5.4.3.1] Убрать nologin из /etc/shells" "simple" "sed -i '/nologin\$/d' /etc/shells" "/etc/shells"
    else
        result_pass "[CIS 5.4.3.1] nologin не числится допустимым shell"
    fi
}

# ── 6.x Логирование и аудит ─────────────────────────────────────────────────
cis_logging() {
    section "6.x ЖУРНАЛИРОВАНИЕ, AUDITD, AIDE"

    result_info "${BOLD}6.1 journald / rsyslog:${RESET}"
    local rs_active=0 jcat storage compress fwd
    systemctl is-active --quiet rsyslog 2>/dev/null && rs_active=1
    jcat="$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null || cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null)"
    storage="$(grep -E '^[[:space:]]*Storage=' <<< "$jcat" | tail -1 | cut -d= -f2)"
    compress="$(grep -E '^[[:space:]]*Compress=' <<< "$jcat" | tail -1 | cut -d= -f2)"
    fwd="$(grep -E '^[[:space:]]*ForwardToSyslog=' <<< "$jcat" | tail -1 | cut -d= -f2)"
    local jneed=0 want_fwd="no"
    (( rs_active )) && want_fwd="yes"
    if [[ "${storage,,}" == "persistent" ]]; then result_pass "[CIS 6.1.1.x] journald Storage=persistent"
    else result_fail "[CIS 6.1.1.x] journald Storage=${storage:-auto} (нужно persistent)"; jneed=1; fi
    if [[ "${compress,,}" != "no" ]]; then result_pass "[CIS 6.1.1.x] journald сжимает журналы"
    else result_fail "[CIS 6.1.1.x] journald Compress=no"; jneed=1; fi
    if (( rs_active )) && [[ "${fwd,,}" != "yes" ]]; then
        result_fail "[CIS 6.1.1.x] rsyslog активен, но ForwardToSyslog=${fwd:-no}"; jneed=1
    fi
    (( jneed )) && add_fix "[CIS 6.1.1.x] journald: Storage=persistent, Compress=yes, ForwardToSyslog=${want_fwd}" "simple" \
        "journald_apply ${want_fwd}"

    if (( rs_active )); then
        result_pass "[CIS 6.1.3.1] rsyslog работает"
        local remote_host="${ANS[log.remote]:-}" rneed=0
        # shellcheck disable=SC2016  # $FileCreateMode — директива rsyslog
        if grep -rqsE '^[[:space:]]*\$FileCreateMode[[:space:]]+0[0-6][0-4]0' /etc/rsyslog.conf /etc/rsyslog.d/; then
            result_pass "[CIS 6.1.3.4] rsyslog создаёт файлы с правами ≤0640"
        else
            result_fail "[CIS 6.1.3.4] \$FileCreateMode не задан (≤0640)"; rneed=1
        fi
        if [[ -n "$remote_host" ]]; then
            if grep -rqsE "target=\"${remote_host%:*}\"|@@?${remote_host%:*}" /etc/rsyslog.conf /etc/rsyslog.d/; then
                result_pass "[CIS 6.1.3.6] Логи отправляются на ${remote_host}"
            else
                result_fail "[CIS 6.1.3.6] Логи не отправляются на ${remote_host}"; rneed=1
            fi
        else
            result_warn "[CIS 6.1.3.6] Удалённый сбор логов не настроен (по ответу)"
        fi
        # shellcheck disable=SC2016
        if grep -rqsE '^[[:space:]]*(\$ModLoad|module\(load=")[[:space:]]*(imtcp|imudp)' /etc/rsyslog.conf /etc/rsyslog.d/; then
            result_warn "[CIS 6.1.3.7] rsyslog принимает логи из сети — нужно только на лог-сервере"
        fi
        (( rneed )) && add_fix "[CIS 6.1.3.x] rsyslog: FileCreateMode 0640${remote_host:+, пересылка на $remote_host}" "simple" \
            "rsyslog_apply $(q "$remote_host")"
    elif unit_exists rsyslog.service; then
        result_fail "[CIS 6.1.3.1] rsyslog установлен, но не запущен"
        add_fix "[CIS 6.1.3.1] Включить rsyslog" "simple" "svc_enable rsyslog.service"
    else
        result_info "[CIS 6.1.2] rsyslog не установлен — журналы ведёт только journald"
    fi
    local bad_logs; bad_logs="$(varlog_bad_files | grep -c . || true)"
    if (( bad_logs == 0 )); then
        result_pass "[CIS 6.1.4.1] Права на файлы в /var/log в норме"
    else
        result_fail "[CIS 6.1.4.1] Файлов в /var/log с лишними правами: ${bad_logs}"
        add_fix "[CIS 6.1.4.1] Срезать лишние права у ${bad_logs} файлов в /var/log" "simple" "fix_varlog_perms"
    fi
    if [[ -f /etc/logrotate.conf ]]; then result_pass "[CIS 6.1.x] logrotate настроен"
    else result_warn "[CIS 6.1.x] logrotate не найден"; fi

    echo ""
    result_info "${BOLD}6.2 auditd:${RESET}"
    if ! command -v auditctl &>/dev/null; then
        if lvl 2 || ask_yn log.auditd "auditd не установлен. Установить (CIS 6.2, L2; на L1 — рекомендуется)?" y; then
            result_fail "[CIS 6.2.1.1] auditd не установлен"
            add_fix "[CIS 6.2.1.1-2] Установить и включить auditd" "simple" "auditd_install"
            add_fix "[CIS 6.2.3.x] Правила аудита CIS в /etc/audit/rules.d/50-cis-hardening.rules" "simple" \
                "audit_rules_install ${ANS[log.audit_immutable]:-n}"
            add_fix "[CIS 6.2.2.x] auditd.conf: max_log_file=${AUDIT_MAX_LOG_MB}, keep_logs, email" "simple" \
                "auditd_conf_apply ${ANS[log.audit_strict]:-n}"
        else
            result_warn "[CIS 6.2] auditd не установлен (по ответу)"
        fi
    else
        if systemctl is-enabled --quiet auditd 2>/dev/null && systemctl is-active --quiet auditd 2>/dev/null; then
            result_pass "[CIS 6.2.1.2] auditd включён и работает"
        else
            result_fail "[CIS 6.2.1.2] auditd не включён"
            add_fix "[CIS 6.2.1.2] Включить auditd" "simple" "svc_enable auditd.service"
        fi
        local cmdl; cmdl="$(cat /proc/cmdline 2>/dev/null)"
        local need_args=()
        [[ " $cmdl " == *" audit=1 "* ]] || need_args+=(audit=1)
        if ! [[ "$cmdl" =~ audit_backlog_limit=([0-9]+) ]] || (( BASH_REMATCH[1] < 8192 )); then
            need_args+=(audit_backlog_limit=8192)
        fi
        if (( ${#need_args[@]} == 0 )); then
            result_pass "[CIS 6.2.1.3-4] audit=1 audit_backlog_limit≥8192 в параметрах ядра"
        elif grep -qs "audit=1" /etc/default/grub && grep -qs "audit_backlog_limit" /etc/default/grub; then
            result_warn "[CIS 6.2.1.3-4] Параметры audit заданы в GRUB, но вступят в силу после перезагрузки"
        elif [[ -f /etc/default/grub ]]; then
            result_fail "[CIS 6.2.1.3-4] Нет параметров ядра: ${need_args[*]}"
            add_fix "[CIS 6.2.1.3-4] Добавить ${need_args[*]} в параметры ядра (после перезагрузки)" "simple" \
                "grub_add_args ${need_args[*]}"
        fi

        # Правила: каждая группа CIS должна присутствовать в загруженных правилах
        local loaded keys k missing=()
        loaded="$(auditctl -l 2>/dev/null)"
        keys=(scope user_emulation time-change system-locale mounts delete access perm_mod kernel_modules identity session logins MAC-policy privileged)
        [[ -x /usr/bin/chcon || -x /usr/bin/setfacl ]] && keys+=(perm_chng)
        [[ -x /usr/sbin/usermod ]] && keys+=(usermod)
        for k in "${keys[@]}"; do grep -q -- "key=${k}\b\|-k ${k}\b" <<< "$loaded" || missing+=("$k"); done
        if (( ${#missing[@]} == 0 )); then
            result_pass "[CIS 6.2.3.x] Загружены все группы правил аудита CIS"
        else
            result_fail "[CIS 6.2.3.x] Нет правил аудита: ${missing[*]}"
            add_fix "[CIS 6.2.3.x] Правила аудита CIS в /etc/audit/rules.d/50-cis-hardening.rules + augenrules --load" "simple" \
                "audit_rules_install ${ANS[log.audit_immutable]:-n}"
        fi
        if lvl 2; then
            if auditctl -s 2>/dev/null | grep -q 'enabled 2'; then
                result_pass "[CIS 6.2.3.20] Конфигурация аудита неизменяема (-e 2)"
            elif [[ "${ANS[log.audit_immutable]:-n}" == "y" ]]; then
                result_fail "[CIS 6.2.3.20] Правила аудита изменяемы (нет -e 2)"
                grep -qs '^-e 2' /etc/audit/rules.d/*.rules || add_fix "[CIS 6.2.3.20] -e 2 в /etc/audit/rules.d/99-finalize.rules (после перезагрузки)" "simple" \
                    "audit_rules_install y"
            fi
        fi

        local c=/etc/audit/auditd.conf
        if [[ -f "$c" ]]; then
            local mlf mla sla aca need_conf=0
            mlf="$(conf_get "$c" max_log_file)"; mla="$(conf_get "$c" max_log_file_action)"
            sla="$(conf_get "$c" space_left_action)"; aca="$(conf_get "$c" admin_space_left_action)"
            if is_num "$mlf"; then result_pass "[CIS 6.2.2.1] max_log_file = ${mlf} МБ"
            else result_fail "[CIS 6.2.2.1] max_log_file не задан"; need_conf=1; fi
            if [[ "${mla,,}" == "keep_logs" ]]; then result_pass "[CIS 6.2.2.2] max_log_file_action = keep_logs"
            else result_fail "[CIS 6.2.2.2] max_log_file_action = ${mla:-?} (журналы аудита удаляются)"; need_conf=1; fi
            if [[ "${sla,,}" =~ ^(email|exec|single|halt)$ ]]; then result_pass "[CIS 6.2.2.4] space_left_action = ${sla}"
            else result_fail "[CIS 6.2.2.4] space_left_action = ${sla:-?} (никто не узнает о нехватке места)"; need_conf=1; fi
            if lvl 2; then
                if [[ "${aca,,}" =~ ^(single|halt)$ ]]; then
                    result_pass "[CIS 6.2.2.3] admin_space_left_action = ${aca}"
                elif ask_yn log.audit_strict "При переполнении раздела аудита переводить систему в single/halt (CIS L2)? Удалённый сервер станет недоступен до вмешательства" n; then
                    result_fail "[CIS 6.2.2.3] admin_space_left_action = ${aca:-?}"; need_conf=1
                else
                    result_warn "[CIS 6.2.2.3] admin_space_left_action = ${aca:-?} (оставлено по ответу)"
                fi
            fi
            (( need_conf )) && add_fix "[CIS 6.2.2.x] auditd.conf: max_log_file=${AUDIT_MAX_LOG_MB}, keep_logs, space_left_action=email" "simple" \
                "auditd_conf_apply ${ANS[log.audit_strict]:-n}"
            check_perm "6.2.4.x" "$c" 640 root root
            local ld; ld="$(conf_get "$c" log_file)"; ld="$(dirname "${ld:-/var/log/audit/audit.log}")"
            check_perm "6.2.4.4" "$ld" 750 root root
            local lf
            for lf in "$ld"/audit.log*; do [[ -f "$lf" ]] && check_perm "6.2.4.1" "$lf" 640 root "root|adm"; done
        fi
        local tool
        for tool in auditctl aureport ausearch autrace auditd augenrules; do
            for f in /sbin/$tool /usr/sbin/$tool; do [[ -f "$f" && ! -L "$f" ]] && { check_perm "6.2.4.8-10" "$f" 755 root root; break; }; done
        done
    fi

    echo ""
    result_info "${BOLD}6.3 Контроль целостности (AIDE):${RESET}"
    if command -v aide &>/dev/null; then
        result_pass "[CIS 6.3.1] AIDE установлен"
        if [[ -n "$(find /var/lib/aide -maxdepth 1 -name 'aide.db*' ! -name '*.new*' 2>/dev/null)" ]]; then
            result_pass "[CIS 6.3.1] База AIDE инициализирована"
        else
            result_fail "[CIS 6.3.1] База AIDE не инициализирована"
            add_fix "[CIS 6.3.1] Инициализировать AIDE и включить ежедневную проверку (несколько минут)" "simple" "aide_setup"
        fi
        if systemctl is-enabled --quiet dailyaidecheck.timer 2>/dev/null || systemctl is-enabled --quiet aidecheck.timer 2>/dev/null \
           || grep -rqs 'aide' /etc/cron.d /etc/crontab /etc/cron.daily /var/spool/cron 2>/dev/null; then
            result_pass "[CIS 6.3.2] Регулярная проверка AIDE запланирована"
        else
            result_fail "[CIS 6.3.2] Регулярная проверка AIDE не запланирована"
            add_fix "[CIS 6.3.2] Ежедневная проверка AIDE" "simple" \
                "write_file /etc/cron.d/cis-aide 644 $(q "0 5 * * * root $(command -v aide) --check")"
        fi
    elif ask_yn log.aide "Установить AIDE (контроль целостности файлов, CIS 6.3)? Первичная инициализация базы — несколько минут" y; then
        result_fail "[CIS 6.3.1] AIDE не установлен"
        add_fix "[CIS 6.3.1-3] Установить AIDE, инициализировать базу, ежедневная проверка" "simple" "aide_setup"
    else
        result_warn "[CIS 6.3.1] AIDE не установлен (по ответу)"
    fi
}

# ── 7.x Обслуживание системы ────────────────────────────────────────────────
cis_maintenance() {
    section "7.x ОБСЛУЖИВАНИЕ: ПРАВА НА ФАЙЛЫ, ПОЛЬЗОВАТЕЛИ И ГРУППЫ"

    result_info "${BOLD}7.1 Системные файлы:${RESET}"
    local shadow_max=640 shadow_grp="root|shadow"
    [[ "$OS_FAMILY" == "rhel" ]] && { shadow_max=000; shadow_grp="root"; }
    local f
    for f in /etc/passwd /etc/passwd- /etc/group /etc/group-; do check_perm "7.1.1-4" "$f" 644 root root; done
    for f in /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-; do check_perm "7.1.5-8" "$f" "$shadow_max" root "$shadow_grp"; done
    check_perm "7.1.9" /etc/shells 644 root root
    check_perm "7.1.10" /etc/security/opasswd 600 root root
    check_perm "7.1.x" /etc/sudoers 440 root root

    fs_scan
    local ww nu ng su
    ww="$(fs_list WW | grep -c . || true)"
    if (( ww == 0 )); then
        result_pass "[CIS 7.1.11] World-writable файлов нет"
    else
        result_fail "[CIS 7.1.11] World-writable файлов: ${ww}"
        fs_list WW | head -10 | while read -r f; do log "    ${DIM}${f}${RESET}"; done
        if ask_yn maint.ww "Снять право записи для «всех» с ${ww} файлов (o-w)?" y "Обычно это ошибки установки; на общих каталогах приложений проверьте список выше"; then
            add_fix "[CIS 7.1.11] chmod o-w для ${ww} world-writable файлов" "simple" "fix_world_writable"
        fi
    fi
    nu="$(fs_list NU | grep -c . || true)"; ng="$(fs_list NG | grep -c . || true)"
    if (( nu + ng == 0 )); then
        result_pass "[CIS 7.1.12] Файлов без владельца/группы нет"
    else
        result_fail "[CIS 7.1.12] Файлов без владельца: ${nu}, без группы: ${ng} (назначьте вручную)"
        { fs_list NU; fs_list NG; } | head -10 | while read -r f; do log "    ${DIM}${f}${RESET}"; done
    fi
    su="$(fs_list SU | grep -Evc '^(/usr/bin|/usr/sbin|/bin|/sbin|/usr/lib|/usr/libexec|/usr/lib64)/' || true)"
    if (( su == 0 )); then
        result_pass "[CIS 7.1.13] Нестандартных SUID/SGID-файлов нет"
    else
        result_warn "[CIS 7.1.13] SUID/SGID вне системных каталогов: ${su} (проверьте вручную)"
        fs_list SU | grep -Ev '^(/usr/bin|/usr/sbin|/bin|/sbin|/usr/lib|/usr/libexec|/usr/lib64)/' | head -10 | while read -r f; do log "    ${DIM}${f}${RESET}"; done
    fi

    echo ""
    result_info "${BOLD}7.2 Пользователи и группы:${RESET}"
    local d spec id what
    # "CIS-пункт|файл|поле|что"
    for spec in "7.2.5|/etc/passwd|3|UID" "7.2.6|/etc/group|3|GID" "7.2.7|/etc/passwd|1|имена пользователей" "7.2.8|/etc/group|1|имена групп"; do
        IFS='|' read -r id f d what <<< "$spec"
        d="$(awk -F: -v c="$d" '{print $c}' "$f" 2>/dev/null | sort | uniq -d | tr '\n' ' ')"
        if [[ -z "$d" ]]; then result_pass "[CIS $id] Дубликатов нет: ${what}"
        else result_fail "[CIS $id] Дублируются ${what}: ${d}"; fi
    done
    local missing_g
    missing_g="$(awk -F: 'NR==FNR {g[$3]=1; next} !($4 in g) {print $1}' /etc/group /etc/passwd 2>/dev/null | tr '\n' ' ')"
    if [[ -z "$missing_g" ]]; then result_pass "[CIS 7.2.3] Все основные группы существуют"
    else result_fail "[CIS 7.2.3] Несуществующие основные группы у: ${missing_g}"; fi

    local u h bad_home=() bad_dot=() hm
    while IFS=: read -r u h; do
        [[ -d "$h" ]] || { result_fail "[CIS 7.2.9] У ${u} нет домашнего каталога ${h}"; continue; }
        hm="$(stat -c '%a %U' "$h" 2>/dev/null)"
        if [[ "${hm#* }" != "$u" ]] || (( (8#${hm%% *} & 8#027) != 0 )); then bad_home+=("$u:$hm"); fi
        for f in "$h"/.[!.]*; do
            [[ -f "$f" && ! -L "$f" ]] || continue
            case "${f##*/}" in
                .netrc|.rhosts|.forward|.shosts) bad_dot+=("$f") ;;
                .bash_history) (( (8#$(stat -c '%a' "$f") & 8#177) != 0 )) && bad_dot+=("$f") ;;
                *) (( (8#$(stat -c '%a' "$f") & 8#022) != 0 )) && bad_dot+=("$f") ;;
            esac
        done
    done < <(login_users_homes)
    if (( ${#bad_home[@]} )); then
        result_fail "[CIS 7.2.9] Домашние каталоги с неверным владельцем или правами шире 750: ${bad_home[*]}"
        add_fix "[CIS 7.2.9] Домашние каталоги: владелец — пользователь, права ≤750" "simple" "fix_home_dirs"
    else
        result_pass "[CIS 7.2.9] Домашние каталоги в порядке"
    fi
    if (( ${#bad_dot[@]} )); then
        result_fail "[CIS 7.2.10] Опасные dot-файлы (.netrc/.rhosts/.forward или запись для группы/всех): ${#bad_dot[@]}"
        printf '%s\n' "${bad_dot[@]}" | head -10 | while read -r f; do log "    ${DIM}${f}${RESET}"; done
        if ask_yn maint.dotfiles "Удалить .netrc/.rhosts/.forward/.shosts (с бэкапом) и срезать права у остальных?" y; then
            add_fix "[CIS 7.2.10] Исправить dot-файлы пользователей" "simple" "fix_dotfiles"
        fi
    else
        result_pass "[CIS 7.2.10] Dot-файлы пользователей в порядке"
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
#  ОПРОСНИК
# ═════════════════════════════════════════════════════════════════════════════

seed_defaults_from_system() {
    local v
    v="$(sys_kv /etc/security/pwquality.conf minlen)"; [[ -n "$v" ]] && MIN_PASS_LEN="$v"
    v="$(sys_kv /etc/login.defs PASS_MAX_DAYS)"; [[ -n "$v" ]] && PASS_MAX_AGE="$v"
    v="$(sys_kv /etc/login.defs PASS_MIN_DAYS)"; [[ -n "$v" ]] && PASS_MIN_AGE="$v"
    v="$(sys_kv /etc/login.defs PASS_WARN_AGE)"; [[ -n "$v" ]] && PASS_WARN_AGE="$v"
    v="$(sys_kv /etc/security/pwhistory.conf remember)"; [[ -n "$v" ]] && PASS_HISTORY="$v"
    [[ -z "$v" ]] && { v="$(grep -oE 'remember=[0-9]+' /etc/pam.d/common-password 2>/dev/null | tail -1 | grep -oE '[0-9]+')"; [[ -n "$v" ]] && PASS_HISTORY="$v"; }
    v="$(useradd -D 2>/dev/null | awk -F= '/^INACTIVE/{print $2}')"; is_num "$v" && (( v >= 0 )) && PASS_INACTIVE="$v"
    v="$(sys_kv /etc/security/faillock.conf deny)"; [[ -n "$v" ]] && FAIL_DENY="$v"
    v="$(sys_kv /etc/security/faillock.conf unlock_time)"
    if [[ -n "$v" ]] && (( v > 0 )); then
        FAIL_UNLOCK_MINUTES=$(( v / 60 ))
        (( FAIL_UNLOCK_MINUTES < 1 )) && FAIL_UNLOCK_MINUTES=1
    fi
    v="$(sys_kv /etc/login.defs UID_MIN)"; [[ -n "$v" ]] && UID_MIN="$v"
    v="$(grep -hsE '^[[:space:]]*(export[[:space:]]+|readonly[[:space:]]+)*TMOUT=[0-9]+' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/*.sh | tail -1 | grep -oE '[0-9]+$')"
    is_num "$v" && (( v > 0 )) && SHELL_TIMEOUT="$v"
    if build_sshd_effective 2>/dev/null; then
        v="$(get_ssh_param MaxAuthTries)"; is_num "$v" && MAX_AUTH_TRIES="$v"
        local i c
        i="$(get_ssh_param ClientAliveInterval)"; c="$(get_ssh_param ClientAliveCountMax)"
        { is_num "$c" && (( c > 0 )); } || c=1
        if is_num "$i" && (( i > 0 )); then SSH_IDLE_TIMEOUT=$(( i * c )); fi
    fi
    v="$(conf_get /etc/audit/auditd.conf max_log_file)"; is_num "$v" && AUDIT_MAX_LOG_MB="$v"
    return 0
}

# Пользователи с ключами SSH — кандидаты для AllowUsers
users_with_keys() {
    local u h
    while IFS=: read -r u h; do
        [[ -s "$h/.ssh/authorized_keys" || -s "$h/.ssh/authorized_keys2" ]] && echo "$u"
    done < <(login_users_homes)
}

BANNER_TEXT="Authorized users only. All activity may be monitored and reported."
WIZARD_DONE=0

interactive_setup() {
    ANS=()
    seed_defaults_from_system
    echo ""
    echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${MAGENTA}║   Опросник: профиль сервера и параметры харденинга   ║${RESET}"
    echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${DIM}Enter = значение по умолчанию. Числовые дефолты — ТЕКУЩИЕ настройки системы,${RESET}"
    echo -e "${DIM}рекомендация CIS показана рядом. Ответы сохраняются: p в меню или --save-profile.${RESET}"
    echo ""

    echo -e "${WHITE}${BOLD}── Профиль CIS ─────────────────────────────────${RESET}"
    echo -e "${DIM}  Level 1 — базовая защита без заметного влияния на работу.${RESET}"
    echo -e "${DIM}  Level 2 — глубокая защита (auditd -e 2, enforce всех профилей MAC, отключение редких протоколов).${RESET}"
    read_int "Уровень профиля CIS (1 или 2)" "$CIS_LEVEL" 1 2; CIS_LEVEL="$INT_RESULT"

    echo ""
    echo -e "${WHITE}${BOLD}── Роль сервера ────────────────────────────────${RESET}"
    local d_router=n d_ipv6=n d_gui=n
    { command -v docker &>/dev/null || command -v kubelet &>/dev/null || command -v podman &>/dev/null \
      || [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]]; } && d_router=y
    ip -6 addr show scope global 2>/dev/null | grep -q inet6 && d_ipv6=y
    systemctl is-active --quiet display-manager 2>/dev/null && d_gui=y
    ask_yn role.router "Сервер маршрутизирует трафик (Docker/Kubernetes/VPN/шлюз — нужен ip_forward)?" "$d_router"
    ask_yn role.ipv6 "Используется ли IPv6?" "$d_ipv6"
    ask_yn role.usb "Подключаются ли к серверу USB-накопители?" n
    ask_yn role.gui "Нужен ли графический интерфейс?" "$d_gui"

    echo ""
    echo -e "${WHITE}${BOLD}── Парольная политика ──────────────────────────${RESET}"
    read_cis_int MIN_PASS_LEN "Минимальная длина пароля" 6 128
    read_cis_int PASS_MAX_AGE "Максимальный срок действия пароля (дни)" 1 99999
    read_cis_int PASS_MIN_AGE "Минимальный срок до смены пароля (дни)" 0 30
    read_cis_int PASS_WARN_AGE "Предупреждение до истечения пароля (дни)" 1 30
    read_cis_int PASS_HISTORY "Количество запоминаемых паролей (история)" 0 400
    read_cis_int PASS_INACTIVE "Блокировка через N дней после истечения пароля" 0 365

    echo ""
    echo -e "${WHITE}${BOLD}── Блокировка после неудачных попыток (pam_faillock) ──${RESET}"
    read_cis_int FAIL_DENY "Неудачных попыток до блокировки" 1 20
    read_cis_int FAIL_UNLOCK_MINUTES "Время блокировки (минуты)" 1 1440
    read_int "Минимальный UID обычных пользователей" "$UID_MIN" 100 60000; UID_MIN="$INT_RESULT"

    echo ""
    echo -e "${WHITE}${BOLD}── Сложность пароля ────────────────────────────${RESET}"
    # shellcheck disable=SC2034  # REQUIRE_* читаются косвенно (${!reqvar})
    if confirm "Требовать ЗАГЛАВНЫЕ буквы"; then REQUIRE_UPPERCASE=1; else REQUIRE_UPPERCASE=0; fi
    # shellcheck disable=SC2034
    if confirm "Требовать строчные буквы"; then REQUIRE_LOWERCASE=1; else REQUIRE_LOWERCASE=0; fi
    # shellcheck disable=SC2034
    if confirm "Требовать цифры"; then REQUIRE_DIGITS=1; else REQUIRE_DIGITS=0; fi
    # shellcheck disable=SC2034
    if confirm "Требовать спецсимволы"; then REQUIRE_SPECIAL=1; else REQUIRE_SPECIAL=0; fi

    echo ""
    echo -e "${WHITE}${BOLD}── Таймауты ────────────────────────────────────${RESET}"
    read_cis_int SSH_IDLE_TIMEOUT "Таймаут неотвечающей SSH-сессии (секунды)" 30 3600
    read_cis_int SHELL_TIMEOUT "Таймаут бездействия shell, TMOUT (секунды)" 60 7200

    echo ""
    echo -e "${WHITE}${BOLD}── SSH ─────────────────────────────────────────${RESET}"
    read_cis_int MAX_AUTH_TRIES "Максимум попыток аутентификации SSH" 1 10
    local direct_root=n
    [[ $EUID -eq 0 && -z "${SUDO_USER:-}" && -n "${SSH_CONNECTION:-}" ]] && direct_root=y
    if [[ "$direct_root" == "y" ]]; then
        echo -e "${RED}${BOLD}  ⚠ Вы вошли по SSH напрямую как root. Запрет root-входа отрежет этот способ входа.${RESET}"
        echo -e "${DIM}    Перед запретом убедитесь, что есть пользователь с sudo и рабочим входом.${RESET}"
    fi
    local root_def=y
    [[ "$direct_root" == "y" ]] && root_def=n
    if ask_yn ssh.root_no "Полностью запретить вход root по SSH (PermitRootLogin no)? Иначе — только по ключу" "$root_def"; then
        ANS[ssh.root_login]=no
    else
        ANS[ssh.root_login]=prohibit-password
    fi
    local -a keyed=()
    mapfile -t keyed < <(users_with_keys)
    echo -e "${DIM}  Пользователи с authorized_keys: ${keyed[*]:-нет}${RESET}"
    if [[ " ${keyed[*]} " == *" ${ADMIN_USER} "* ]]; then
        ask_yn ssh.no_password "Запретить вход по паролю — только ключи (у ${ADMIN_USER} ключ есть)?" y
    else
        echo -e "${YELLOW}  У ${ADMIN_USER} нет ~/.ssh/authorized_keys — вход по паролю отключать не предлагаю.${RESET}"
        ANS[ssh.no_password]=n
    fi
    # Кандидаты в AllowUsers: все, у кого есть ключи, + администратор; root —
    # только если ему оставлен вход по ключу
    local -a cand=()
    mapfile -t cand < <(printf '%s\n' ${keyed[@]+"${keyed[@]}"} "$ADMIN_USER" | grep -v '^root$' | sort -u)
    if [[ "${ANS[ssh.root_login]}" != "no" && ( " ${keyed[*]} " == *" root "* || "$ADMIN_USER" == "root" ) ]]; then
        cand+=(root)
    fi
    ask_str ssh.allow_users "Кому разрешён SSH (AllowUsers через пробел; «-» — не ограничивать)" "${cand[*]}" '^[A-Za-z0-9._@*?!-]+( [A-Za-z0-9._@*?!-]+)*$|^$'
    if [[ -n "$STR_RESULT" && " $STR_RESULT " != *" ${ADMIN_USER} "* ]] \
       && { [[ "$ADMIN_USER" != "root" ]] || [[ "${ANS[ssh.root_login]}" != "no" ]]; }; then
        echo -e "${YELLOW}  Добавляю ${ADMIN_USER} в AllowUsers, иначе вы потеряете доступ.${RESET}"
        ANS[ssh.allow_users]="$STR_RESULT $ADMIN_USER"
    fi
    ask_yn ssh.forwarding "Нужны ли SSH-туннели/проброс портов/агента (IDE remote, jump-host)?" n
    local d_gss=n
    systemctl is-active --quiet sssd 2>/dev/null && d_gss=y
    ask_yn ssh.gssapi "Используется вход по Kerberos/GSSAPI (FreeIPA/AD)?" "$d_gss"

    echo ""
    echo -e "${WHITE}${BOLD}── Брандмауэр ──────────────────────────────────${RESET}"
    echo -e "${DIM}  SSH-порты разрешаются всегда. О портах, которые сейчас слушают сеть, спрошу при проверке.${RESET}"
    ask_str fw.extra_ports "Дополнительно открыть входящие порты (например 80/tcp,443/tcp)" "" "$PORTS_RE"

    echo ""
    echo -e "${WHITE}${BOLD}── Журналирование и аудит ──────────────────────${RESET}"
    ask_str log.remote "Удалённый syslog-сервер (host или host:port; «-» — не отправлять)" "" '^[A-Za-z0-9.:_-]*$'
    read_int "Размер одного файла журнала auditd (МБ)" "$AUDIT_MAX_LOG_MB" 1 10240; AUDIT_MAX_LOG_MB="$INT_RESULT"
    if (( CIS_LEVEL >= 2 )); then
        ask_yn log.audit_immutable "Сделать правила аудита неизменяемыми до перезагрузки (-e 2)?" y \
            "После этого любые изменения правил auditd требуют перезагрузки"
    fi

    echo ""
    echo -e "${WHITE}${BOLD}── Баннер входа ────────────────────────────────${RESET}"
    ask_str banner.text "Текст баннера для /etc/issue, /etc/issue.net, /etc/motd" "$BANNER_TEXT" '^[^\\]+$'
    BANNER_TEXT="$STR_RESULT"

    echo ""
    echo -e "${WHITE}${BOLD}── Безопасное применение исправлений ───────────${RESET}"
    echo -e "${DIM}Для password/PAM, SSH, sudo и firewall исправления применяются с бэкапом${RESET}"
    echo -e "${DIM}и окном на подтверждение — иначе автооткат по таймауту.${RESET}"
    read_int "Таймаут окна подтверждения (секунды)" "$CONFIRM_TIMEOUT" 30 900; CONFIRM_TIMEOUT="$INT_RESULT"
    if confirm "Включить предохранитель (авто-откат по таймауту)" y; then DO_ROLLBACK_GUARD=1; else DO_ROLLBACK_GUARD=0; fi

    echo ""
    WIZARD_DONE=1
    echo -e "${GREEN}${BOLD}✔ Параметры сохранены. О найденных сервисах и портах спрошу по ходу проверки.${RESET}"
    sleep 1
}

# Дефолты для --no-interactive: безопасные («ничего не отрезать»)
# Роль сервера по косвенным признакам: Docker/K8s или включённый ip_forward → маршрутизирует
D_ROUTER=n
D_IPV6=n
detect_role_defaults() {
    D_ROUTER=n; D_IPV6=n
    { command -v docker &>/dev/null || command -v kubelet &>/dev/null || [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]]; } && D_ROUTER=y
    ip -6 addr show scope global 2>/dev/null | grep -q inet6 && D_IPV6=y
    return 0
}

noninteractive_defaults() {
    detect_role_defaults
    : "${ANS[role.router]:=$D_ROUTER}" "${ANS[role.ipv6]:=$D_IPV6}" "${ANS[role.usb]:=n}" "${ANS[role.gui]:=n}"
    : "${ANS[ssh.root_login]:=prohibit-password}" "${ANS[ssh.no_password]:=n}" "${ANS[ssh.forwarding]:=y}" "${ANS[ssh.gssapi]:=y}"
    : "${ANS[net.slaac]:=y}"
    [[ -n "${ANS[banner.text]:-}" ]] && BANNER_TEXT="${ANS[banner.text]}"
    return 0
}

# Ответы для аудита «как есть»: строгая трактовка CIS — то, о чём опросник
# не спрашивал, считается ненужным. Ответы пройденного опросника важнее.
audit_defaults() {
    detect_role_defaults
    : "${ANS[role.router]:=$D_ROUTER}" "${ANS[role.ipv6]:=$D_IPV6}" "${ANS[role.usb]:=n}" "${ANS[role.gui]:=n}"
    : "${ANS[ssh.root_login]:=no}" "${ANS[ssh.no_password]:=n}" "${ANS[ssh.forwarding]:=n}" "${ANS[ssh.gssapi]:=n}"
    : "${ANS[net.slaac]:=y}"
    return 0
}

save_profile() {
    local file="$1" v k
    ( umask 077
      {
        echo "# Профиль linux_cis_hardening.sh v${VERSION} — $(hostname 2>/dev/null) $(date '+%F %T')"
        echo "# Использование: sudo ./linux_cis_hardening.sh --profile ${file##*/}"
        for v in "${PROFILE_VARS[@]}"; do printf '%s=%s\n' "$v" "${!v}"; done
        for k in $(printf '%s\n' "${!ANS[@]}" | sort); do printf 'ans.%s=%s\n' "$k" "${ANS[$k]}"; done
      } > "$file" ) || { result_fail "Не удалось записать профиль $file"; return 1; }
    result_pass "Профиль сохранён: $file"
}

# Профиль НЕ исполняется (никакого source): только whitelist ключей и проверка значений
load_profile() {
    local file="$1" line name val n=0 v ok
    [[ -r "$file" ]] || { echo "Профиль не найден: $file"; exit 2; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ "$line" =~ ^ans\.([a-z0-9_.-]+)=(.*)$ ]]; then
            name="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
            # shellcheck disable=SC1003
            case "$val" in *'`'*|*'$'*|*'\'*|*'"'*) echo "Профиль: недопустимые символы в строке: $line"; exit 2 ;; esac
            if [[ "$name" == fw.*_ports && ! "$val" =~ $PORTS_RE ]]; then
                echo "Профиль: некорректный список портов: $line"; exit 2
            fi
            ANS[$name]="$val"; n=$((n+1))
        elif [[ "$line" =~ ^([A-Z_]+)=([0-9]+)$ ]]; then
            name="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"; ok=0
            for v in "${PROFILE_VARS[@]}"; do [[ "$v" == "$name" ]] && ok=1; done
            (( ok )) || { echo "Профиль: неизвестный параметр $name"; exit 2; }
            printf -v "$name" '%s' "$val"; n=$((n+1))
        else
            echo "Профиль: строка не распознана: $line"; exit 2
        fi
    done < "$file"
    (( CIS_LEVEL == 1 || CIS_LEVEL == 2 )) || { echo "Профиль: CIS_LEVEL должен быть 1 или 2"; exit 2; }
    (( CONFIRM_TIMEOUT >= 10 )) || { echo "Профиль: CONFIRM_TIMEOUT должен быть >= 10"; exit 2; }
    [[ -n "${ANS[banner.text]:-}" ]] && BANNER_TEXT="${ANS[banner.text]}"
    echo "Загружено параметров из профиля: $n"
}

# ═════════════════════════════════════════════════════════════════════════════
#  ОТКАТ ИЗ МЕНЮ / CLI
# ═════════════════════════════════════════════════════════════════════════════
list_backups() {
    local d
    for d in /root/security-toolkit-backup-* /var/tmp/security-toolkit-backup-*; do
        [[ -d "$d" && -f "$d/CATEGORY" ]] && echo "$d"
    done
}

rollback_interactive() {
    local dirs=() i choice
    mapfile -t dirs < <(list_backups)
    if (( ${#dirs[@]} == 0 )); then
        result_info "Бэкапов не найдено"
        return
    fi
    echo ""
    for i in "${!dirs[@]}"; do
        printf "  %2d) %s ${DIM}[%s]${RESET}\n" "$((i+1))" "${dirs[i]}" "$(cat "${dirs[i]}/CATEGORY")" >/dev/tty
    done
    read_int "Номер бэкапа для отката (0 — отмена)" 0 0 "${#dirs[@]}"; choice="$INT_RESULT"
    (( choice == 0 )) && return
    rollback_dir "${dirs[choice-1]}"
}

rollback_dir() {
    local d="$1"
    [[ $EUID -eq 0 ]] || { echo "Откат требует root"; return 1; }
    [[ -d "$d" && -f "$d/CATEGORY" && "$(basename "$d")" == security-toolkit-backup-* ]] \
        || { echo "Не похоже на каталог бэкапа: $d"; return 1; }
    if (( HAVE_TTY )) && ! confirm "Откатить изменения из ${d} ($(cat "$d/CATEGORY"))?" n; then
        return 0
    fi
    restore_dir "$d"
}

# ═════════════════════════════════════════════════════════════════════════════
#  ИТОГ, МЕНЮ, MAIN
# ═════════════════════════════════════════════════════════════════════════════

print_summary() {
    local total=$((PASSES + ISSUES)) score=0
    (( total > 0 )) && score=$(( PASSES * 100 / total ))
    section "ИТОГ"
    log "  ${GREEN}${BOLD}PASS: ${PASSES}${RESET}   ${RED}${BOLD}FAIL: ${ISSUES}${RESET}   ${YELLOW}${BOLD}WARN: ${WARNINGS}${RESET}"
    if [[ -n "$LAST_SCORE" && "$REAUDIT" -eq 1 ]]; then
        log "  Соответствие CIS Level ${CIS_LEVEL} (проверенные пункты): ${BOLD}${LAST_SCORE}% → ${score}%${RESET}"
    else
        log "  Соответствие CIS Level ${CIS_LEVEL} (проверенные пункты): ${BOLD}${score}%${RESET}"
    fi
    if (( REAUDIT == 0 )); then
        log "  К исправлению: PAM/пароли — ${PASS_POLICY_ISSUES}, SSH — ${#FIXES_SSH[@]}, sudo — ${#FIXES_SUDO[@]}, firewall — ${#FIXES_FW[@]}, прочее — ${#FIXES[@]}"
    fi
    LAST_SCORE="$score"
}

MENU_CHOICE=""

show_menu() {
    echo "" >/dev/tty
    echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════╗${RESET}" >/dev/tty
    echo -e "${BOLD}${MAGENTA}║        Выберите раздел CIS (профиль: Level ${CIS_LEVEL})               ║${RESET}" >/dev/tty
    echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════╝${RESET}" >/dev/tty
    echo "" >/dev/tty
    echo -e "  ${GREEN}${BOLD}0)${RESET}  Аудит текущих настроек ${DIM}(только посмотреть: без вопросов, ничего не меняет)${RESET}" >/dev/tty
    echo -e "  ${DIM}─────────────────────────────────────────────────────────────${RESET}" >/dev/tty
    echo -e "  ${WHITE}${BOLD}1)${RESET}  Полный харденинг (все разделы)" >/dev/tty
    echo -e "  ${WHITE}${BOLD}2)${RESET}  1.1   Файловые системы, модули ядра, /tmp" >/dev/tty
    echo -e "  ${WHITE}${BOLD}3)${RESET}  1.2–1.5 Обновления, загрузчик, защита процессов" >/dev/tty
    echo -e "  ${WHITE}${BOLD}4)${RESET}  1.6–1.7 SELinux/AppArmor, баннеры" >/dev/tty
    echo -e "  ${WHITE}${BOLD}5)${RESET}  2.x   Сервисы, время, cron" >/dev/tty
    echo -e "  ${WHITE}${BOLD}6)${RESET}  3.x   Сеть: параметры ядра, протоколы" >/dev/tty
    echo -e "  ${WHITE}${BOLD}7)${RESET}  4.x   Брандмауэр" >/dev/tty
    echo -e "  ${WHITE}${BOLD}8)${RESET}  5.1   SSH" >/dev/tty
    echo -e "  ${WHITE}${BOLD}9)${RESET}  5.2–5.4 sudo, PAM, пароли, учётные записи" >/dev/tty
    echo -e "  ${WHITE}${BOLD}10)${RESET} 6.x   Журналирование, auditd, AIDE" >/dev/tty
    echo -e "  ${WHITE}${BOLD}11)${RESET} 7.x   Права на файлы, пользователи и группы" >/dev/tty
    echo -e "  ${DIM}─────────────────────────────────────────────────────────────${RESET}" >/dev/tty
    echo -e "  ${CYAN}${BOLD}r)${RESET} Откатить изменения из бэкапа" >/dev/tty
    echo -e "  ${CYAN}${BOLD}p)${RESET} Сохранить ответы в профиль" >/dev/tty
    echo -e "  ${CYAN}${BOLD}s)${RESET} Пройти опросник заново" >/dev/tty
    echo -e "  ${WHITE}${BOLD}q)${RESET} Выход" >/dev/tty
    echo "" >/dev/tty
    while true; do
        printf "%b" "${CYAN}Ваш выбор: ${RESET}" >/dev/tty
        read -r MENU_CHOICE </dev/tty || MENU_CHOICE="q"
        MENU_CHOICE="${MENU_CHOICE//[[:space:]]/}"
        case "$MENU_CHOICE" in
            0|1|2|3|4|5|6|7|8|9|10|11|r|R|p|P|s|S|q|Q) break ;;
            *) echo -e "${RED}  Введите цифру 0–11, r, p, s или q${RESET}" >/dev/tty ;;
        esac
    done
}

run_checks() {
    local mode="${1:-1}"
    # Сбрасываем накопленные исправления и счётчики перед новым прогоном
    FIXES=(); FIXES_SSH=(); FIXES_FW=(); FIXES_SUDO=()
    PASS_POLICY_ISSUES=0
    PASSES=0; ISSUES=0; WARNINGS=0
    SSHD_EFFECTIVE=""; SSHD_SOURCE=""
    FS_SCAN_DONE=0
    case "$mode" in
        1)
            cis_filesystems; cis_boot_process; cis_mac_banners
            cis_services; cis_network; cis_firewall
            cis_ssh; cis_access; cis_logging; cis_maintenance
            ;;
        2) cis_filesystems ;;
        3) cis_boot_process ;;
        4) cis_mac_banners ;;
        5) cis_services ;;
        6) cis_network ;;
        7) cis_firewall ;;
        8) cis_ssh ;;
        9) cis_access ;;
        10) cis_logging ;;
        11) cis_maintenance ;;
    esac
}

# Аудит → исправления → (по желанию) повторный аудит с оценкой «было → стало»
run_cycle() {
    local mode="$1"
    REAUDIT=0
    run_checks "$mode"
    print_summary
    if (( REPORT_ONLY == 0 )); then
        offer_remediation
        if (( HAVE_TTY )) && [[ $EUID -eq 0 ]] && confirm "Повторить проверку, чтобы оценить результат?" y; then
            REAUDIT=1
            log ""
            log "${BOLD}${CYAN}══════════ ПОВТОРНЫЙ АУДИТ ══════════${RESET}"
            run_checks "$mode"
            print_summary
            REAUDIT=0
        fi
    fi
}

# Аудит текущих настроек: все разделы, без вопросов и без исправлений.
# Ответы опросника и режимы после аудита возвращаются как были.
run_audit() {
    local saved_ni="$NONINTERACTIVE" saved_ro="$REPORT_ONLY" k
    local -A saved_ans=()
    if (( ${#ANS[@]} )); then for k in "${!ANS[@]}"; do saved_ans[$k]="${ANS[$k]}"; done; fi
    NONINTERACTIVE=1; REPORT_ONLY=1
    audit_defaults
    log ""
    log "${BOLD}${CYAN}══════════ АУДИТ ТЕКУЩИХ НАСТРОЕК (ничего не меняется) ══════════${RESET}"
    if (( WIZARD_DONE == 0 )); then
        log "  ${DIM}Опросник не пройден: пороги — рекомендации CIS Level ${CIS_LEVEL}, сервисы и порты оцениваются по строгому CIS.${RESET}"
    fi
    run_cycle 1
    log ""
    log "  ${DIM}Чтобы исправить найденное, выберите раздел 1–11 (перед первым применением будет опросник).${RESET}"
    ANS=()
    if (( ${#saved_ans[@]} )); then for k in "${!saved_ans[@]}"; do ANS[$k]="${saved_ans[$k]}"; done; fi
    NONINTERACTIVE="$saved_ni"; REPORT_ONLY="$saved_ro"
}

# Явные флаги командной строки важнее значений из профиля и опросника.
# Читает локальные переменные main (динамическая область видимости bash).
apply_cli_overrides() {
    [[ -n "$level_override" ]] && CIS_LEVEL="$level_override"
    [[ -n "$timeout_override" ]] && CONFIRM_TIMEOUT="$timeout_override"
    [[ -n "$noguard_override" ]] && DO_ROLLBACK_GUARD=0
    return 0
}

usage() {
    cat <<EOF
Использование: $0 [ОПЦИИ]

Без опций — меню; пункт 0 в нём — аудит без вопросов.

Аудит:
  --audit           Аудит текущих настроек по CIS: без вопросов, ничего не меняет

Разделы (one-shot, без меню):
  --full, -f        Все разделы CIS
  --fs              1.1   Файловые системы, модули, /tmp
  --boot            1.2–1.5 Обновления, загрузчик, процессы
  --mac             1.6–1.7 SELinux/AppArmor, баннеры
  --services        2.x   Сервисы, время, cron
  --network         3.x   Сеть
  --firewall        4.x   Брандмауэр
  --ssh             5.1   SSH
  --access          5.2–5.4 sudo, PAM, пароли, учётные записи
  --logging         6.x   Журналы, auditd, AIDE
  --maintenance     7.x   Права, пользователи, группы

Режим:
  --level 1|2       Профиль CIS (по умолчанию 1)
  --report-only     Только аудит, ничего не менять (алиас: --dry-run)
  --no-interactive  Не задавать вопросов: безопасные дефолты / профиль
  --profile FILE    Загрузить ответы опросника (без исполнения файла)
  --save-profile FILE  Сохранить ответы после опросника
  --timeout N       Секунд на подтверждение перед авто-откатом (по умолчанию 180)
  --no-rollback-guard  Отключить авто-откат по таймауту (не для прода)
  --rollback DIR    Откатить изменения из каталога бэкапа
  --list-backups    Показать каталоги бэкапов
  --help, -h        Справка
EOF
}

main() {
    local skip_interactive=0
    local oneshot_mode=""
    local profile_in="" profile_out="" level_override="" timeout_override="" noguard_override="" audit_only=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --audit)          audit_only=1 ;;
            --full|-f)        oneshot_mode="1" ;;
            --fs)             oneshot_mode="2" ;;
            --boot)           oneshot_mode="3" ;;
            --mac)            oneshot_mode="4" ;;
            --services)       oneshot_mode="5" ;;
            --network|--kernel) oneshot_mode="6" ;;
            --firewall)       oneshot_mode="7" ;;
            --ssh)            oneshot_mode="8" ;;
            --access|--accounts|--password|--pam) oneshot_mode="9" ;;
            --logging)        oneshot_mode="10" ;;
            --maintenance)    oneshot_mode="11" ;;
            --no-interactive) skip_interactive=1; NONINTERACTIVE=1 ;;
            --report-only|--dry-run) REPORT_ONLY=1 ;;
            --level)
                shift
                [[ $# -gt 0 && "$1" =~ ^[12]$ ]] || { echo "Ошибка: --level требует 1 или 2"; exit 2; }
                level_override="$1" ;;
            --profile)
                shift
                [[ $# -gt 0 ]] || { echo "Ошибка: --profile требует путь"; exit 2; }
                profile_in="$1" ;;
            --save-profile)
                shift
                [[ $# -gt 0 ]] || { echo "Ошибка: --save-profile требует путь"; exit 2; }
                profile_out="$1" ;;
            --timeout)
                shift
                # shift без проверки: `--timeout` последним аргументом падал бы на unbound variable из-за set -u
                [[ $# -gt 0 ]] || { echo "Ошибка: --timeout требует значение"; exit 2; }
                timeout_override="$1"
                ;;
            --no-rollback-guard) noguard_override=1 ;;
            --rollback)
                shift
                [[ $# -gt 0 ]] || { echo "Ошибка: --rollback требует каталог"; exit 2; }
                rollback_dir "$1"; exit $? ;;
            --list-backups) list_backups; exit 0 ;;
            --help|-h) usage; exit 0 ;;
            *) echo "Неизвестный аргумент: $1"; usage; exit 1 ;;
        esac
        shift
    done

    if [[ -n "$timeout_override" ]] && { [[ ! "$timeout_override" =~ ^[0-9]+$ ]] || (( timeout_override < 10 )); }; then
        echo "Некорректный --timeout: '${timeout_override}' (нужно целое >= 10)"
        exit 2
    fi
    if (( NONINTERACTIVE == 0 && HAVE_TTY == 0 )); then
        echo "Нет терминала (/dev/tty) — переключаюсь в --no-interactive --report-only"
        NONINTERACTIVE=1; skip_interactive=1; REPORT_ONLY=1
    fi

    # Порядок: текущие значения системы → профиль поверх них → безопасные
    # дефолты для того, чего нет ни там, ни там. С профилем вопросы о найденных
    # сервисах/портах, которых в нём нет, всё ещё задаются (без --no-interactive).
    if (( NONINTERACTIVE )) || [[ -n "$profile_in" ]]; then
        seed_defaults_from_system
        if [[ -n "$profile_in" ]]; then
            load_profile "$profile_in"
            skip_interactive=1
        fi
        noninteractive_defaults
    fi
    (( skip_interactive )) && WIZARD_DONE=1
    apply_cli_overrides

    # print_banner делает clear — предупреждение о запуске без root должно
    # выводиться ПОСЛЕ него, иначе пользователь его никогда не видел бы.
    print_banner
    check_root

    if (( audit_only )); then
        run_audit
        echo ""
        echo -e "${DIM}Отчёт сохранён: ${WHITE}${REPORT_FILE}${RESET}"
        echo ""
        exit 0
    fi

    # Опросник нужен перед применением. Для one-shot и --save-profile — сразу;
    # в меню — перед первым разделом 1–11, чтобы пункт 0 (аудит) открывался мгновенно.
    if (( WIZARD_DONE == 0 )) && [[ -n "$oneshot_mode" || -n "$profile_out" ]]; then
        interactive_setup
        apply_cli_overrides
    fi
    [[ -n "$profile_out" ]] && save_profile "$profile_out"

    # ── Режим одиночного запуска (из аргументов CLI) ─────────────────────────
    if [[ -n "$oneshot_mode" ]]; then
        run_cycle "$oneshot_mode"
        echo ""
        echo -e "${DIM}Отчёт сохранён: ${WHITE}${REPORT_FILE}${RESET}"
        echo ""
        exit 0
    fi
    if (( HAVE_TTY == 0 )); then
        run_cycle 1
        exit 0
    fi

    # ── Интерактивный цикл меню (опросник — один раз, перед первым применением) ──
    while true; do
        show_menu

        case "$MENU_CHOICE" in
            s|S) interactive_setup; apply_cli_overrides; continue ;;
            0)
                run_audit
                echo ""
                echo -e "${DIM}Отчёт дополнен: ${WHITE}${REPORT_FILE}${RESET}"
                echo ""
                echo -e "${DIM}Нажмите Enter для возврата в меню...${RESET}"
                read -r </dev/tty || true
                ;;
            p|P)
                ask_str _profile_path "Куда сохранить профиль" "/root/cis-hardening-profile.conf" '^/[^ ]+$'
                save_profile "$STR_RESULT"; unset 'ANS[_profile_path]'
                continue ;;
            r|R) rollback_interactive; continue ;;
            q|Q)
                echo ""
                echo -e "${CYAN}До свидания!${RESET}"
                echo -e "${DIM}Отчёт сохранён: ${WHITE}${REPORT_FILE}${RESET}"
                echo ""
                exit 0
                ;;
            *)
                if (( WIZARD_DONE == 0 )); then
                    interactive_setup
                    apply_cli_overrides
                fi
                run_cycle "$MENU_CHOICE"
                echo ""
                echo -e "${DIM}Отчёт дополнен: ${WHITE}${REPORT_FILE}${RESET}"
                echo ""
                echo -e "${DIM}Нажмите Enter для возврата в меню...${RESET}"
                read -r </dev/tty || true
                ;;
        esac
    done
}

main "$@"
