#!/usr/bin/env bash
# =============================================================================
#  Linux Security Audit Multitool v2.1
#  Автор: ilyabem
#  Описание: Интерактивный аудит безопасности Linux-машин
# =============================================================================

set -uo pipefail

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
REPORT_FILE="/tmp/security_audit_$(hostname -s 2>/dev/null || echo host)_$(date +%Y%m%d_%H%M%S).txt"
ISSUES=0
WARNINGS=0
PASSES=0
NOPASS_USERS=()

# Отчёт может содержать имена пользователей, открытые порты и пути — создаём
# его сразу с правами 600, чтобы он не читался всей системой из /tmp.
if : > "$REPORT_FILE" 2>/dev/null; then
    chmod 600 "$REPORT_FILE" 2>/dev/null || true
else
    REPORT_FILE="$(mktemp -t security_audit.XXXXXX)" || REPORT_FILE=/dev/null
    [[ "$REPORT_FILE" != /dev/null ]] && chmod 600 "$REPORT_FILE" 2>/dev/null
fi

# Пороговые значения по умолчанию (будут переопределены при интерактивной настройке)
MIN_PASS_LEN=12
PASS_MAX_AGE=90
PASS_MIN_AGE=1
PASS_WARN_AGE=14
PASS_HISTORY=5
REQUIRE_UPPERCASE=1
REQUIRE_LOWERCASE=1
REQUIRE_DIGITS=1
REQUIRE_SPECIAL=1
SSH_IDLE_TIMEOUT=300
SHELL_TIMEOUT=600
MAX_AUTH_TRIES=3

# ── Параметры, нужные безопасному движку применения (перенесены из pass_polic.sh) ──
FAIL_DENY=5                 # неудачных попыток до блокировки (pam_faillock)
FAIL_UNLOCK_MINUTES=15      # время блокировки, минут
UID_MIN=1000                # мин. UID, к которому применяется старение паролей
CONFIRM_TIMEOUT=180         # сек. на подтверждение до авто-отката safe-apply
DO_ROLLBACK_GUARD=1         # 1 — включён предохранитель (авто-откат по таймауту)

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
    clear
    log ""
    log "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    log "${CYAN}${BOLD}║         🛡  Linux Security Audit Multitool v2.1  🛡              ║${RESET}"
    log "${CYAN}${BOLD}║            github: ilyabem/security_audit_linux                  ║${RESET}"
    log "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    log ""
    log "  ${DIM}Хост:     ${WHITE}$(hostname -f 2>/dev/null || hostname)${RESET}"
    log "  ${DIM}ОС:       ${WHITE}$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -sr)${RESET}"
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

# Значения из конфигов могут оказаться мусором — перед (( )) всегда проверяем.
is_num() { [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}${BOLD}[⚠] Внимание: запуск без root. Часть проверок будет недоступна.${RESET}"
        echo -e "${DIM}    Рекомендуется: sudo $0${RESET}"
        echo ""
        sleep 2
    fi
}

confirm() {
    local prompt="$1"
    local default="${2:-y}"
    local yn
    if [[ "$default" == "y" ]]; then
        printf "%b" "${YELLOW}${prompt} [Y/n]: ${RESET}" >/dev/tty
        read -r yn </dev/tty
        [[ -z "$yn" || "$yn" =~ ^[Yy]$ ]]
    else
        printf "%b" "${YELLOW}${prompt} [y/N]: ${RESET}" >/dev/tty
        read -r yn </dev/tty
        [[ "$yn" =~ ^[Yy]$ ]]
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
    # никогда не проходил валидацию и пользователь застревал в цикле.
    is_num "$default" || default="$min"
    (( default < min )) && default="$min"
    (( default > max )) && default="$max"
    while true; do
        printf "%b" "${CYAN}${prompt} [по умолчанию: ${default}]: ${RESET}" >/dev/tty
        read -r val </dev/tty
        [[ -z "$val" ]] && val="$default"
        if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= min && val <= max )); then
            INT_RESULT="$val"
            return
        fi
        printf "%b\n" "${RED}  Введите число от $min до $max${RESET}" >/dev/tty
    done
}

# Читает "key = value" / "key value" из конфиг-файла (pwquality.conf, faillock.conf,
# login.defs и т.п.). Возвращает пусто, если ключ не найден — тогда вызывающий код
# оставляет жёстко заданный дефолт. Заимствовано из pass_polic.sh: показывать
# ТЕКУЩЕЕ значение системы как дефолт в интерактивной настройке, а не голую константу.
sys_kv() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    grep -E "^[[:space:]]*${key}[[:space:]]*[=]?[[:space:]]*[0-9]+" "$file" 2>/dev/null \
        | tail -1 | grep -oE '[0-9]+' | tail -1
}

# Подставляет текущие системные значения вместо статичных дефолтов, если их
# удалось прочитать (только для password/PAM-параметров — остального они не касаются).
seed_defaults_from_system() {
    local v
    v="$(sys_kv /etc/security/pwquality.conf minlen)"; [[ -n "$v" ]] && MIN_PASS_LEN="$v"
    v="$(sys_kv /etc/login.defs PASS_MAX_DAYS)"; [[ -n "$v" ]] && PASS_MAX_AGE="$v"
    v="$(sys_kv /etc/login.defs PASS_MIN_DAYS)"; [[ -n "$v" ]] && PASS_MIN_AGE="$v"
    v="$(sys_kv /etc/login.defs PASS_WARN_AGE)"; [[ -n "$v" ]] && PASS_WARN_AGE="$v"
    v="$(sys_kv /etc/security/pwhistory.conf remember)"; [[ -n "$v" ]] && PASS_HISTORY="$v"
    [[ -z "$v" ]] && { v="$(grep -oE 'remember=[0-9]+' /etc/pam.d/common-password 2>/dev/null | tail -1 | grep -oE '[0-9]+')"; [[ -n "$v" ]] && PASS_HISTORY="$v"; }
    v="$(sys_kv /etc/security/faillock.conf deny)"; [[ -n "$v" ]] && FAIL_DENY="$v"
    v="$(sys_kv /etc/security/faillock.conf unlock_time)"
    if [[ -n "$v" ]]; then
        FAIL_UNLOCK_MINUTES=$(( v / 60 ))
        (( FAIL_UNLOCK_MINUTES < 1 )) && FAIL_UNLOCK_MINUTES=1
    fi
    v="$(sys_kv /etc/login.defs UID_MIN)"; [[ -n "$v" ]] && UID_MIN="$v"
}

# ─────────────────────────── Интерактивная настройка ────────────────────────

interactive_setup() {
    seed_defaults_from_system
    echo ""
    echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${MAGENTA}║   Интерактивная настройка параметров     ║${RESET}"
    echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${DIM}Настройте пороговые значения для аудита. Enter = значение по умолчанию${RESET}"
    echo -e "${DIM}(там, где это возможно, дефолт подставлен из ТЕКУЩИХ настроек системы).${RESET}"
    echo ""

    echo -e "${WHITE}${BOLD}── Парольная политика ──────────────────────────${RESET}"
    read_int "Минимальная длина пароля" "$MIN_PASS_LEN" 6 128; MIN_PASS_LEN="$INT_RESULT"
    read_int "Максимальный срок действия пароля (дни)" "$PASS_MAX_AGE" 1 365; PASS_MAX_AGE="$INT_RESULT"
    read_int "Минимальный срок до смены пароля (дни)" "$PASS_MIN_AGE" 0 30; PASS_MIN_AGE="$INT_RESULT"
    read_int "Предупреждение до истечения пароля (дни)" "$PASS_WARN_AGE" 1 30; PASS_WARN_AGE="$INT_RESULT"
    read_int "Количество запоминаемых паролей (история)" "$PASS_HISTORY" 0 24; PASS_HISTORY="$INT_RESULT"

    echo ""
    echo -e "${WHITE}${BOLD}── Блокировка после неудачных попыток (pam_faillock) ──${RESET}"
    read_int "Неудачных попыток до блокировки" "$FAIL_DENY" 1 20; FAIL_DENY="$INT_RESULT"
    read_int "Время блокировки (минуты)" "$FAIL_UNLOCK_MINUTES" 1 1440; FAIL_UNLOCK_MINUTES="$INT_RESULT"
    read_int "Минимальный UID, к которому применяется старение паролей" "$UID_MIN" 100 60000; UID_MIN="$INT_RESULT"

    echo ""
    echo -e "${WHITE}${BOLD}── Сложность пароля ────────────────────────────${RESET}"
    # shellcheck disable=SC2034  # REQUIRE_* читаются косвенно (${!reqvar}) в check_pam_pwquality
    if confirm "Требовать ЗАГЛАВНЫЕ буквы"; then REQUIRE_UPPERCASE=1; else REQUIRE_UPPERCASE=0; fi
    # shellcheck disable=SC2034
    if confirm "Требовать строчные буквы"; then REQUIRE_LOWERCASE=1; else REQUIRE_LOWERCASE=0; fi
    # shellcheck disable=SC2034
    if confirm "Требовать цифры"; then REQUIRE_DIGITS=1; else REQUIRE_DIGITS=0; fi
    # shellcheck disable=SC2034
    if confirm "Требовать спецсимволы"; then REQUIRE_SPECIAL=1; else REQUIRE_SPECIAL=0; fi

    echo ""
    echo -e "${WHITE}${BOLD}── Таймауты ────────────────────────────────────${RESET}"
    read_int "Таймаут бездействия SSH (секунды)" "$SSH_IDLE_TIMEOUT" 60 3600; SSH_IDLE_TIMEOUT="$INT_RESULT"
    read_int "Таймаут бездействия shell (секунды)" "$SHELL_TIMEOUT" 60 7200; SHELL_TIMEOUT="$INT_RESULT"

    echo ""
    echo -e "${WHITE}${BOLD}── SSH параметры ───────────────────────────────${RESET}"
    read_int "Максимум попыток аутентификации SSH" "$MAX_AUTH_TRIES" 1 10; MAX_AUTH_TRIES="$INT_RESULT"

    echo ""
    echo -e "${WHITE}${BOLD}── Безопасное применение исправлений ───────────${RESET}"
    echo -e "${DIM}Для password/PAM, SSH и firewall исправления применяются с бэкапом${RESET}"
    echo -e "${DIM}и окном на подтверждение — иначе автооткат по таймауту.${RESET}"
    read_int "Таймаут окна подтверждения (секунды)" "$CONFIRM_TIMEOUT" 30 900; CONFIRM_TIMEOUT="$INT_RESULT"
    if confirm "Включить предохранитель (авто-откат по таймауту)" y; then DO_ROLLBACK_GUARD=1; else DO_ROLLBACK_GUARD=0; fi

    echo ""
    echo -e "${GREEN}${BOLD}✔ Параметры сохранены. Начинаю аудит...${RESET}"
    sleep 1
}


# Полный обход ФС в поисках SUID/SGID делается и в check_filesystem,
# и в check_backdoors — кэшируем, чтобы не сканировать диск дважды.
SUID_CACHE=""
SUID_CACHE_DONE=0
collect_suid() {
    (( SUID_CACHE_DONE == 1 )) && return 0
    SUID_CACHE="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)"
    SUID_CACHE_DONE=1
    return 0
}

# Персистентная запись sysctl-параметра в /etc/sysctl.d/, с нейтрализацией
# конфликтующих строк в /etc/sysctl.conf.
sysctl_persist() {
    local key="$1" val="$2" file="/etc/sysctl.d/99-security-audit.conf" esc
    esc="${key//./\\.}"
    mkdir -p /etc/sysctl.d || return 1
    [[ -f "$file" ]] || printf '# Создан security_audit.sh\n' > "$file"
    sed -i -E "/^[[:space:]]*#?[[:space:]]*${esc}[[:space:]]*=/d" "$file"
    printf '%s = %s\n' "$key" "$val" >> "$file"
    if [[ -f /etc/sysctl.conf ]]; then
        sed -i -E "s|^([[:space:]]*${esc}[[:space:]]*=.*)$|# disabled by security_audit: \\1|" /etc/sysctl.conf
    fi
    return 0
}

# ─────────────────────────── ПРОВЕРКИ ───────────────────────────────────────

# 1. Парольная политика (/etc/login.defs)
check_password_policy() {
    section "ПАРОЛЬНАЯ ПОЛИТИКА (/etc/login.defs)"

    if [[ ! -f /etc/login.defs ]]; then
        result_warn "Файл /etc/login.defs не найден"
        return
    fi

    local file=/etc/login.defs

    # PASS_MAX_DAYS
    local max_days
    max_days=$(grep -E "^PASS_MAX_DAYS" "$file" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ -z "$max_days" ]]; then
        result_fail "PASS_MAX_DAYS не задан"
        add_fix "Установить PASS_MAX_DAYS=${PASS_MAX_AGE} в /etc/login.defs" "password"
    elif ! is_num "$max_days"; then
        result_warn "PASS_MAX_DAYS = '$max_days' — не число, проверьте /etc/login.defs"
    elif (( max_days <= PASS_MAX_AGE )); then
        result_pass "PASS_MAX_DAYS = $max_days (≤ ${PASS_MAX_AGE} дней)"
    else
        result_fail "PASS_MAX_DAYS = $max_days (требуется ≤ ${PASS_MAX_AGE})"
        add_fix "Установить PASS_MAX_DAYS=${PASS_MAX_AGE} в /etc/login.defs" "password"
    fi

    # PASS_MIN_DAYS
    local min_days
    min_days=$(grep -E "^PASS_MIN_DAYS" "$file" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ -z "$min_days" ]]; then
        result_fail "PASS_MIN_DAYS не задан"
        add_fix "Установить PASS_MIN_DAYS=${PASS_MIN_AGE} в /etc/login.defs" "password"
    elif ! is_num "$min_days"; then
        result_warn "PASS_MIN_DAYS = '$min_days' — не число, проверьте /etc/login.defs"
    elif (( min_days >= PASS_MIN_AGE )); then
        result_pass "PASS_MIN_DAYS = $min_days (≥ ${PASS_MIN_AGE} дней)"
    else
        result_warn "PASS_MIN_DAYS = $min_days (рекомендуется ≥ ${PASS_MIN_AGE})"
        add_fix "Установить PASS_MIN_DAYS=${PASS_MIN_AGE} в /etc/login.defs" "password"
    fi

    # PASS_WARN_AGE
    local warn_age
    warn_age=$(grep -E "^PASS_WARN_AGE" "$file" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ -z "$warn_age" ]]; then
        result_fail "PASS_WARN_AGE не задан"
        add_fix "Установить PASS_WARN_AGE=${PASS_WARN_AGE} в /etc/login.defs" "password"
    elif ! is_num "$warn_age"; then
        result_warn "PASS_WARN_AGE = '$warn_age' — не число, проверьте /etc/login.defs"
    elif (( warn_age >= PASS_WARN_AGE )); then
        result_pass "PASS_WARN_AGE = $warn_age (≥ ${PASS_WARN_AGE} дней)"
    else
        result_warn "PASS_WARN_AGE = $warn_age (рекомендуется ≥ ${PASS_WARN_AGE} дней)"
        add_fix "Установить PASS_WARN_AGE=${PASS_WARN_AGE} в /etc/login.defs" "password"
    fi

    # PASS_MIN_LEN
    local min_len
    min_len=$(grep -E "^PASS_MIN_LEN" "$file" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ -z "$min_len" ]]; then
        result_info "PASS_MIN_LEN не задан в login.defs (на системах с PAM параметр игнорируется — важен minlen из pwquality)"
    elif ! is_num "$min_len"; then
        result_warn "PASS_MIN_LEN = '$min_len' — не число"
    elif (( min_len >= MIN_PASS_LEN )); then
        result_pass "PASS_MIN_LEN = $min_len (≥ ${MIN_PASS_LEN})"
    else
        result_fail "PASS_MIN_LEN = $min_len (требуется ≥ ${MIN_PASS_LEN})"
    fi

    # ENCRYPT_METHOD
    local enc_method
    enc_method=$(grep -E "^ENCRYPT_METHOD" "$file" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ -z "$enc_method" ]]; then
        result_warn "ENCRYPT_METHOD не задан (возможно MD5)"
    elif [[ "$enc_method" =~ ^(SHA512|YESCRYPT|BCRYPT)$ ]]; then
        result_pass "ENCRYPT_METHOD = $enc_method (безопасный алгоритм)"
    else
        result_fail "ENCRYPT_METHOD = $enc_method (рекомендуется SHA512 или YESCRYPT)"
    fi

    # SHA_CRYPT_MIN_ROUNDS
    local sha_rounds
    sha_rounds=$(grep -E "^SHA_CRYPT_MIN_ROUNDS" "$file" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ -n "$sha_rounds" ]] && is_num "$sha_rounds"; then
        if (( sha_rounds >= 500000 )); then
            result_pass "SHA_CRYPT_MIN_ROUNDS = $sha_rounds"
        else
            result_warn "SHA_CRYPT_MIN_ROUNDS = $sha_rounds (рекомендуется ≥ 500000)"
        fi
    else
        result_info "SHA_CRYPT_MIN_ROUNDS не задан (используется значение по умолчанию)"
    fi
}

# Значение параметра pwquality: сначала pwquality.conf (+ pwquality.conf.d),
# затем — inline-параметры в строках pam_pwquality/pam_cracklib в /etc/pam.d.
pwq_value() {
    local key="$1" v="" f
    for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
        [[ -f "$f" ]] || continue
        v=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$f" 2>/dev/null | tail -1 \
            | cut -d= -f2- | tr -d '[:space:]')
        [[ -n "$v" ]] && { printf '%s' "$v"; return 0; }
    done
    v=$(grep -rhE "(pam_pwquality|pam_cracklib)\.so" /etc/pam.d/ 2>/dev/null \
        | grep -v "^[[:space:]]*#" | grep -oE "${key}=-?[0-9]+" | head -1 | cut -d= -f2)
    printf '%s' "$v"
}

# 2. Сложность пароля (PAM / pwquality)
check_pam_pwquality() {
    section "СЛОЖНОСТЬ ПАРОЛЯ (PAM / pwquality)"

    local pwq_conf=""
    for f in /etc/security/pwquality.conf /etc/pam.d/common-password /etc/pam.d/system-auth; do
        [[ -f "$f" ]] && pwq_conf="$f" && break
    done

    if [[ -z "$pwq_conf" ]]; then
        result_warn "Файлы PAM/pwquality не найдены"
        return
    fi

    result_info "Анализируется: $pwq_conf"

    # Проверка наличия libpam-pwquality или pam_cracklib
    if grep -rq "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null; then
        result_pass "Модуль проверки сложности паролей (pam_pwquality/pam_cracklib) подключён"
    else
        result_fail "Модуль pam_pwquality/pam_cracklib НЕ подключён в PAM"
        add_fix "Установить и включить модуль проверки сложности паролей" "password"
    fi

    # minlen
    local pwq_minlen
    pwq_minlen=$(pwq_value minlen)
    if [[ -z "$pwq_minlen" ]]; then
        result_warn "minlen не задан в pwquality.conf"
        add_fix "Установить minlen=${MIN_PASS_LEN} в /etc/security/pwquality.conf" "password"
    elif ! is_num "$pwq_minlen"; then
        result_warn "minlen = '$pwq_minlen' — не число"
    elif (( pwq_minlen >= MIN_PASS_LEN )); then
        result_pass "minlen = $pwq_minlen (≥ ${MIN_PASS_LEN})"
    else
        result_fail "minlen = $pwq_minlen (требуется ≥ ${MIN_PASS_LEN})"
        add_fix "Установить minlen=${MIN_PASS_LEN} в /etc/security/pwquality.conf" "password"
    fi

    # Классы символов: ucredit/lcredit/dcredit/ocredit.
    # Отрицательное значение = «столько символов класса ОБЯЗАТЕЛЬНО»,
    # положительное = «бонус к длине», поэтому требование выполнено при <= -1.
    local cred key label reqvar cur
    for cred in "ucredit:ЗАГЛАВНЫЕ буквы:REQUIRE_UPPERCASE" \
                "lcredit:строчные буквы:REQUIRE_LOWERCASE" \
                "dcredit:цифры:REQUIRE_DIGITS" \
                "ocredit:спецсимволы:REQUIRE_SPECIAL"; do
        key="${cred%%:*}"
        label="$(cut -d: -f2 <<< "$cred")"
        reqvar="${cred##*:}"
        (( ${!reqvar} == 1 )) || continue
        cur="$(pwq_value "$key")"
        if is_num "$cur" && (( cur <= -1 )); then
            result_pass "${key} = ${cur} (${label} обязательны)"
        else
            result_fail "${key} не требует обязательных символов класса «${label}» (текущее: ${cur:-не задано})"
            add_fix "Требовать ${label} (${key}=-1)" "password"
        fi
    done

    # История паролей (remember)
    local remember
    remember=$(grep -rhE "remember=[0-9]+" /etc/pam.d/ /etc/security/pwhistory.conf 2>/dev/null \
        | grep -v "^[[:space:]]*#" | grep -oE "remember=[0-9]+" | head -1 | cut -d= -f2)
    [[ -z "$remember" ]] && remember=$(sys_kv /etc/security/pwhistory.conf remember)
    if is_num "$remember" && (( remember >= PASS_HISTORY )); then
        result_pass "История паролей: remember=$remember (≥ ${PASS_HISTORY})"
    else
        result_fail "История паролей не задана или недостаточна (текущее: ${remember:-0}, требуется ≥ ${PASS_HISTORY})"
        add_fix "Включить историю паролей (remember=${PASS_HISTORY})" "password"
    fi

    # Блокировка после неудачных попыток (pam_faillock / pam_tally2)
    if grep -rq "pam_faillock\|pam_tally2" /etc/pam.d/ 2>/dev/null; then
        result_pass "Блокировка после неудачных попыток входа настроена (pam_faillock/pam_tally2)"
        local deny
        deny=$(grep -rhE "deny=[0-9]+" /etc/pam.d/ 2>/dev/null | grep -v "^[[:space:]]*#" | grep -oE "deny=[0-9]+" | head -1 | cut -d= -f2)
        [[ -z "$deny" ]] && deny=$(sys_kv /etc/security/faillock.conf deny)
        [[ -n "$deny" ]] && result_info "  Блокировка после $deny неудачных попыток"
    else
        result_fail "pam_faillock/pam_tally2 не настроен — нет блокировки после неудачных попыток"
        add_fix "Включить pam_faillock (блокировка после ${FAIL_DENY} неудач на ${FAIL_UNLOCK_MINUTES} мин)" "password"
    fi
}

# 3. Учётные записи
check_accounts() {
    section "УЧЁТНЫЕ ЗАПИСИ И SHELL"

    # Аккаунты с интерактивной оболочкой (не nologin, не false)
    result_info "${BOLD}Пользователи с интерактивной оболочкой:${RESET}"
    local shell_users
    shell_users=$(awk -F: '($7 !~ /nologin|false|sync|shutdown|halt/) {print}' /etc/passwd)
    if [[ -z "$shell_users" ]]; then
        result_pass "Нет пользователей с интерактивной оболочкой"
    else
        while IFS=: read -r uname _ uid _ _ home shell; do
            local marker=""
            if (( uid == 0 )); then
                marker="${RED}[ROOT]${RESET}"
            elif (( uid < 1000 )); then
                marker="${YELLOW}[СИСТЕМА]${RESET}"
            else
                marker="${GREEN}[ПОЛЬЗОВАТЕЛЬ]${RESET}"
            fi
            log "    ${marker} ${WHITE}${uname}${RESET} ${DIM}(uid=${uid}, shell=${shell}, home=${home})${RESET}"
        done <<< "$shell_users"
    fi

    echo ""
    # Аккаунты без пароля
    result_info "${BOLD}Пользователи без пароля:${RESET}"
    if [[ $EUID -eq 0 ]]; then
        # ВАЖНО: пустое поле пароля (вход вообще без пароля) и "!", "!!", "*",
        # "!<hash>" (учётка ЗАБЛОКИРОВАНА) — принципиально разные вещи.
        # Старая версия смешивала их и репортила заблокированных как «без пароля».
        local empty_pw locked_pw real_nopass=0 u u_uid u_shell
        empty_pw=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null)
        locked_pw=$(awk -F: '$2 ~ /^[!*]/ {print $1}' /etc/shadow 2>/dev/null)

        if [[ -z "$empty_pw" ]]; then
            result_pass "Учётных записей с пустым паролем не обнаружено"
        else
            while read -r u; do
                [[ -n "$u" ]] || continue
                u_uid=$(awk -F: -v user="$u" '$1==user{print $3}' /etc/passwd 2>/dev/null)
                u_shell=$(awk -F: -v user="$u" '$1==user{print $7}' /etc/passwd 2>/dev/null)
                if is_num "$u_uid" && (( u_uid < 1000 )) && [[ "$u_shell" =~ nologin|false|/bin/sync ]]; then
                    result_warn "  ${u} (uid=${u_uid}) — системный аккаунт с ПУСТЫМ паролем (shell=${u_shell})"
                else
                    result_fail "  Пользователь '${u}' (uid=${u_uid:-?}) не имеет пароля!"
                    real_nopass=$((real_nopass+1))
                    NOPASS_USERS+=("$u")
                fi
            done <<< "$empty_pw"
        fi

        # Заблокированные — это норма для сервисных учёток, отдельной строкой
        if [[ -n "$locked_pw" ]]; then
            local locked_total=0
            while read -r u; do
                [[ -n "$u" ]] || continue
                locked_total=$((locked_total+1))
            done <<< "$locked_pw"
            result_info "  Заблокированных учётных записей (пароль отключён): ${locked_total} ${DIM}[норма для сервисных]${RESET}"
        fi

        if (( real_nopass > 0 )); then
            add_fix "Заблокировать учётные записи без пароля: ${NOPASS_USERS[*]}" "simple" \
                "for u in ${NOPASS_USERS[*]}; do passwd -l \"\$u\"; done"
        fi
    else
        result_warn "Требуется root для проверки /etc/shadow"
    fi

    echo ""
    # Аккаунты с UID 0 (кроме root)
    result_info "${BOLD}Аккаунты с UID=0 (суперпользователи):${RESET}"
    local uid0
    uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    while read -r u; do
        [[ -n "$u" ]] || continue
        if [[ "$u" == "root" ]]; then
            result_info "  root — стандартный суперпользователь"
        else
            result_fail "  Нестандартный UID=0 пользователь: ${u}!"
        fi
    done <<< "$uid0"

    echo ""
    # Проверка root login
    result_info "${BOLD}Прямой вход root:${RESET}"
    # /etc/securetty удалён в Ubuntu 22+, проверяем несколько источников
    if [[ -f /etc/securetty ]]; then
        local securetty_entries
        securetty_entries=$(grep -cv "^#\|^$" /etc/securetty 2>/dev/null || echo 0)
        if (( securetty_entries == 0 )); then
            result_pass "/etc/securetty пуст — прямой root-вход заблокирован"
        else
            result_warn "/etc/securetty: root разрешён через $securetty_entries tty"
        fi
    else
        result_info "/etc/securetty отсутствует (Ubuntu 22+ — управление через PAM/shadow)"
    fi
    # Проверяем заблокирован ли root в shadow
    if [[ $EUID -eq 0 ]]; then
        local root_pw_field
        root_pw_field=$(awk -F: '$1=="root"{print $2}' /etc/shadow 2>/dev/null)
        if [[ "$root_pw_field" =~ ^[!*] ]]; then
            result_pass "root заблокирован в /etc/shadow (пароль: ${root_pw_field:0:2}...)"
        elif [[ -z "$root_pw_field" ]]; then
            result_fail "root не имеет пароля в /etc/shadow!"
        else
            result_warn "root имеет активный пароль — прямой вход возможен"
        fi
    fi
    # PAM pam_securetty
    if grep -rq "pam_securetty" /etc/pam.d/ 2>/dev/null; then
        result_pass "pam_securetty подключён (ограничивает root-вход)"
    else
        result_info "pam_securetty не используется"
    fi
    # Проверяем /etc/passwd — не пустой ли пароль root
    local root_passwd_field
    root_passwd_field=$(awk -F: '$1=="root"{print $2}' /etc/passwd 2>/dev/null)
    if [[ "$root_passwd_field" == "x" ]]; then
        result_pass "root в /etc/passwd ссылается на shadow (нормально)"
    elif [[ "$root_passwd_field" == "" ]]; then
        result_fail "root в /etc/passwd — пустой пароль!"
    fi

    # Аккаунты с истёкшим паролем
    echo ""
    result_info "${BOLD}Аккаунты с истёкшим паролем:${RESET}"
    if [[ $EUID -eq 0 ]] && command -v chage &>/dev/null; then
        local expired_found=0
        while IFS=: read -r uname _ uid _ _ _ shell; do
            [[ "$shell" =~ nologin|false ]] && continue
            is_num "$uid" || continue
            (( uid < 1000 )) && [[ "$uname" != "root" ]] && continue
            local exp
            # LC_ALL=C — иначе на локализованной системе grep по английской
            # строке "Password expires" не находит ничего и проверка молча пустая
            exp=$(LC_ALL=C chage -l "$uname" 2>/dev/null | grep "Password expires" | cut -d: -f2- | xargs)
            if [[ "$exp" == "never" || -z "$exp" ]]; then
                : # не истёк
            elif [[ "$exp" =~ "password must be changed" ]]; then
                result_fail "  ${uname}: пароль НЕОБХОДИМО сменить"
                expired_found=$((expired_found+1))
            fi
        done < /etc/passwd
        (( expired_found == 0 )) && result_pass "Истёкших паролей не обнаружено"
    else
        result_warn "Требуется root и утилита chage"
    fi

    # Sudo права
    echo ""
    result_info "${BOLD}Пользователи и группы с sudo:${RESET}"
    if [[ -f /etc/sudoers ]]; then
        grep -v "^#\|^$\|^Defaults\|^root" /etc/sudoers 2>/dev/null | while read -r line; do
            log "    ${DIM}${line}${RESET}"
        done
        # Проверка NOPASSWD
        if grep -qE "NOPASSWD" /etc/sudoers 2>/dev/null || grep -rqE "NOPASSWD" /etc/sudoers.d/ 2>/dev/null; then
            result_fail "Обнаружены правила NOPASSWD в sudoers — sudo без пароля!"
        else
            result_pass "NOPASSWD в sudoers не обнаружен"
        fi
    fi
}

# ── Эффективная конфигурация sshd ────────────────────────────────────────────
# Старая версия читала только /etc/ssh/sshd_config и игнорировала директиву
# Include, из-за чего на Ubuntu 22+/Debian 12 (где 50-cloud-init.conf и прочие
# drop-in'ы задают PasswordAuthentication, PermitRootLogin и т.д.) выдавала
# ложные PASS. Теперь: по возможности `sshd -T` (учитывает Include и дефолты),
# иначе — склейка sshd_config со всеми Include-файлами.
SSHD_EFFECTIVE=""
SSHD_SOURCE=""

build_sshd_effective() {
    SSHD_EFFECTIVE=""; SSHD_SOURCE=""
    local main="/etc/ssh/sshd_config"
    [[ -f "$main" ]] || return 1

    local bin
    for bin in /usr/sbin/sshd /sbin/sshd "$(command -v sshd 2>/dev/null || true)"; do
        [[ -n "$bin" && -x "$bin" ]] || continue
        if [[ $EUID -eq 0 ]]; then
            SSHD_EFFECTIVE="$("$bin" -T 2>/dev/null)"
            if [[ -n "$SSHD_EFFECTIVE" ]]; then
                SSHD_SOURCE="sshd -T"
                return 0
            fi
        fi
        break
    done

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
    done < "$main"
    SSHD_SOURCE="sshd_config + Include"
    return 0
}

# Первое поле значения (PermitRootLogin, Port, MaxAuthTries...)
get_ssh_param() {
    local param="$1"
    if [[ "$SSHD_SOURCE" == "sshd -T" ]]; then
        awk -v p="${param,,}" 'tolower($1)==p {v=$2} END{ if (v!="") print v }' <<< "$SSHD_EFFECTIVE"
    else
        grep -Ei "^[[:space:]]*${param}[[:space:]]" <<< "$SSHD_EFFECTIVE" \
            | grep -v "^[[:space:]]*#" | head -1 | awk '{print $2}'
    fi
}

# Значение целиком (Ciphers, MACs, KexAlgorithms, AllowUsers...)
get_ssh_param_full() {
    local param="$1"
    if [[ "$SSHD_SOURCE" == "sshd -T" ]]; then
        awk -v p="${param,,}" 'tolower($1)==p { $1=""; sub(/^[[:space:]]+/,""); v=$0 } END{ if (v!="") print v }' <<< "$SSHD_EFFECTIVE"
    else
        grep -Ei "^[[:space:]]*${param}[[:space:]]" <<< "$SSHD_EFFECTIVE" \
            | grep -v "^[[:space:]]*#" | head -1 | sed -E 's/^[[:space:]]*[^[:space:]]+[[:space:]]+//'
    fi
}

# Записывает директиву так, чтобы она гарантированно победила: в OpenSSH
# выигрывает ПЕРВОЕ вхождение, а Include обычно стоит в начале sshd_config —
# поэтому конфликтующие строки в drop-in'ах комментируются, а наша строка
# вставляется первой строкой основного файла (до Include и до любого Match).
ssh_set_param() {
    local key="$1" val="$2" main="/etc/ssh/sshd_config" f
    [[ -f "$main" ]] || return 1
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$f" ]] || continue
        sed -i -E "s|^([[:space:]]*${key}[[:space:]].*)$|# disabled by security_audit: \\1|I" "$f"
    done
    sed -i -E "/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]/Id" "$main"
    sed -i "1i ${key} ${val}" "$main"
}

# 4. SSH конфигурация
check_ssh() {
    section "КОНФИГУРАЦИЯ SSH"

    if [[ ! -f /etc/ssh/sshd_config ]]; then
        result_warn "SSH не установлен или конфиг не найден"
        return
    fi
    build_sshd_effective || { result_warn "Не удалось прочитать конфигурацию sshd"; return; }
    result_info "Источник конфигурации: ${SSHD_SOURCE}"
    [[ "$SSHD_SOURCE" != "sshd -T" ]] && result_info "${DIM}  (запуск от root даёт точную эффективную конфигурацию через sshd -T)${RESET}"

    # Root login
    local root_login
    root_login=$(get_ssh_param "PermitRootLogin")
    if [[ -z "$root_login" ]]; then
        result_warn "PermitRootLogin не задан (по умолчанию — prohibit-password)"
    elif [[ "${root_login,,}" == "no" ]]; then
        result_pass "PermitRootLogin = no"
    elif [[ "${root_login,,}" == "prohibit-password" || "${root_login,,}" == "without-password" ]]; then
        result_warn "PermitRootLogin = $root_login (допускает root по ключу)"
    else
        result_fail "PermitRootLogin = $root_login (рекомендуется 'no')"
        add_fix "Запретить прямой root-вход SSH (PermitRootLogin no)" "ssh" "ssh_set_param PermitRootLogin no"
    fi

    # Пустые пароли
    local empty_pw
    empty_pw=$(get_ssh_param "PermitEmptyPasswords")
    if [[ "${empty_pw,,}" == "no" || -z "$empty_pw" ]]; then
        result_pass "PermitEmptyPasswords = ${empty_pw:-no (по умолчанию)}"
    else
        result_fail "PermitEmptyPasswords = $empty_pw — КРИТИЧНО!"
        add_fix "Запретить пустые пароли SSH (PermitEmptyPasswords no)" "ssh" "ssh_set_param PermitEmptyPasswords no"
    fi

    # Парольная аутентификация
    local pass_auth
    pass_auth=$(get_ssh_param "PasswordAuthentication")
    if [[ "${pass_auth,,}" == "no" ]]; then
        result_pass "PasswordAuthentication = no (только ключи)"
    else
        result_warn "PasswordAuthentication = ${pass_auth:-yes} (рекомендуется отключить)"
    fi

    # Аутентификация по ключу
    local pubkey_auth
    pubkey_auth=$(get_ssh_param "PubkeyAuthentication")
    if [[ "${pubkey_auth,,}" == "yes" || -z "$pubkey_auth" ]]; then
        result_pass "PubkeyAuthentication = ${pubkey_auth:-yes (по умолчанию)}"
    else
        result_fail "PubkeyAuthentication = $pubkey_auth — аутентификация по ключу отключена!"
    fi

    # Таймаут бездействия
    local client_alive_int
    local client_alive_cnt
    client_alive_int=$(get_ssh_param "ClientAliveInterval")
    client_alive_cnt=$(get_ssh_param "ClientAliveCountMax")
    # sshd -T всегда печатает clientaliveinterval, и 0 означает «отключено»
    is_num "$client_alive_int" || client_alive_int=""
    [[ "$client_alive_int" == "0" ]] && client_alive_int=""
    is_num "$client_alive_cnt" || client_alive_cnt=""
    local effective_timeout=0
    if [[ -n "$client_alive_int" && -n "$client_alive_cnt" ]] && (( client_alive_cnt > 0 )); then
        effective_timeout=$(( client_alive_int * client_alive_cnt ))
    elif [[ -n "$client_alive_int" ]]; then
        effective_timeout=$client_alive_int
    fi

    if [[ -z "$client_alive_int" ]]; then
        result_fail "ClientAliveInterval не задан — SSH-сессии не прерываются по таймауту"
        add_fix "Установить таймаут SSH (ClientAliveInterval=${SSH_IDLE_TIMEOUT}, CountMax=1)" "ssh" \
            "ssh_set_param ClientAliveCountMax 1; ssh_set_param ClientAliveInterval ${SSH_IDLE_TIMEOUT}"
    elif (( effective_timeout <= SSH_IDLE_TIMEOUT )); then
        result_pass "Таймаут SSH: ClientAliveInterval=${client_alive_int}×ClientAliveCountMax=${client_alive_cnt:-1} = ${effective_timeout}с (≤ ${SSH_IDLE_TIMEOUT}с)"
    else
        result_fail "Таймаут SSH слишком велик: ${effective_timeout}с (требуется ≤ ${SSH_IDLE_TIMEOUT}с)"
    fi

    # MaxAuthTries
    local max_auth
    max_auth=$(get_ssh_param "MaxAuthTries")
    if [[ -z "$max_auth" ]] || ! is_num "$max_auth"; then
        result_warn "MaxAuthTries не задан (по умолчанию 6)"
    elif (( max_auth <= MAX_AUTH_TRIES )); then
        result_pass "MaxAuthTries = $max_auth (≤ ${MAX_AUTH_TRIES})"
    else
        result_fail "MaxAuthTries = $max_auth (рекомендуется ≤ ${MAX_AUTH_TRIES})"
        add_fix "Установить MaxAuthTries=${MAX_AUTH_TRIES} в sshd_config" "ssh" "ssh_set_param MaxAuthTries ${MAX_AUTH_TRIES}"
    fi

    # Protocol / версия
    local protocol
    protocol=$(get_ssh_param "Protocol")
    if [[ -n "$protocol" && "$protocol" != "2" ]]; then
        result_fail "Protocol = $protocol (должен быть 2)"
    else
        result_pass "SSH Protocol 2 (устаревший SSHv1 не активен)"
    fi

    # X11Forwarding
    local x11fwd
    x11fwd=$(get_ssh_param "X11Forwarding")
    if [[ "${x11fwd,,}" == "yes" ]]; then
        result_warn "X11Forwarding = yes (рекомендуется отключить)"
    else
        result_pass "X11Forwarding = ${x11fwd:-no}"
    fi

    # AllowTcpForwarding
    local tcp_fwd
    tcp_fwd=$(get_ssh_param "AllowTcpForwarding")
    if [[ "${tcp_fwd,,}" == "yes" || -z "$tcp_fwd" ]]; then
        result_warn "AllowTcpForwarding = ${tcp_fwd:-yes (по умолчанию)} (рассмотрите отключение)"
    else
        result_pass "AllowTcpForwarding = $tcp_fwd"
    fi

    # UsePAM
    local use_pam
    use_pam=$(get_ssh_param "UsePAM")
    if [[ "${use_pam,,}" == "yes" || -z "$use_pam" ]]; then
        result_pass "UsePAM = ${use_pam:-yes}"
    else
        result_warn "UsePAM = $use_pam (рекомендуется yes)"
    fi

    # Port
    local ssh_port
    ssh_port=$(get_ssh_param "Port")
    if [[ -z "$ssh_port" || "$ssh_port" == "22" ]]; then
        result_warn "SSH порт = ${ssh_port:-22} (стандартный — рассмотрите смену)"
    else
        result_pass "SSH порт = $ssh_port (нестандартный)"
    fi

    # LoginGraceTime
    local grace
    grace=$(get_ssh_param "LoginGraceTime")
    grace="${grace%s}"
    if [[ -z "$grace" ]] || ! is_num "$grace"; then
        result_warn "LoginGraceTime не задан или задан в нечисловом формате (по умолчанию 120с)"
    elif (( grace == 0 )); then
        result_fail "LoginGraceTime = 0 (время на аутентификацию не ограничено)"
    elif (( grace <= 60 )); then
        result_pass "LoginGraceTime = ${grace}с"
    else
        result_warn "LoginGraceTime = ${grace}с (рекомендуется ≤ 60с)"
    fi

    # AllowUsers / AllowGroups
    local allow_users allow_groups
    allow_users=$(get_ssh_param_full "AllowUsers")
    allow_groups=$(get_ssh_param_full "AllowGroups")
    if [[ -n "$allow_users" || -n "$allow_groups" ]]; then
        result_pass "Ограничение доступа: AllowUsers='${allow_users:-}' AllowGroups='${allow_groups:-}'"
    else
        result_warn "AllowUsers/AllowGroups не заданы — все пользователи могут подключаться по SSH"
    fi

    # Banner
    local banner
    banner=$(get_ssh_param_full "Banner")
    if [[ -n "$banner" && "$banner" != "none" ]]; then
        result_pass "Баннер SSH настроен: $banner"
    else
        result_warn "Баннер SSH (Banner) не настроен"
    fi
}

# 5. Таймаут бездействия shell
check_shell_timeout() {
    section "ТАЙМАУТ БЕЗДЕЙСТВИЯ SHELL"

    local timeout_found=0
    local tmout_val=""

    # Проверяем глобальные профили
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/*.sh; do
        [[ -f "$f" ]] || continue
        local val
        val=$(grep -E "^[[:space:]]*(export[[:space:]]+)?(readonly[[:space:]]+)?TMOUT[[:space:]]*=" "$f" 2>/dev/null \
              | tail -1 | sed -E 's/.*TMOUT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')
        is_num "$val" || val=""
        if [[ -n "$val" ]]; then
            tmout_val="$val"
            timeout_found=1
            result_info "TMOUT=$val найден в $f"
        fi
    done

    if [[ "$timeout_found" -eq 0 ]]; then
        result_fail "TMOUT не задан в глобальных профилях — shell не завершается по таймауту"
        add_fix "Установить TMOUT=${SHELL_TIMEOUT} (таймаут shell) в /etc/profile.d/timeout.sh" "simple" \
            "printf 'readonly TMOUT=%s\\nexport TMOUT\\n' '${SHELL_TIMEOUT}' > /etc/profile.d/timeout.sh && chmod 644 /etc/profile.d/timeout.sh"
    elif [[ -n "$tmout_val" ]] && is_num "$tmout_val" && (( tmout_val <= SHELL_TIMEOUT )); then
        result_pass "Таймаут shell TMOUT=${tmout_val}с (≤ ${SHELL_TIMEOUT}с)"
    else
        result_fail "Таймаут shell TMOUT=${tmout_val}с слишком велик (требуется ≤ ${SHELL_TIMEOUT}с)"
    fi

    # readonly TMOUT
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/*.sh; do
        [[ -f "$f" ]] || continue
        if grep -qE "^\s*readonly\s+TMOUT" "$f" 2>/dev/null; then
            result_pass "TMOUT объявлен как readonly в $f"
            return
        fi
    done
    (( timeout_found == 1 )) && result_warn "TMOUT не объявлен как readonly — пользователь может сбросить его"
}

# 6. Брандмауэр
check_firewall() {
    section "БРАНДМАУЭР"

    local fw_active=0

    # UFW
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1)
        if echo "$ufw_status" | grep -qi "active"; then
            result_pass "UFW активен: $ufw_status"
            fw_active=1
            ufw status verbose 2>/dev/null | grep -E "^(To|Ports|From)" | while read -r line; do
                result_info "  UFW: $line"
            done
        else
            result_warn "UFW установлен, но не активен"
        fi
    fi

    # firewalld
    if command -v firewall-cmd &>/dev/null; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            result_pass "firewalld активен"
            fw_active=1
            result_info "  Активная зона: $(firewall-cmd --get-active-zones 2>/dev/null | head -1)"
        else
            result_warn "firewalld установлен, но не запущен"
        fi
    fi

    # iptables
    if command -v iptables &>/dev/null; then
        local ipt_rules
        ipt_rules=$(iptables -L INPUT --line-numbers 2>/dev/null | grep -c "^[0-9]")
        ipt_rules="${ipt_rules:-0}"
        if (( ipt_rules > 0 )); then
            result_pass "iptables: $ipt_rules правил в цепочке INPUT"
            fw_active=1
        else
            result_warn "iptables: цепочка INPUT пуста"
        fi
    fi

    # БЫЛО: add_fix стоял вне if из-за сбитого отступа и добавлялся всегда —
    # то есть скрипт предлагал сбросить работающий firewall (`ufw --force reset`).
    if (( fw_active == 0 )); then
        result_fail "Ни один брандмауэр не обнаружен в активном состоянии!"
        if command -v ufw &>/dev/null; then
            add_fix "Включить UFW (deny incoming, allow outgoing, allow ssh)" "firewall" \
                "ufw --force reset; ufw default deny incoming; ufw default allow outgoing; ufw allow ssh; ufw --force enable"
        else
            result_info "ufw не установлен — автоисправление недоступно, настройте брандмауэр вручную"
        fi
    fi

    # IPv6 firewall
    if command -v ip6tables &>/dev/null; then
        local ip6t_rules
        ip6t_rules=$(ip6tables -L INPUT 2>/dev/null | grep -c "^[A-Z]")
        ip6t_rules="${ip6t_rules:-0}"
        if (( ip6t_rules > 2 )); then
            result_pass "ip6tables: правила IPv6 настроены"
        else
            result_warn "ip6tables: правила IPv6 не настроены"
        fi
    fi
}

# 7. Обновления и патчи
check_updates() {
    section "ОБНОВЛЕНИЯ СИСТЕМЫ"

    # Дата последнего обновления
    if command -v apt &>/dev/null; then
        local last_update
        last_update=$(stat -c %Y /var/lib/apt/lists/ 2>/dev/null)
        if [[ -n "$last_update" ]]; then
            local now days_ago
            now=$(date +%s)
            days_ago=$(( (now - last_update) / 86400 ))
            if (( days_ago <= 7 )); then
                result_pass "apt: последнее обновление индекса $days_ago дней назад"
            else
                result_warn "apt: последнее обновление индекса $days_ago дней назад (рекомендуется ≤ 7)"
            fi
        fi

        # Доступные обновления безопасности.
        # apt-check не в PATH — он лежит в /usr/lib/update-notifier/.
        local apt_check_bin="" c
        for c in /usr/lib/update-notifier/apt-check "$(command -v apt-check 2>/dev/null || true)"; do
            [[ -n "$c" && -x "$c" ]] && { apt_check_bin="$c"; break; }
        done
        if [[ -n "$apt_check_bin" ]]; then
            local security_updates
            security_updates=$("$apt_check_bin" 2>&1 | awk -F';' '{print $2}')
            if [[ "$security_updates" == "0" ]]; then
                result_pass "Нет ожидающих обновлений безопасности"
            elif is_num "$security_updates"; then
                result_fail "Ожидает установки обновлений безопасности: $security_updates"
            fi
        else
            local pending
            pending=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c "^Inst ")
            is_num "$pending" || pending=0
            if (( pending == 0 )); then
                result_pass "Ожидающих обновлений пакетов нет"
            else
                result_warn "Ожидает установки обновлений: ${pending} (проверьте, есть ли среди них security)"
            fi
        fi

        # unattended-upgrades
        if dpkg -l unattended-upgrades &>/dev/null 2>&1 &&
           systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
            result_pass "unattended-upgrades активен (автоматические обновления)"
        else
            result_warn "unattended-upgrades не активен"
        fi

    elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
        local pkg_mgr="yum"
        command -v dnf &>/dev/null && pkg_mgr="dnf"
        local sec_updates
        sec_updates=$($pkg_mgr check-update --security 2>/dev/null | grep -c "^[a-zA-Z]")
        sec_updates="${sec_updates:-?}"
        result_info "Проверка обновлений безопасности через $pkg_mgr: ~$sec_updates пакетов"
    fi
}

# 8. Сервисы и открытые порты
check_services() {
    section "СЕРВИСЫ И ОТКРЫТЫЕ ПОРТЫ"

    # Прослушиваемые порты
    result_info "${BOLD}Открытые порты (LISTEN):${RESET}"
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep LISTEN | while read -r line; do
            local port
            port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
            local proc
            proc=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "?")
            log "    ${DIM}Порт ${WHITE}${port}${DIM} — процесс: ${WHITE}${proc}${RESET}"
        done
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep LISTEN | while read -r line; do
            log "    ${DIM}${line}${RESET}"
        done
    fi

    echo ""
    # Опасные сервисы
    result_info "${BOLD}Небезопасные сервисы:${RESET}"
    local dangerous_services=("telnet" "ftp" "rsh" "rlogin" "rexec" "tftp" "talk" "ntalk" "finger" "rcp")
    for svc in "${dangerous_services[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            result_fail "Небезопасный сервис АКТИВЕН: $svc"
        elif command -v "$svc" &>/dev/null; then
            result_warn "Небезопасный сервис установлен (не запущен): $svc"
        fi
    done

    echo ""
    # Автозапуск
    result_info "${BOLD}Сервисы в автозапуске (enabled):${RESET}"
    if command -v systemctl &>/dev/null; then
        systemctl list-unit-files --state=enabled --type=service 2>/dev/null | grep -v "^UNIT\|listed" | while read -r unit state; do
            log "    ${DIM}${unit} ${GREEN}${state}${RESET}"
        done
    fi
}

# 9. Файловая система и права
check_filesystem() {
    section "ФАЙЛОВАЯ СИСТЕМА И ПРАВА ДОСТУПА"

    # SUID/SGID файлы.
    # БЫЛО: `find | grep | while` — тело while крутилось в подоболочке, поэтому
    # suid_count всегда оставался 0 и печатался PASS даже при найденных файлах.
    result_info "${BOLD}Файлы с SUID/SGID (вне стандартных путей):${RESET}"
    local suid_count=0 f
    collect_suid
    while read -r f; do
        [[ -n "$f" ]] || continue
        result_warn "  SUID/SGID: $f"
        suid_count=$((suid_count+1))
    done < <(grep -Ev "^(/usr/bin|/usr/sbin|/bin|/sbin|/usr/lib|/usr/libexec)" <<< "$SUID_CACHE")
    (( suid_count == 0 )) && result_pass "Нестандартных SUID/SGID файлов не обнаружено"

    echo ""
    # Мировозаписываемые файлы
    result_info "${BOLD}Мировозаписываемые файлы (world-writable):${RESET}"
    local ww_files ww_total
    # sticky-bit каталоги (/tmp и т.п.) исключаем — это штатная конфигурация
    ww_total=$(find / -xdev -perm -o+w ! -type l ! -perm -1000 \
        -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | wc -l)
    ww_files=$(find / -xdev -perm -o+w ! -type l ! -perm -1000 \
        -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -20)
    if [[ -z "$ww_files" ]]; then
        result_pass "Мировозаписываемых файлов не обнаружено"
    else
        while read -r f; do
            [[ -n "$f" ]] || continue
            result_warn "  world-writable: $f"
        done <<< "$ww_files"
        is_num "$ww_total" && (( ww_total > 20 )) && \
            result_info "  ...показаны первые 20 из ${ww_total}"
    fi

    echo ""
    # /tmp как отдельный раздел с noexec
    result_info "${BOLD}Монтирование /tmp:${RESET}"
    if mount | grep -q "on /tmp "; then
        local tmp_opts
        tmp_opts=$(mount | grep "on /tmp " | awk '{print $6}')
        if echo "$tmp_opts" | grep -q "noexec"; then
            result_pass "/tmp смонтирован с noexec"
        else
            result_warn "/tmp не имеет флага noexec: $tmp_opts"
        fi
        if echo "$tmp_opts" | grep -q "nosuid"; then
            result_pass "/tmp смонтирован с nosuid"
        else
            result_warn "/tmp не имеет флага nosuid"
        fi
    else
        result_warn "/tmp не смонтирован как отдельный раздел"
    fi

    echo ""
    # Права на /etc/passwd и /etc/shadow
    result_info "${BOLD}Права на критические файлы:${RESET}"
    local critical_files=(
        "/etc/passwd:644"
        "/etc/shadow:640"
        "/etc/group:644"
        "/etc/gshadow:640"
        "/etc/sudoers:440"
        "/etc/ssh/sshd_config:600"
    )
    for entry in "${critical_files[@]}"; do
        local file="${entry%%:*}"
        local expected_perm="${entry##*:}"
        [[ ! -f "$file" ]] && continue
        local actual_perm
        actual_perm=$(stat -c "%a" "$file" 2>/dev/null)
        if [[ "$actual_perm" == "$expected_perm" ]]; then
            result_pass "$file: права $actual_perm (OK)"
        else
            result_fail "$file: права $actual_perm (ожидается $expected_perm)"
        fi
    done
}

# 10. Ядро и системные параметры (sysctl)
check_kernel() {
    section "ПАРАМЕТРЫ ЯДРА (sysctl)"

    declare -A sysctl_checks=(
        ["net.ipv4.ip_forward"]="0|Переадресация IP пакетов отключена"
        ["net.ipv4.conf.all.accept_redirects"]="0|ICMP-редиректы отклоняются"
        ["net.ipv4.conf.all.send_redirects"]="0|Отправка ICMP-редиректов отключена"
        ["net.ipv4.conf.all.accept_source_route"]="0|Source routing отключён"
        ["net.ipv4.conf.all.log_martians"]="1|Логирование martian-пакетов включено"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1|Ignore broadcast pings"
        ["net.ipv4.tcp_syncookies"]="1|SYN cookies (защита от SYN flood) активны"
        ["net.ipv6.conf.all.accept_redirects"]="0|IPv6 ICMP-редиректы отклоняются"
        ["kernel.randomize_va_space"]="2|ASLR максимальный (2)"
        ["kernel.dmesg_restrict"]="1|dmesg ограничен для обычных пользователей"
        ["kernel.kptr_restrict"]="2|Указатели ядра скрыты"
        ["fs.protected_hardlinks"]="1|Защита жёстких ссылок"
        ["fs.protected_symlinks"]="1|Защита символических ссылок"
        ["net.ipv4.conf.default.rp_filter"]="1|Reverse path filtering"
        ["net.ipv4.conf.all.rp_filter"]="1|Reverse path filtering (all)"
    )

    for param in "${!sysctl_checks[@]}"; do
        local expected="${sysctl_checks[$param]%%|*}"
        local desc="${sysctl_checks[$param]##*|}"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        if [[ "$actual" == "$expected" ]]; then
            result_pass "$desc ($param = $actual)"
        elif [[ "$actual" == "N/A" ]]; then
            result_info "$param недоступен в данной системе"
        else
            result_fail "$desc — $param = $actual (ожидается $expected)"
            # БЫЛО: sed 's|param.*|param=X|' по /etc/sysctl.conf правил и
            # закомментированные строки (#net.ipv4... → #net.ipv4...=0), т.е.
            # «исправление» молча не применялось после перезагрузки.
            add_fix "Установить ${param}=${expected} (${desc})" "simple" \
                "sysctl -w '${param}=${expected}' >/dev/null && sysctl_persist '${param}' '${expected}'"
        fi
    done
}

# 11. Аудит и логирование
check_logging() {
    section "АУДИТ И ЛОГИРОВАНИЕ"

    # auditd
    if command -v auditctl &>/dev/null; then
        if systemctl is-active --quiet auditd 2>/dev/null; then
            result_pass "auditd активен"
            local audit_rules
            audit_rules=$(auditctl -l 2>/dev/null | grep -cv "^No rules")
            result_info "  Правил аудита: $audit_rules"
        else
            result_fail "auditd установлен, но НЕ запущен"
        fi
    else
        result_warn "auditd не установлен (рекомендуется для STIG/CIS)"
        add_fix "Установить и включить auditd" "simple" "apt-get install -y auditd audispd-plugins 2>/dev/null || yum install -y audit 2>/dev/null; systemctl enable --now auditd"
    fi

    # rsyslog / syslog-ng
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        result_pass "rsyslog активен"
    elif systemctl is-active --quiet syslog-ng 2>/dev/null; then
        result_pass "syslog-ng активен"
    else
        result_fail "rsyslog/syslog-ng не запущен — системные логи могут не писаться"
        add_fix "Установить и запустить rsyslog" "simple" "apt-get install -y rsyslog 2>/dev/null || yum install -y rsyslog 2>/dev/null; systemctl enable --now rsyslog"
    fi

    # journald
    if systemctl is-active --quiet systemd-journald 2>/dev/null; then
        result_pass "systemd-journald активен"
        local journal_storage
        journal_storage=$(grep -E "^\s*Storage\s*=" /etc/systemd/journald.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        if [[ "${journal_storage,,}" == "persistent" ]]; then
            result_pass "  Логи journald хранятся постоянно (persistent)"
        else
            result_warn "  Хранение логов journald: ${journal_storage:-auto} (рекомендуется persistent)"
        fi
    fi

    # /var/log права
    result_info "${BOLD}Права на /var/log:${RESET}"
    local varlog_perm
    varlog_perm=$(stat -c "%a" /var/log 2>/dev/null)
    if [[ "$varlog_perm" =~ ^[67][57]0$ ]] || [[ "$varlog_perm" == "750" ]] || [[ "$varlog_perm" == "755" ]]; then
        result_pass "/var/log права: $varlog_perm"
    else
        result_warn "/var/log права: $varlog_perm (рекомендуется 750 или 755)"
    fi

    # Ротация логов
    if [[ -f /etc/logrotate.conf ]]; then
        result_pass "logrotate настроен (/etc/logrotate.conf)"
    else
        result_warn "logrotate не найден"
    fi
}

# 12. SELinux / AppArmor
check_mac() {
    section "МАНДАТНЫЙ КОНТРОЛЬ ДОСТУПА (SELinux / AppArmor)"

    # SELinux
    if command -v getenforce &>/dev/null; then
        local se_mode
        se_mode=$(getenforce 2>/dev/null)
        if [[ "$se_mode" == "Enforcing" ]]; then
            result_pass "SELinux: Enforcing (активен)"
        elif [[ "$se_mode" == "Permissive" ]]; then
            result_warn "SELinux: Permissive (логирует, но не блокирует)"
        else
            result_fail "SELinux: $se_mode (отключён)"
        fi
    # AppArmor
    elif command -v aa-status &>/dev/null; then
        if aa-status --enabled 2>/dev/null; then
            local loaded_profiles
            loaded_profiles=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
            local enforce_profiles
            enforce_profiles=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')
            result_pass "AppArmor активен: загружено профилей: $loaded_profiles, в enforce: $enforce_profiles"
        else
            result_fail "AppArmor установлен, но не активен"
        fi
    else
        result_warn "SELinux и AppArmor не обнаружены"
    fi
}

# 13. Шифрование диска
check_encryption() {
    section "ШИФРОВАНИЕ ДИСКОВ"

    if command -v lsblk &>/dev/null; then
        local encrypted
        encrypted=$(lsblk -o TYPE 2>/dev/null | grep -c "crypt")
        encrypted="${encrypted:-0}"
        if (( encrypted > 0 )); then
            result_pass "Обнаружено $encrypted зашифрованных раздела (dm-crypt/LUKS)"
            lsblk -o NAME,TYPE,SIZE,MOUNTPOINT 2>/dev/null | grep "crypt" | while read -r line; do
                result_info "  $line"
            done
        else
            result_warn "Зашифрованных разделов не обнаружено"
        fi
    fi

    # LUKS
    if command -v cryptsetup &>/dev/null; then
        result_info "cryptsetup доступен"
    fi
}

# 14. Cron и задачи
check_cron() {
    section "CRON И ЗАДАЧИ ПЛАНИРОВЩИКА"

    # Права на /etc/crontab
    if [[ -f /etc/crontab ]]; then
        local cron_perm
        cron_perm=$(stat -c "%a %U %G" /etc/crontab)
        result_info "/etc/crontab: $cron_perm"
    fi

    # Разрешения cron
    if [[ -f /etc/cron.allow ]]; then
        result_pass "/etc/cron.allow существует (ограниченный список)"
        while read -r u; do
            [[ -n "$u" ]] && result_info "  cron.allow: $u"
        done < /etc/cron.allow
    elif [[ -f /etc/cron.deny ]]; then
        result_warn "/etc/cron.deny используется (менее безопасно, чем cron.allow)"
    else
        result_warn "Ни cron.allow, ни cron.deny не настроены"
    fi

    # Пользовательские crontab
    result_info "${BOLD}Пользовательские crontab:${RESET}"
    if [[ -d /var/spool/cron/crontabs ]]; then
        local ctab
        for ctab in /var/spool/cron/crontabs/*; do
            [[ -f "$ctab" ]] && result_warn "  Пользовательский crontab: $(basename "$ctab")"
        done
    fi
}

# 15. Сетевая конфигурация
check_network() {
    section "СЕТЕВАЯ КОНФИГУРАЦИЯ"

    # Сетевые интерфейсы
    result_info "${BOLD}Сетевые интерфейсы:${RESET}"
    ip -o addr 2>/dev/null | awk '{print "    ",$2,$3,$4}' | while read -r line; do
        log "$line"
    done

    echo ""
    # Подозрительные соединения
    result_info "${BOLD}Установленные соединения:${RESET}"
    if command -v ss &>/dev/null; then
        ss -tnp state established 2>/dev/null | tail -n +2 | while read -r line; do
            log "    ${DIM}${line}${RESET}"
        done
    fi

    echo ""
    # Проверка /etc/hosts.deny и /etc/hosts.allow (TCP Wrappers)
    result_info "${BOLD}TCP Wrappers:${RESET}"
    if [[ -f /etc/hosts.allow ]]; then
        result_info "  /etc/hosts.allow:"
        grep -v "^#\|^$" /etc/hosts.allow 2>/dev/null | while read -r line; do
            log "    ${DIM}${line}${RESET}"
        done
    else
        result_warn "/etc/hosts.allow не найден"
    fi
    if [[ -f /etc/hosts.deny ]]; then
        result_info "  /etc/hosts.deny:"
        grep -v "^#\|^$" /etc/hosts.deny 2>/dev/null | while read -r line; do
            log "    ${DIM}${line}${RESET}"
        done
        if grep -q "ALL: ALL" /etc/hosts.deny 2>/dev/null; then
            result_pass "  hosts.deny содержит 'ALL: ALL' — запрет по умолчанию"
        fi
    fi
}

# 16. Криптография SSH ключей и хост-ключей
check_ssh_crypto() {
    section "КРИПТОГРАФИЯ SSH"

    local sshd_conf="/etc/ssh/sshd_config"
    [[ -f "$sshd_conf" ]] || { result_warn "SSH не установлен или конфиг не найден"; return; }
    # check_ssh_crypto может вызываться отдельно (пункт меню 3 и --ssh)
    [[ -n "$SSHD_EFFECTIVE" ]] || build_sshd_effective || return

    # Ciphers
    local ciphers
    ciphers=$(get_ssh_param_full "Ciphers")
    if [[ -n "$ciphers" ]]; then
        if echo "$ciphers" | grep -qi "3des\|blowfish\|arcfour\|cast128"; then
            result_fail "Слабые шифры в Ciphers: $ciphers"
        else
            result_pass "Ciphers: $ciphers"
        fi
    else
        result_warn "Ciphers не задан явно (используются defaults)"
    fi

    # MACs
    local macs
    macs=$(get_ssh_param_full "MACs")
    if [[ -n "$macs" ]]; then
        if echo "$macs" | grep -qi "hmac-md5\|hmac-sha1"; then
            result_fail "Слабые MAC в MACs: $macs"
        else
            result_pass "MACs: $macs"
        fi
    else
        result_warn "MACs не задан явно"
    fi

    # KexAlgorithms
    local kex
    kex=$(get_ssh_param_full "KexAlgorithms")
    if [[ -n "$kex" ]]; then
        if echo "$kex" | grep -qi "diffie-hellman-group1\|diffie-hellman-group14"; then
            result_fail "Слабые KexAlgorithms: $kex"
        else
            result_pass "KexAlgorithms: $kex"
        fi
    else
        result_warn "KexAlgorithms не заданы явно"
    fi

    # HostKey - DSA
    if grep -qi "HostKey.*ssh_host_dsa_key" <<< "$SSHD_EFFECTIVE"; then
        result_fail "Используется устаревший DSA HostKey"
    else
        result_pass "DSA HostKey не используется"
    fi
}

# ─────────────────────────── ИТОГОВЫЙ ОТЧЁТ ─────────────────────────────────

print_summary() {
    local total=$(( PASSES + WARNINGS + ISSUES ))
    local score=0
    (( total > 0 )) && score=$(( (PASSES * 100) / total ))

    log ""
    log "${BOLD}${WHITE}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    log "${BOLD}${WHITE}║                     ИТОГИ АУДИТА БЕЗОПАСНОСТИ                   ║${RESET}"
    log "${BOLD}${WHITE}╠══════════════════════════════════════════════════════════════════╣${RESET}"
    log "${BOLD}${WHITE}║${RESET}  ${GREEN}✔ Пройдено:${RESET}    ${BOLD}${GREEN}${PASSES}${RESET}"
    log "${BOLD}${WHITE}║${RESET}  ${YELLOW}⚠ Предупреждений:${RESET} ${BOLD}${YELLOW}${WARNINGS}${RESET}"
    log "${BOLD}${WHITE}║${RESET}  ${RED}✘ Проблем:${RESET}     ${BOLD}${RED}${ISSUES}${RESET}"
    log "${BOLD}${WHITE}║${RESET}  ${CYAN}Всего проверок:${RESET}  ${BOLD}${total}${RESET}"
    log "${BOLD}${WHITE}║${RESET}"

    if (( score >= 80 )); then
        log "${BOLD}${WHITE}║${RESET}  ${GREEN}${BOLD}Оценка безопасности: ${score}% — ХОРОШО${RESET}"
    elif (( score >= 60 )); then
        log "${BOLD}${WHITE}║${RESET}  ${YELLOW}${BOLD}Оценка безопасности: ${score}% — УДОВЛЕТВОРИТЕЛЬНО${RESET}"
    else
        log "${BOLD}${WHITE}║${RESET}  ${RED}${BOLD}Оценка безопасности: ${score}% — ТРЕБУЕТ ВНИМАНИЯ${RESET}"
    fi

    log "${BOLD}${WHITE}╠══════════════════════════════════════════════════════════════════╣${RESET}"
    log "${BOLD}${WHITE}║${RESET}  Полный отчёт: ${WHITE}${REPORT_FILE}${RESET}"
    log "${BOLD}${WHITE}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    log ""
}

# ─────────────────────────── МЕХАНИЗМ ИСПРАВЛЕНИЙ ───────────────────────────

# Глобальные списки: каждый элемент = "описание|||команда"
FIXES=()
FIXES_SSH=()
FIXES_FW=()
PASS_POLICY_ISSUES=0


# Категории:
#   password  — попадает в PASS_POLICY_ISSUES, реального fix-а тут нет:
#               при обнаружении проблем предлагается запустить apply_password_policy()
#               (весь безопасный движок, а не точечный sed)
#   ssh       — идёт в safe_apply_batch "ssh" (бэкап sshd_config, sshd -t, предохранитель)
#   firewall  — идёт в safe_apply_batch "firewall" (бэкап правил, предохранитель)
#   simple    — как раньше: показать команду, применить по одиночному подтверждению
add_fix() {
    local desc="$1"
    local category="$2"
    local cmd="${3:-}"   # для категории password команда не нужна — см. ниже
    case "$category" in
        password) PASS_POLICY_ISSUES=$((PASS_POLICY_ISSUES+1)) ;;
        ssh)      FIXES_SSH+=("${desc}|||${cmd}") ;;
        firewall) FIXES_FW+=("${desc}|||${cmd}") ;;
        *)        FIXES+=("${desc}|||${cmd}") ;;
    esac
}

# ══════════════════════════════════════════════════════════════════════════
# БЕЗОПАСНЫЙ ДВИЖОК ПРИМЕНЕНИЯ (обобщён из pass_polic.sh)
#
# Применяется к трём "критическим" категориям — password (PAM/парольная
# политика), ssh, firewall. Общая схема для всех трёх:
#   1) бэкап затронутых файлов/правил
#   2) сами изменения выполняются в защищённом подпроцессе с `set -e`,
#      чтобы любая упавшая команда сразу остановила применение, не оставляя
#      систему в наполовину настроенном состоянии
#   3) при ошибке — немедленный откат из бэкапа
#   4) при успехе — предохранитель: ждём подтверждения из НОВОГО сеанса
#      (что вход/sudo всё ещё работают), иначе автооткат по таймауту
#
# Категория "simple" (всё остальное: ядро, ФС, логи, cron, NTP, DNS, MAC,
# бэкдоры) через этот движок не проходит — там как раньше, разовое
# подтверждение и прямое применение без бэкапа/отката.
# ══════════════════════════════════════════════════════════════════════════

SAFE_BACKUP_DIR=""
SAFE_MARKER=""
SAFE_GUARD_PID=""
SAFE_PENDING_CATEGORY=""

# Если скрипт завершится (в т.ч. по Ctrl-C) с неподтверждёнными изменениями —
# откатываем их сами, не дожидаясь фонового сторожа.
cleanup_pending() {
    local rc=$?
    if [[ -n "$SAFE_MARKER" && -f "$SAFE_MARKER" ]]; then
        rm -f "$SAFE_MARKER" 2>/dev/null
        echo ""
        result_warn "Выход с неподтверждёнными изменениями (${SAFE_PENDING_CATEGORY}) — откатываю."
        safe_restore_backup "$SAFE_PENDING_CATEGORY"
    fi
    [[ -n "$SAFE_GUARD_PID" ]] && kill "$SAFE_GUARD_PID" 2>/dev/null
    SAFE_GUARD_PID=""
    return $rc
}
trap cleanup_pending EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

safe_tracked_files() {
    case "$1" in
        password) echo "/etc/security/pwquality.conf /etc/security/faillock.conf /etc/security/pwhistory.conf /etc/login.defs /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth" ;;
        ssh)      echo "/etc/ssh/sshd_config" ;;
        firewall) echo "" ;;
    esac
}

safe_make_backup() {
    local category="$1"
    SAFE_BACKUP_DIR="/root/security-toolkit-backup-$(date +%Y%m%d-%H%M%S)-${category}"
    if ! mkdir -p "$SAFE_BACKUP_DIR" 2>/dev/null; then
        SAFE_BACKUP_DIR="/var/tmp/security-toolkit-backup-$(date +%Y%m%d-%H%M%S)-${category}"
        mkdir -p "$SAFE_BACKUP_DIR" 2>/dev/null || { result_fail "Не удалось создать каталог бэкапа"; return 1; }
    fi
    chmod 700 "$SAFE_BACKUP_DIR" 2>/dev/null || true
    local f safe
    for f in $(safe_tracked_files "$category"); do
        [[ -e "$f" ]] || continue
        safe="${f//\//__}"
        cp -a "$f" "$SAFE_BACKUP_DIR/$safe" 2>/dev/null || true
    done
    if [[ "$category" == "firewall" ]]; then
        command -v ufw &>/dev/null && ufw status verbose > "$SAFE_BACKUP_DIR/ufw.status" 2>/dev/null
        command -v iptables-save &>/dev/null && iptables-save > "$SAFE_BACKUP_DIR/iptables.rules" 2>/dev/null
        command -v nft &>/dev/null && nft list ruleset > "$SAFE_BACKUP_DIR/nft.ruleset" 2>/dev/null
    fi
    if [[ "$category" == "password" ]] && command -v authselect &>/dev/null; then
        authselect current 2>/dev/null > "$SAFE_BACKUP_DIR/authselect.current"
    fi
    result_info "Бэкап (${category}) создан: $SAFE_BACKUP_DIR"
    return 0
}

safe_restore_backup() {
    local category="$1"
    [[ -d "$SAFE_BACKUP_DIR" ]] || return 0
    if [[ "$category" == "password" && -f "$SAFE_BACKUP_DIR/authselect.added" ]] && command -v authselect &>/dev/null; then
        while IFS= read -r feat; do
            [[ -n "$feat" ]] && authselect disable-feature "$feat" >/dev/null 2>&1
        done < "$SAFE_BACKUP_DIR/authselect.added"
        authselect apply-changes -b >/dev/null 2>&1
    fi
    local f safe
    for f in $(safe_tracked_files "$category"); do
        safe="${f//\//__}"
        [[ -e "$SAFE_BACKUP_DIR/$safe" ]] && cp -a "$SAFE_BACKUP_DIR/$safe" "$f" 2>/dev/null
    done
    if [[ "$category" == "firewall" ]]; then
        [[ -f "$SAFE_BACKUP_DIR/iptables.rules" ]] && command -v iptables-restore &>/dev/null \
            && iptables-restore < "$SAFE_BACKUP_DIR/iptables.rules" 2>/dev/null
        [[ -f "$SAFE_BACKUP_DIR/nft.ruleset" ]] && command -v nft &>/dev/null \
            && nft -f "$SAFE_BACKUP_DIR/nft.ruleset" 2>/dev/null
        [[ -f "$SAFE_BACKUP_DIR/ufw.status" ]] && result_info "Правила ufw до изменений сохранены в ${SAFE_BACKUP_DIR}/ufw.status (восстановите вручную при необходимости)"
    fi
    if [[ "$category" == "ssh" ]]; then
        systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null || true
    fi
    command -v faillock &>/dev/null && faillock --reset >/dev/null 2>&1
    result_warn "Файлы категории '${category}' восстановлены из ${SAFE_BACKUP_DIR}"
}

# Предохранитель: ждём подтверждения из НОВОГО сеанса, иначе — автооткат по таймауту.
safe_confirm_or_rollback() {
    local category="$1"
    if [[ "$DO_ROLLBACK_GUARD" -ne 1 ]]; then
        result_warn "Предохранитель отключён — изменения применены без окна отката. Бэкап: ${SAFE_BACKUP_DIR}"
        return 0
    fi
    SAFE_MARKER="$(mktemp /var/tmp/security_toolkit_pending.XXXXXX)"
    SAFE_PENDING_CATEGORY="$category"
    # БЫЛО: сторож спал ровно CONFIRM_TIMEOUT — столько же, сколько ждал `read -t`,
    # то есть срабатывал одновременно с вводом «YES» (гонка). Даём ему запас.
    local guard_timeout=$(( CONFIRM_TIMEOUT + 15 ))
    (
        sleep "$guard_timeout"
        [[ -f "$SAFE_MARKER" ]] || exit 0
        {
            echo "[$(date)] АВТО-ОТКАТ (${category}): подтверждение не получено за ${guard_timeout}с"
            # БЫЛО: в bash -c передавались только safe_* функции, а они зовут
            # result_warn/result_info — в фоновой оболочке их не было, откат
            # сыпал «command not found». Подкладываем заглушки.
            SAFE_BACKUP_DIR="$SAFE_BACKUP_DIR" bash -c "
                result_pass() { echo \"[pass] \$*\"; }
                result_fail() { echo \"[fail] \$*\"; }
                result_warn() { echo \"[warn] \$*\"; }
                result_info() { echo \"[info] \$*\"; }
                $(declare -f safe_tracked_files safe_restore_backup)
                safe_restore_backup '${category}'
            "
        } >> /var/log/security_toolkit_autorollback.log 2>&1
        rm -f "$SAFE_MARKER" 2>/dev/null
    ) &
    SAFE_GUARD_PID=$!
    disown "$SAFE_GUARD_PID" 2>/dev/null || true

    echo ""
    echo -e "${RED}${BOLD}============================ ВАЖНО ============================${RESET}"
    echo -e "${YELLOW}Изменения (${category}) применены, но ЕЩЁ НЕ ЗАФИКСИРОВАНЫ.${RESET}"
    echo "  1) Откройте НОВОЕ SSH-подключение к серверу, не закрывая текущее."
    echo "  2) Убедитесь, что вход и sudo всё ещё работают."
    echo "  3) Вернитесь сюда и подтвердите."
    echo ""
    echo -e "У вас ${YELLOW}${CONFIRM_TIMEOUT} сек${RESET}. Иначе — автоматический откат из ${SAFE_BACKUP_DIR}."
    echo -e "${RED}=================================================================${RESET}"

    local answer=""
    read -r -t "$CONFIRM_TIMEOUT" -p "Введите YES для фиксации: " answer </dev/tty
    # Снимаем «неподтверждённое» состояние до любых действий, чтобы ни сторож,
    # ни trap не откатили уже принятое решение.
    rm -f "$SAFE_MARKER" 2>/dev/null
    kill "$SAFE_GUARD_PID" >/dev/null 2>&1
    SAFE_GUARD_PID=""
    SAFE_MARKER=""
    if [[ "${answer^^}" == "YES" ]]; then
        result_pass "Изменения (${category}) зафиксированы. Бэкап сохранён в ${SAFE_BACKUP_DIR}"
        return 0
    else
        echo ""
        result_warn "Подтверждение не получено — откатываю немедленно."
        safe_restore_backup "$category"
        return 1
    fi
}

# ── Помощники специально для password/PAM-модуля ──
pam_module_exists() {
    find /lib /lib64 /usr/lib /usr/lib64 -name "$1" 2>/dev/null | grep -q .
}

is_simple_faillock_wrappable() {
    [[ -f "$1" ]] && grep -Eq '^auth[[:space:]]+\[success=1 default=ignore\][[:space:]]+pam_unix\.so' "$1"
}

detect_os_family() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        if [[ "${ID_LIKE:-}" =~ (debian|ubuntu) || "${ID:-}" =~ ^(debian|ubuntu|astra)$ ]]; then
            echo "debian"
        elif [[ "${ID_LIKE:-}" =~ (rhel|fedora) || "${ID:-}" =~ ^(centos|rhel|rocky|almalinux|fedora)$ ]]; then
            echo "rhel"
        else
            echo "unknown"
        fi
    else
        echo "unknown"
    fi
}

authselect_feature_enabled() {
    authselect current 2>/dev/null | grep -qE "^[[:space:]]*-[[:space:]]+${1}[[:space:]]*$"
}

# Все мутирующие шаги парольной/PAM-политики. Выполняется в защищённом
# подпроцессе с `set -e` — см. apply_password_policy().
apply_password_policy_body() {
    local os_family="$1"
    local fail_unlock_seconds=$(( FAIL_UNLOCK_MINUTES * 60 ))

    if [[ "$os_family" == "debian" ]]; then
        apt-get update -qq || result_warn "Часть репозиториев недоступна — продолжаю с имеющимися списками"
        apt-get install -y -qq libpam-pwquality libpam-modules pamtester \
            || result_warn "Не все пакеты установлены (проверьте libpam-pwquality/libpam-modules)"
    else
        dnf install -y libpwquality pam authselect >/dev/null || result_warn "dnf install завершился с предупреждением"
        dnf install -y pamtester >/dev/null 2>&1 || true
    fi

    cat > /etc/security/pwquality.conf <<EOF
minlen = ${MIN_PASS_LEN}
lcredit = -1
ucredit = -1
dcredit = -1
ocredit = -1
difok = 3
retry = 3
maxrepeat = 2
usercheck = 1
dictcheck = 1
enforce_for_root
EOF
    result_pass "pwquality.conf записан (minlen=${MIN_PASS_LEN})"

    cat > /etc/security/faillock.conf <<EOF
# Управляется security_toolkit.sh
deny = ${FAIL_DENY}
unlock_time = ${fail_unlock_seconds}
fail_interval = 900
silent
EOF
    result_pass "faillock.conf записан (deny=${FAIL_DENY}, unlock_time=${fail_unlock_seconds})"

    if [[ "$os_family" == "rhel" ]]; then
        local cur_profile
        cur_profile="$(authselect current 2>/dev/null | awk -F': ' '/Profile/{print $2; exit}')"
        if [[ -z "$cur_profile" ]]; then
            result_warn "authselect: активный профиль не найден — faillock/pwhistory в auth-стек не включаю (риск сломать SSSD/AD)"
        else
            result_info "Активный профиль authselect: ${cur_profile}"
            local feat
            for feat in with-faillock with-pwhistory; do
                if authselect_feature_enabled "$feat"; then
                    result_info "authselect: ${feat} уже был включён — оставляю как есть"
                    continue
                fi
                authselect enable-feature "$feat"
                echo "$feat" >> "$SAFE_BACKUP_DIR/authselect.added"
            done
            authselect apply-changes -b
            result_pass "authselect: применены изменения (with-faillock/with-pwhistory)"
        fi
        if [[ -f /etc/security/pwhistory.conf ]]; then
            sed -i '/^[[:space:]]*remember/d' /etc/security/pwhistory.conf
        fi
        echo "remember = ${PASS_HISTORY}" >> /etc/security/pwhistory.conf
        result_pass "pwhistory.conf: remember=${PASS_HISTORY}"
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
            sed -i "/^password[[:space:]].*pam_unix\.so/i password requisite pam_pwhistory.so remember=${PASS_HISTORY} use_authtok" "$common_password"
            result_pass "pam_pwhistory добавлен (remember=${PASS_HISTORY})"
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
            cp -a "$wrap_tmp" "$common_auth"; rm -f "$wrap_tmp"
            if [[ -f "$common_account" ]]; then
                sed -i '/pam_faillock\.so/d' "$common_account"
                echo "account required pam_faillock.so" >> "$common_account"
            fi
            result_pass "faillock настроен в $common_auth (+account в $common_account)"
        fi
    fi

    local user uid shell
    while IFS=: read -r user _ uid _ _ _ shell; do
        [[ "$user" == "root" || "$user" == "nobody" ]] && continue
        case "$shell" in *nologin|*false|*sync|*shutdown|*halt) continue ;; esac
        is_num "$uid" || continue
        (( uid >= UID_MIN )) || continue
        chage -M "$PASS_MAX_AGE" -m "$PASS_MIN_AGE" -W "$PASS_WARN_AGE" "$user" \
            || result_warn "chage не применился для $user (пропускаю)"
    done < /etc/passwd
    result_pass "Старение паролей применено (UID >= ${UID_MIN})"

    if [[ -f /etc/login.defs ]]; then
        sed -i '/^PASS_MAX_DAYS/d; /^PASS_MIN_DAYS/d; /^PASS_WARN_AGE/d' /etc/login.defs
        {
            echo ""
            echo "# Password aging (security_toolkit.sh)"
            echo "PASS_MAX_DAYS   ${PASS_MAX_AGE}"
            echo "PASS_MIN_DAYS   ${PASS_MIN_AGE}"
            echo "PASS_WARN_AGE   ${PASS_WARN_AGE}"
        } >> /etc/login.defs
        result_pass "login.defs обновлён"
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
    if command -v pamtester &>/dev/null; then
        if pamtester -v login "$(id -un)" account >/dev/null 2>&1; then
            result_pass "pamtester: базовая проверка account-фазы прошла"
        else
            result_warn "pamtester: account-фаза вернула ошибку — проверьте стек вручную"
        fi
    fi
    [[ "$pam_ok" -eq 1 ]]
}

# Точка входа: полноценный безопасный модуль парольной/PAM-политики,
# использует пороги, уже собранные в interactive_setup()
# (MIN_PASS_LEN, PASS_HISTORY, FAIL_DENY, FAIL_UNLOCK_MINUTES,
#  PASS_MAX_AGE, PASS_MIN_AGE, PASS_WARN_AGE, UID_MIN).
apply_password_policy() {
    if [[ $EUID -ne 0 ]]; then
        result_warn "Для применения парольной/PAM-политики нужен root. Запустите через sudo."
        return 1
    fi

    echo ""
    log "${BOLD}${MAGENTA}══════════ Безопасное применение парольной/PAM-политики ══════════${RESET}"
    log "  minlen=${MIN_PASS_LEN}  remember=${PASS_HISTORY}  deny=${FAIL_DENY}  unlock=${FAIL_UNLOCK_MINUTES}мин"
    log "  PASS_MAX_DAYS=${PASS_MAX_AGE}  PASS_MIN_DAYS=${PASS_MIN_AGE}  PASS_WARN_AGE=${PASS_WARN_AGE}  UID_MIN=${UID_MIN}"

    if (( PASS_MIN_AGE >= PASS_MAX_AGE )); then
        result_fail "PASS_MIN_AGE (${PASS_MIN_AGE}) не может быть >= PASS_MAX_AGE (${PASS_MAX_AGE}) — отменено"
        return 1
    fi
    if ! confirm "Применить парольную/PAM-политику с этими параметрами (бэкап + окно отката ${CONFIRM_TIMEOUT}с)?" n; then
        result_info "Отменено пользователем."
        return 0
    fi

    local os_family
    os_family="$(detect_os_family)"
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

# Все мутирующие шаги для категорий ssh/firewall — список команд из
# add_fix(), выполняется в защищённом подпроцессе с `set -e`.
safe_apply_batch_body() {
    local -n fixes_ref="$1"
    local entry desc cmd
    for entry in "${fixes_ref[@]}"; do
        desc="${entry%%|||*}"; cmd="${entry##*|||}"
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
    local entry
    for entry in "${fixes_ref[@]}"; do
        log "  • ${entry%%|||*}"
    done
    if ! confirm "Применить все ${#fixes_ref[@]} исправлений категории '${category}' (бэкап + окно отката ${CONFIRM_TIMEOUT}с)?" n; then
        result_info "Отменено пользователем."
        return 0
    fi

    safe_make_backup "$category" || return 1

    ( set -e -o pipefail; safe_apply_batch_body "$arrname" )
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        result_fail "Ошибка применения (${category}) — откатываю."
        safe_restore_backup "$category"
        return 1
    fi

    if [[ "$category" == "ssh" ]]; then
        local sshd_bin="" b
        for b in /usr/sbin/sshd /sbin/sshd "$(command -v sshd 2>/dev/null || true)"; do
            [[ -n "$b" && -x "$b" ]] && { sshd_bin="$b"; break; }
        done
        if [[ -n "$sshd_bin" ]] && ! "$sshd_bin" -t 2>/tmp/security_toolkit_sshd_test; then
            result_fail "sshd -t не прошла проверку: $(cat /tmp/security_toolkit_sshd_test 2>/dev/null)"
            rm -f /tmp/security_toolkit_sshd_test
            safe_restore_backup "ssh"
            return 1
        fi
        rm -f /tmp/security_toolkit_sshd_test
        systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null || true
        result_pass "sshd -t пройдена, конфигурация перезагружена"
    fi

    safe_confirm_or_rollback "$category"
}

# Диспетчер: разводит найденные проблемы по трём сценариям —
#  1) password/PAM — полноценный безопасный модуль apply_password_policy()
#  2) ssh / firewall — safe_apply_batch() с бэкапом и окном отката
#  3) всё остальное ("simple") — как раньше, разовое подтверждение на каждую правку
offer_remediation() {
    if (( PASS_POLICY_ISSUES == 0 && ${#FIXES_SSH[@]} == 0 && ${#FIXES_FW[@]} == 0 && ${#FIXES[@]} == 0 )); then
        return
    fi

    if [[ $EUID -ne 0 ]]; then
        echo ""
        log "${YELLOW}${BOLD}⚠ Для применения исправлений требуется root.${RESET}"
        log "  Запустите скрипт через: ${WHITE}sudo $0${RESET}"
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
    safe_apply_batch "firewall" FIXES_FW

    simple_remediation
}

# Старое поведение: показать команду, применить по одиночному подтверждению,
# без бэкапа/отката. Используется для категорий, не относящихся к
# password/ssh/firewall (ядро, ФС, логирование, cron, NTP, DNS, MAC, бэкдоры).
simple_remediation() {
    [[ ${#FIXES[@]} -eq 0 ]] && return

    echo ""
    log "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    log "${BOLD}${MAGENTA}║           🔧  АВТОМАТИЧЕСКОЕ ИСПРАВЛЕНИЕ ПРОБЛЕМ  🔧             ║${RESET}"
    log "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    log ""
    log "  Найдено ${#FIXES[@]} исправлений. Каждое требует вашего подтверждения."
    log ""

    local applied=0
    local skipped=0
    local failed=0

    for entry in "${FIXES[@]}"; do
        local desc="${entry%%|||*}"
        local cmd="${entry##*|||}"

        echo ""
        echo -e "${CYAN}${BOLD}┌─ Исправление ─────────────────────────────────────────────────${RESET}"
        echo -e "${CYAN}│${RESET} ${WHITE}${desc}${RESET}"
        echo -e "${CYAN}│${RESET} ${DIM}Команда: ${cmd}${RESET}"
        echo -e "${CYAN}└───────────────────────────────────────────────────────────────${RESET}"

        printf "%b" "${YELLOW}  Применить? [y/N/q(выход)]: ${RESET}" >/dev/tty
        local ans
        read -r ans </dev/tty
        ans="${ans//[[:space:]]/}"

        case "${ans,,}" in
            y|yes|д|да)
                echo -e "  ${DIM}Выполняю: ${cmd}${RESET}"
                if eval "$cmd" >> "$REPORT_FILE" 2>&1; then
                    echo -e "  ${GREEN}${BOLD}✔ Применено успешно${RESET}"
                    log "  [REMEDIATION OK] ${desc}"
                    applied=$((applied+1))
                else
                    echo -e "  ${RED}${BOLD}✘ Ошибка при выполнении${RESET}"
                    log "  [REMEDIATION FAIL] ${desc}"
                    failed=$((failed+1))
                fi
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

    if (( applied > 0 )); then
        echo ""
        echo -e "  ${YELLOW}${BOLD}⚠ Рекомендуется перезапустить затронутые сервисы и повторить аудит.${RESET}"
    fi
}

# 17. NTP — синхронизация времени
check_ntp() {
    section "NTP — СИНХРОНИЗАЦИЯ ВРЕМЕНИ"

    # ── Определяем активный NTP-демон ────────────────────────────────────────
    result_info "${BOLD}Статус NTP-сервиса:${RESET}"

    # systemd-timesyncd
    if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        result_pass "systemd-timesyncd активен"
        local tsd_status
        tsd_status=$(timedatectl show-timesync --value --property=ServerName 2>/dev/null || \
                     timedatectl timesync-status 2>/dev/null | head -5)
        [[ -n "$tsd_status" ]] && result_info "  Текущий сервер: ${tsd_status}"

        # Проверяем /etc/systemd/timesyncd.conf
        local tsd_conf="/etc/systemd/timesyncd.conf"
        if [[ -f "$tsd_conf" ]]; then
            local ntp_servers
            ntp_servers=$(grep -E "^\s*NTP=" "$tsd_conf" 2>/dev/null | head -1)
            local fallback
            fallback=$(grep -E "^\s*FallbackNTP=" "$tsd_conf" 2>/dev/null | head -1)
            if [[ -n "$ntp_servers" ]]; then
                result_pass "NTP серверы заданы: ${ntp_servers}"
            else
                result_warn "NTP= не задан в timesyncd.conf — используются серверы дистрибутива"
            fi
            if [[ -n "$fallback" ]]; then
                result_pass "Резервные NTP серверы: ${fallback}"
            else
                result_warn "FallbackNTP= не задан — нет резервных серверов"
                add_fix "Добавить резервные NTP серверы в timesyncd.conf" "simple" \
                    "grep -q '^FallbackNTP' /etc/systemd/timesyncd.conf && \
                     sed -i 's/^FallbackNTP.*/FallbackNTP=0.pool.ntp.org 1.pool.ntp.org/' /etc/systemd/timesyncd.conf || \
                     echo 'FallbackNTP=0.pool.ntp.org 1.pool.ntp.org' >> /etc/systemd/timesyncd.conf"
            fi
        fi

    elif systemctl is-active --quiet chrony 2>/dev/null || \
         systemctl is-active --quiet chronyd 2>/dev/null; then
        result_pass "chrony активен"
        if command -v chronyc &>/dev/null; then
            local tracking
            tracking=$(chronyc tracking 2>/dev/null | grep -E "Reference ID|System time|Stratum")
            while read -r line; do
                result_info "  ${line}"
            done <<< "$tracking"
            # Источники
            result_info "${BOLD}  Источники chrony:${RESET}"
            chronyc sources 2>/dev/null | grep -E "^\^" | while read -r src; do
                log "    ${DIM}${src}${RESET}"
            done
        fi

    elif systemctl is-active --quiet ntp 2>/dev/null || \
         systemctl is-active --quiet ntpd 2>/dev/null; then
        result_pass "ntpd активен"
        if command -v ntpq &>/dev/null; then
            result_info "${BOLD}  Пиры ntpq:${RESET}"
            ntpq -p 2>/dev/null | while read -r line; do
                log "    ${DIM}${line}${RESET}"
            done
        fi

    else
        result_fail "Ни один NTP-демон не запущен (timesyncd / chrony / ntpd)"
        add_fix "Включить systemd-timesyncd (синхронизация времени)" "simple" \
            "systemctl enable --now systemd-timesyncd"
    fi

    # ── Проверяем что NTP включён через timedatectl ──────────────────────────
    echo ""
    result_info "${BOLD}Синхронизация через timedatectl:${RESET}"
    if command -v timedatectl &>/dev/null; then
        local ntp_active
        ntp_active=$(timedatectl show --value --property=NTP 2>/dev/null || \
                     timedatectl status 2>/dev/null | grep "NTP" | awk '{print $NF}')
        local synced
        synced=$(timedatectl show --value --property=NTPSynchronized 2>/dev/null || \
                 timedatectl status 2>/dev/null | grep "synchronized" | awk '{print $NF}')
        local tz
        tz=$(timedatectl show --value --property=Timezone 2>/dev/null || \
             timedatectl status 2>/dev/null | grep "zone" | awk '{print $3}')

        if [[ "${ntp_active,,}" == "yes" || "${ntp_active,,}" == "true" ]]; then
            result_pass "NTP включён (timedatectl NTP=yes)"
        else
            result_fail "NTP отключён в timedatectl"
            add_fix "Включить NTP синхронизацию" "simple" "timedatectl set-ntp true"
        fi

        if [[ "${synced,,}" == "yes" || "${synced,,}" == "true" ]]; then
            result_pass "Время синхронизировано (NTPSynchronized=yes)"
        else
            result_warn "Время ещё не синхронизировано"
        fi

        [[ -n "$tz" ]] && result_info "  Часовой пояс: ${tz}"
    else
        result_warn "timedatectl недоступен"
    fi

    # ── Проверка точности времени (drift) ────────────────────────────────────
    echo ""
    result_info "${BOLD}Смещение времени (drift):${RESET}"
    if command -v chronyc &>/dev/null && ( systemctl is-active --quiet chrony 2>/dev/null || \
       systemctl is-active --quiet chronyd 2>/dev/null ); then
        local offset
        offset=$(chronyc tracking 2>/dev/null | grep "System time" | grep -oP '[\d.]+(?= seconds)')
        if [[ -n "$offset" ]]; then
            # Сравниваем с порогом 1 секунда
            local ok
            ok=$(awk "BEGIN {print ($offset < 1.0) ? 1 : 0}")
            if (( ok == 1 )); then
                result_pass "Смещение времени: ${offset}s (< 1s — норма)"
            else
                result_warn "Смещение времени: ${offset}s (> 1s — возможны проблемы с Kerberos/TLS)"
            fi
        fi
    elif command -v ntpq &>/dev/null && systemctl is-active --quiet ntpd 2>/dev/null; then
        local offset
        offset=$(ntpq -p 2>/dev/null | awk 'NR>2 && /^\*/{print $9}' | head -1)
        [[ -n "$offset" ]] && result_info "  ntpq offset: ${offset}ms"
    else
        result_info "Проверка drift недоступна (требуется chronyc или ntpq)"
    fi

    # ── Stratum ───────────────────────────────────────────────────────────────
    echo ""
    result_info "${BOLD}Stratum (уровень синхронизации):${RESET}"
    if command -v chronyc &>/dev/null && ( systemctl is-active --quiet chrony 2>/dev/null || \
       systemctl is-active --quiet chronyd 2>/dev/null ); then
        local stratum
        stratum=$(chronyc tracking 2>/dev/null | grep "Stratum" | awk '{print $3}')
        if is_num "$stratum"; then
            if (( stratum <= 3 )); then
                result_pass "Stratum: ${stratum} (хорошо — близко к атомным часам)"
            elif (( stratum <= 5 )); then
                result_warn "Stratum: ${stratum} (допустимо, но не идеально)"
            else
                result_fail "Stratum: ${stratum} (слишком далеко от источника точного времени)"
            fi
        fi
    elif command -v timedatectl &>/dev/null; then
        local stratum
        stratum=$(timedatectl timesync-status 2>/dev/null | grep -i "Stratum" | awk '{print $2}')
        if is_num "$stratum"; then
            if (( stratum <= 3 )); then
                result_pass "Stratum: ${stratum}"
            else
                result_warn "Stratum: ${stratum} (рекомендуется ≤ 3)"
            fi
        fi
    fi

    # ── NTP порт открыт наружу? ───────────────────────────────────────────────
    echo ""
    result_info "${BOLD}NTP порт 123 (UDP):${RESET}"
    if command -v ss &>/dev/null; then
        local ntp_listen
        ntp_listen=$(ss -ulnp 2>/dev/null | grep ":123 ")
        if [[ -n "$ntp_listen" ]]; then
            # Смотрим — слушает на 0.0.0.0 (опасно для публичных серверов) или только lo
            if echo "$ntp_listen" | grep -qE "0\.0\.0\.0:123|:::123|\*:123"; then
                result_warn "NTP порт 123 открыт на всех интерфейсах (сервер может быть использован для amplification-атак)"
                add_fix "Ограничить NTP только localhost если сервер не является NTP-сервером" "simple" \
                    "echo 'Настройте bindaddress в /etc/chrony.conf или /etc/ntp.conf'"
            else
                result_pass "NTP порт 123 слушает только на локальных интерфейсах"
            fi
        else
            result_info "NTP порт 123 не слушает (клиентский режим — норма)"
        fi
    fi

    # ── Конфигурация chrony — безопасность ───────────────────────────────────
    echo ""
    for chrony_conf in /etc/chrony.conf /etc/chrony/chrony.conf; do
        [[ -f "$chrony_conf" ]] || continue
        result_info "${BOLD}Безопасность chrony (${chrony_conf}):${RESET}"

        # cmdallow — кто может управлять chronyc
        if grep -qE "^\s*cmdallow" "$chrony_conf" 2>/dev/null; then
            local cmdallow
            cmdallow=$(grep -E "^\s*cmdallow" "$chrony_conf" | head -1)
            if echo "$cmdallow" | grep -qE "cmdallow\s+all|0\.0\.0\.0"; then
                result_fail "cmdallow all — управление chrony доступно отовсюду!"
            else
                result_pass "cmdallow ограничен: ${cmdallow}"
            fi
        fi

        # makestep — коррекция большого drift
        if grep -qE "^\s*makestep" "$chrony_conf" 2>/dev/null; then
            result_pass "makestep настроен (корректировка больших смещений)"
        else
            result_warn "makestep не настроен в chrony.conf"
        fi

        # Количество серверов
        local srv_count
        srv_count=$(grep -cE "^\s*(server|pool|peer)" "$chrony_conf" 2>/dev/null)
        srv_count="${srv_count:-0}"
        if (( srv_count >= 3 )); then
            result_pass "Источников NTP: ${srv_count} (≥ 3 — хорошо для отказоустойчивости)"
        elif (( srv_count >= 1 )); then
            result_warn "Источников NTP: ${srv_count} (рекомендуется ≥ 3)"
        else
            result_fail "Источники NTP не настроены в ${chrony_conf}"
        fi
    done
}

# 18. DNS — конфигурация и безопасность
check_dns() {
    section "DNS — КОНФИГУРАЦИЯ И БЕЗОПАСНОСТЬ"

    # ── Текущие DNS-серверы ───────────────────────────────────────────────────
    result_info "${BOLD}Настроенные DNS-серверы:${RESET}"

    local dns_servers=()

    # systemd-resolved
    if command -v resolvectl &>/dev/null; then
        result_info "  ${DIM}(через systemd-resolved / resolvectl)${RESET}"
        local res_dns
        res_dns=$(resolvectl status 2>/dev/null | grep "DNS Servers" | sed 's/.*DNS Servers: //' | head -3)
        while read -r srv; do
            [[ -z "$srv" ]] && continue
            for ip in $srv; do
                dns_servers+=("$ip")
                result_info "  DNS: ${WHITE}${ip}${RESET}"
            done
        done <<< "$res_dns"
    fi

    # /etc/resolv.conf
    if [[ -f /etc/resolv.conf ]]; then
        result_info "  ${DIM}(/etc/resolv.conf)${RESET}"
        while read -r line; do
            if [[ "$line" =~ ^nameserver ]]; then
                local ip="${line#nameserver }"
                ip="${ip// /}"
                dns_servers+=("$ip")
                result_info "  nameserver: ${WHITE}${ip}${RESET}"
            fi
        done < /etc/resolv.conf
    fi

    if [[ ${#dns_servers[@]} -eq 0 ]]; then
        result_fail "DNS-серверы не обнаружены"
    fi

    # ── Классификация DNS-серверов ────────────────────────────────────────────
    echo ""
    result_info "${BOLD}Анализ DNS-серверов:${RESET}"

    # Известные публичные DNS
    declare -A known_dns=(
        ["8.8.8.8"]="Google DNS"          ["8.8.4.4"]="Google DNS"
        ["1.1.1.1"]="Cloudflare DNS"      ["1.0.0.1"]="Cloudflare DNS"
        ["9.9.9.9"]="Quad9 (фильтрация)" ["149.112.112.112"]="Quad9"
        ["208.67.222.222"]="OpenDNS"      ["208.67.220.220"]="OpenDNS"
        ["77.88.8.8"]="Yandex DNS"        ["77.88.8.1"]="Yandex DNS"
        ["94.140.14.14"]="AdGuard DNS"    ["94.140.15.15"]="AdGuard DNS"
        ["176.103.130.130"]="AdGuard DNS" ["185.228.168.9"]="CleanBrowsing"
        ["127.0.0.1"]="localhost"         ["127.0.0.53"]="systemd-resolved (stub)"
        ["::1"]="localhost IPv6"
    )

    local has_public=0
    local has_internal=0
    local seen_servers=()

    for ip in "${dns_servers[@]}"; do
        # Дедупликация
        local dup=0
        for s in ${seen_servers[@]+"${seen_servers[@]}"}; do [[ "$s" == "$ip" ]] && dup=1 && break; done
        (( dup == 1 )) && continue
        seen_servers+=("$ip")

        local label="${known_dns[$ip]:-}"
        if [[ -n "$label" ]]; then
            if [[ "$label" == "localhost"* || "$label" == "systemd-resolved"* ]]; then
                result_pass "  ${ip} — ${label}"
            else
                result_warn "  ${ip} — ${label} ${DIM}(публичный DNS — трафик уходит наружу)${RESET}"
                has_public=1
            fi
        elif [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
            result_pass "  ${ip} — внутренний DNS-сервер ${DIM}(приватная сеть)${RESET}"
            has_internal=1
        elif [[ "$ip" =~ ^(127\.|::1$|fe80:) ]]; then
            result_pass "  ${ip} — локальный резолвер"
        else
            result_warn "  ${ip} — неизвестный DNS-сервер"
        fi
    done

    (( has_public == 1 )) && result_warn "Используется публичный DNS — все DNS-запросы видны провайдеру сервиса"
    (( has_public == 1 && has_internal == 1 )) && \
        result_warn "Смешаны внутренний и публичный DNS — внутренние имена могут утекать наружу"

    # ── /etc/resolv.conf — безопасность ──────────────────────────────────────
    echo ""
    result_info "${BOLD}Безопасность /etc/resolv.conf:${RESET}"
    if [[ -f /etc/resolv.conf ]]; then
        local resolv_perm
        resolv_perm=$(stat -c "%a %U %G" /etc/resolv.conf 2>/dev/null)
        local resolv_mode
        resolv_mode=$(stat -c "%a" /etc/resolv.conf 2>/dev/null)

        result_info "  Права: ${resolv_perm}"
        if [[ "$resolv_mode" =~ ^[64][04][04]$ ]]; then
            result_pass "  Права /etc/resolv.conf в норме (${resolv_mode})"
        else
            result_warn "  Нестандартные права /etc/resolv.conf: ${resolv_mode}"
        fi

        # Проверяем что файл не world-writable
        local o_write
        o_write=$(stat -c "%A" /etc/resolv.conf 2>/dev/null | cut -c9)
        if [[ "$o_write" == "w" ]]; then
            result_fail "/etc/resolv.conf доступен для записи всем пользователям!"
            add_fix "Убрать world-write с /etc/resolv.conf" "simple" \
                "chmod o-w /etc/resolv.conf"
        fi

        # Симлинк?
        if [[ -L /etc/resolv.conf ]]; then
            local target
            target=$(readlink -f /etc/resolv.conf 2>/dev/null)
            result_info "  /etc/resolv.conf — симлинк → ${target}"
            if echo "$target" | grep -q "systemd\|resolvectl\|resolved"; then
                result_pass "  Управляется systemd-resolved (норма)"
            elif echo "$target" | grep -q "NetworkManager"; then
                result_pass "  Управляется NetworkManager (норма)"
            else
                result_warn "  Нестандартный симлинк: → ${target}"
            fi
        fi

        # Опции безопасности
        result_info "${BOLD}  Опции resolv.conf:${RESET}"
        local options_line
        options_line=$(grep -E "^\s*options" /etc/resolv.conf 2>/dev/null | head -1)
        if [[ -n "$options_line" ]]; then
            result_info "  ${options_line}"
            # ndots — влияет на безопасность (SSRF через DNS)
            if echo "$options_line" | grep -oP "ndots:\K[0-9]+" | grep -qE "^[6-9]$|^[0-9]{2,}"; then
                result_warn "  ndots слишком высокий — возможны утечки внутренних имён во внешний DNS"
            fi
        fi

        # search / domain — утечка внутренних доменов
        local search_line
        search_line=$(grep -E "^\s*(search|domain)" /etc/resolv.conf 2>/dev/null)
        if [[ -n "$search_line" ]]; then
            result_info "  Домены поиска: ${search_line}"
        fi
    fi

    # ── systemd-resolved — конфигурация ──────────────────────────────────────
    echo ""
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        result_info "${BOLD}systemd-resolved:${RESET}"
        result_pass "systemd-resolved активен"

        local resolved_conf="/etc/systemd/resolved.conf"
        if [[ -f "$resolved_conf" ]]; then
            # DNSSEC
            local dnssec
            dnssec=$(grep -E "^\s*DNSSEC=" "$resolved_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
            if [[ -z "$dnssec" ]]; then
                dnssec=$(resolvectl status 2>/dev/null | grep -i "DNSSEC" | awk '{print $NF}' | head -1)
            fi
            if [[ "${dnssec,,}" == "yes" || "${dnssec,,}" == "true" || "${dnssec,,}" == "allow-downgrade" ]]; then
                result_pass "DNSSEC: ${dnssec} (проверка подписи DNS включена)"
            elif [[ "${dnssec,,}" == "no" || -z "$dnssec" ]]; then
                result_warn "DNSSEC отключён — DNS-ответы не проверяются на подлинность"
                add_fix "Включить DNSSEC в systemd-resolved" "simple" \
                    "grep -q '^DNSSEC' /etc/systemd/resolved.conf && \
                     sed -i 's/^DNSSEC.*/DNSSEC=allow-downgrade/' /etc/systemd/resolved.conf || \
                     echo 'DNSSEC=allow-downgrade' >> /etc/systemd/resolved.conf; \
                     systemctl restart systemd-resolved"
            fi

            # DNSOverTLS
            local dot
            dot=$(grep -E "^\s*DNSOverTLS=" "$resolved_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
            if [[ "${dot,,}" == "yes" || "${dot,,}" == "opportunistic" ]]; then
                result_pass "DNS-over-TLS: ${dot} (шифрование DNS запросов)"
            else
                result_warn "DNS-over-TLS не включён — DNS запросы передаются в открытом виде"
                add_fix "Включить DNS-over-TLS в systemd-resolved" "simple" \
                    "grep -q '^DNSOverTLS' /etc/systemd/resolved.conf && \
                     sed -i 's/^DNSOverTLS.*/DNSOverTLS=opportunistic/' /etc/systemd/resolved.conf || \
                     echo 'DNSOverTLS=opportunistic' >> /etc/systemd/resolved.conf; \
                     systemctl restart systemd-resolved"
            fi

            # Cache
            local cache
            cache=$(grep -E "^\s*Cache=" "$resolved_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
            if [[ "${cache,,}" == "no" ]]; then
                result_warn "DNS кеш отключён — снижает производительность"
            elif [[ "${cache,,}" == "no-negative" ]]; then
                result_warn "DNS кеш не кеширует отрицательные ответы (no-negative)"
            else
                result_pass "DNS кеш: ${cache:-yes (по умолчанию)}"
            fi
        fi
    fi

    # ── Проверка DNS-резолвинга ───────────────────────────────────────────────
    echo ""
    result_info "${BOLD}Проверка DNS-резолвинга:${RESET}"
    local test_domains=("google.com" "cloudflare.com" "example.com")
    local dns_working=0
    for domain in "${test_domains[@]}"; do
        if command -v dig &>/dev/null; then
            local ans
            ans=$(dig +short +timeout=3 +tries=1 "$domain" A 2>/dev/null | head -1)
            if [[ -n "$ans" ]]; then
                result_pass "  Резолвинг ${domain} → ${ans}"
                dns_working=1
                break
            fi
        elif command -v nslookup &>/dev/null; then
            if nslookup "$domain" &>/dev/null 2>&1; then
                result_pass "  Резолвинг ${domain} работает (nslookup)"
                dns_working=1
                break
            fi
        elif command -v getent &>/dev/null; then
            if getent hosts "$domain" &>/dev/null 2>&1; then
                result_pass "  Резолвинг ${domain} работает (getent)"
                dns_working=1
                break
            fi
        fi
    done
    (( dns_working == 0 )) && result_fail "DNS-резолвинг не работает или инструменты недоступны"

    # ── Проверка на DNS-спуфинг в /etc/hosts ─────────────────────────────────
    echo ""
    result_info "${BOLD}Подмена популярных доменов в /etc/hosts:${RESET}"
    local spoof_domains=("google.com" "github.com" "pypi.org" "npmjs.com"
                         "apt.releases.hashicorp.com" "registry.npmjs.org"
                         "registry-1.docker.io" "auth.docker.io"
                         "update.microsoft.com" "windowsupdate.com")
    local spoof_found=0
    for d in "${spoof_domains[@]}"; do
        if grep -qE "^\s*[0-9a-f:]+\s+.*${d}" /etc/hosts 2>/dev/null; then
            local spoof_line
            spoof_line=$(grep -E "^\s*[0-9a-f:]+\s+.*${d}" /etc/hosts | head -1)
            result_fail "Возможный DNS-спуфинг в /etc/hosts: ${spoof_line}"
            spoof_found=$((spoof_found+1))
        fi
    done
    (( spoof_found == 0 )) && result_pass "Подмены популярных доменов в /etc/hosts не обнаружено"

    # ── DNSSEC — прямая проверка резолвера ───────────────────────────────────
    echo ""
    result_info "${BOLD}DNSSEC — проверка резолвера:${RESET}"
    if command -v dig &>/dev/null; then
        # Проверяем что резолвер проверяет DNSSEC (dnssec-failed.org должен НЕ резолвиться)
        local dnssec_fail
        dnssec_fail=$(dig +short +timeout=3 +tries=1 dnssec-failed.org A 2>/dev/null)
        if [[ -z "$dnssec_fail" ]]; then
            result_pass "DNSSEC работает: dnssec-failed.org не резолвится (валидация активна)"
        else
            result_warn "DNSSEC не валидирует: dnssec-failed.org резолвится (${dnssec_fail})"
        fi

        # Проверяем что корректный DNSSEC-домен резолвится
        local dnssec_ok
        dnssec_ok=$(dig +short +timeout=3 +tries=1 dnssec-tools.org A 2>/dev/null | head -1)
        if [[ -n "$dnssec_ok" ]]; then
            result_pass "DNSSEC-домен dnssec-tools.org резолвится корректно"
        fi
    else
        result_info "dig не установлен — пропуск DNSSEC-проверки"
    fi

    # ── Утечки DNS через stub-resolver ───────────────────────────────────────
    echo ""
    result_info "${BOLD}Stub-резолвер:${RESET}"
    if grep -q "127.0.0.53" /etc/resolv.conf 2>/dev/null; then
        result_pass "Используется systemd-resolved stub (127.0.0.53) — централизованный резолвинг"
    elif grep -q "127.0.0.1" /etc/resolv.conf 2>/dev/null && \
         ( systemctl is-active --quiet dnsmasq 2>/dev/null || \
           systemctl is-active --quiet unbound 2>/dev/null ); then
        result_pass "Локальный DNS-резолвер на 127.0.0.1 (dnsmasq/unbound)"
    fi
}


# ─────────────────────────── ПОИСК БЭКДОРОВ ──────────────────────────────────

check_backdoors() {
    section "🔍 ПОИСК БЭКДОРОВ И ЗАКЛАДОК"
    log "  ${DIM}Глубокое сканирование — может занять несколько минут...${RESET}"

    local bd_found=0 f

    # ── 1. Подозрительные SUID/SGID бинарники ────────────────────────────────
    result_info "${BOLD}SUID/SGID файлы вне стандартных путей:${RESET}"
    local suid_list
    collect_suid
    suid_list=$(grep -Ev "^(/usr/(bin|sbin|lib|libexec)|/bin|/sbin|/usr/local/(bin|sbin))" <<< "$SUID_CACHE" \
        | grep -Ev "^(/var/lib/(docker|containerd|podman|lxc|lxd)|/run/containerd|/snap)")
    if [[ -z "$suid_list" ]]; then
        result_pass "Нестандартных SUID/SGID не найдено"
    else
        while read -r f; do
            result_fail "SUID/SGID вне стандартного пути: $f"
            bd_found=$((bd_found+1))
        done <<< "$suid_list"
    fi

    # ── 2. Скрытые файлы в /tmp, /var/tmp, /dev/shm ──────────────────────────
    echo ""
    result_info "${BOLD}Скрытые и исполняемые файлы в /tmp, /var/tmp, /dev/shm:${RESET}"
    local tmp_hits
    tmp_hits=$(find /tmp /var/tmp /dev/shm -maxdepth 3 \( -name ".*" -o -perm -u+x -o -perm -g+x \) \
        -type f 2>/dev/null \
        | grep -Ev "\.(lock|pid|socket)$" \
        | grep -Ev "/\.X[0-9]+-lock$" \
        | grep -Ev "/(RustDesk|snap-private-tmp|vmware|pulse|dbus|ssh-|systemd)" \
        | grep -v "^$")
    if [[ -z "$tmp_hits" ]]; then
        result_pass "Подозрительных файлов в /tmp и /dev/shm не найдено"
    else
        while read -r f; do
            result_warn "Исполняемый/скрытый файл в tmp: $f"
            bd_found=$((bd_found+1))
        done <<< "$tmp_hits"
    fi

    # ── 3. Процессы без исполняемого файла на диске (deleted) ────────────────
    echo ""
    result_info "${BOLD}Процессы с удалённым исполняемым файлом (deleted):${RESET}"
    # БЫЛО: `ls -la /proc/*/exe | awk '{print $NF}'` возвращало литерал
    # "(deleted)", а не путь, поэтому PID никогда не извлекался и вся проверка
    # печатала мусор. Читаем симлинки напрямую.
    local del_count=0 proc_exe pid target cmd
    for proc_exe in /proc/[0-9]*/exe; do
        target=$(readlink "$proc_exe" 2>/dev/null) || continue
        [[ "$target" == *"(deleted)"* ]] || continue
        pid="${proc_exe#/proc/}"; pid="${pid%/exe}"
        cmd=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | head -c 80)
        result_fail "Процесс PID=${pid} из удалённого файла '${target% (deleted)}': ${cmd:-<нет cmdline>}"
        del_count=$((del_count+1))
    done
    if (( del_count == 0 )); then
        result_pass "Процессов с удалённым exe не обнаружено"
    else
        bd_found=$((bd_found+del_count))
        [[ $EUID -ne 0 ]] && result_info "  ${DIM}(без root видны только свои процессы)${RESET}"
    fi

    # ── 4. Нестандартные cron-задачи ─────────────────────────────────────────
    echo ""
    result_info "${BOLD}Нестандартные и пользовательские cron-задачи:${RESET}"
    # БЫЛО: `find | while` — счётчик bd_found инкрементился в подоболочке и терялся
    local crondir owner
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly; do
        [[ -d "$crondir" ]] || continue
        while read -r f; do
            [[ -n "$f" ]] || continue
            owner=$(stat -c "%U" "$f" 2>/dev/null)
            if [[ "$owner" != "root" ]]; then
                result_fail "Cron-файл не от root: $f (владелец: $owner)"
                bd_found=$((bd_found+1))
            else
                result_info "  $f ${DIM}(root)${RESET}"
            fi
        done < <(find "$crondir" -type f 2>/dev/null)
    done
    # Пользовательские crontab
    if [[ -d /var/spool/cron/crontabs ]]; then
        for ctab in /var/spool/cron/crontabs/*; do
            [[ -f "$ctab" ]] || continue
            local uname
            uname=$(basename "$ctab")
            result_warn "Пользовательский crontab: $uname"
            grep -v "^#\|^$" "$ctab" 2>/dev/null | while read -r line; do
                log "    ${DIM}${line}${RESET}"
            done
        done
    fi

    # ── 5. Systemd юниты не из стандартных путей ─────────────────────────────
    echo ""
    result_info "${BOLD}Нестандартные systemd-юниты:${RESET}"
    local unit_hits=0 unit_sus=0 u exec_start
    while read -r u; do
        [[ -n "$u" ]] || continue
        unit_hits=$((unit_hits+1))
        exec_start=$(grep -E "^[[:space:]]*ExecStart" "$u" 2>/dev/null | head -1)
        if grep -qE "/tmp/|/dev/shm/|/var/tmp/|base64|eval|curl.*sh|wget.*sh|\bnc\b|\bncat\b" <<< "$exec_start"; then
            result_fail "Подозрительный ExecStart в юните $u: $exec_start"
            unit_sus=$((unit_sus+1))
            bd_found=$((bd_found+1))
        else
            log_only "    $(basename "$u"): ${exec_start}"
        fi
    done < <(find /etc/systemd /run/systemd /usr/local/lib/systemd -name "*.service" -type f 2>/dev/null)
    if (( unit_hits == 0 )); then
        result_pass "Локальных systemd-юнитов не найдено"
    elif (( unit_sus == 0 )); then
        result_pass "Проверено юнитов: ${unit_hits}, подозрительных ExecStart нет ${DIM}(список — в отчёте)${RESET}"
    fi

    # ── 6. Подозрительные ~/.ssh/authorized_keys ─────────────────────────────
    echo ""
    result_info "${BOLD}SSH authorized_keys — нестандартные записи:${RESET}"
    local ak_count=0
    while IFS=: read -r uname _ uid _ _ home _; do
        (( uid < 1000 )) && [[ "$uname" != "root" ]] && continue
        local akfile="${home}/.ssh/authorized_keys"
        [[ -f "$akfile" ]] || continue
        local key_count
        key_count=$(grep -cv "^#\|^$" "$akfile" 2>/dev/null)
        key_count="${key_count:-0}"
        result_info "  ${uname}: ${akfile} — ${key_count} ключей"
        # Команды в ключах (command= опция) — потенциальный бэкдор
        if grep -qE "^command=" "$akfile" 2>/dev/null; then
            result_warn "  В authorized_keys найдена опция command= (принудительная команда при входе)"
        fi
        # Ключи с IP-адресами откуда угодно
        if grep -qE "^\s*(ssh-rsa|ecdsa|ssh-ed25519)" "$akfile" 2>/dev/null; then
            grep -E "^\s*(ssh-rsa|ecdsa|ssh-ed25519)" "$akfile" | while read -r keyline; do
                local keycomment
                keycomment=$(echo "$keyline" | awk '{print $NF}')
                result_info "    Ключ: ${DIM}...${keycomment}${RESET}"
            done
        fi
        ak_count=$((ak_count+1))
    done < /etc/passwd
    (( ak_count == 0 )) && result_pass "SSH authorized_keys файлов не найдено"

    # ── 7. Прослушивающие процессы на нестандартных портах ───────────────────
    echo ""
    result_info "${BOLD}Нестандартные LISTEN-порты (>1024, кроме типичных):${RESET}"
    local common_ports="3000|3306|5432|5672|6379|8080|8443|8888|9200|9300|27017|27018"
    local nonstd=0 line port proc
    if command -v ss &>/dev/null; then
        while read -r line; do
            [[ -n "$line" ]] || continue
            port=$(awk '{print $4}' <<< "$line" | rev | cut -d: -f1 | rev)
            proc=$(grep -oP 'users:\(\("\K[^"]+' <<< "$line" || echo "?")
            if is_num "$port" && (( port > 1024 )) && ! grep -qE "^(${common_ports})$" <<< "$port"; then
                result_warn "Нестандартный порт $port — процесс: ${proc:-?}"
                nonstd=$((nonstd+1))
                bd_found=$((bd_found+1))
            fi
        done < <(ss -tlnp 2>/dev/null | grep LISTEN)
        (( nonstd == 0 )) && result_pass "Нестандартных LISTEN-портов не обнаружено"
    else
        result_info "ss недоступен — проверка портов пропущена"
    fi

    # ── 8. Netcat, socat, nmap, masscan — инструменты в системе ──────────────
    echo ""
    result_info "${BOLD}Инструменты пентеста / разведки в системе:${RESET}"
    local pentest_tools=("nc" "ncat" "netcat" "socat" "nmap" "masscan" "tcpdump"                          "tshark" "wireshark" "metasploit" "msfconsole" "sqlmap"                          "hydra" "john" "hashcat" "aircrack-ng" "nikto" "dirb")
    local pt_found=0
    for tool in "${pentest_tools[@]}"; do
        local path
        path=$(command -v "$tool" 2>/dev/null)
        if [[ -n "$path" ]]; then
            result_warn "Инструмент обнаружен: ${WHITE}$tool${RESET} → $path"
            pt_found=$((pt_found+1))
        fi
    done
    (( pt_found == 0 )) && result_pass "Инструменты пентеста не обнаружены"

    # ── 9. Подозрительные записи в /etc/hosts ────────────────────────────────
    echo ""
    result_info "${BOLD}Нестандартные записи в /etc/hosts:${RESET}"
    local hosts_hits
    # Исключаем стандартные записи включая типичные IPv6 Ubuntu (fe00, fe02 etc.)
    hosts_hits=$(grep -v "^#\|^$\|^127\.\|^::1\|^fe80\|^ff\|^fe00\|^fe02\|^2001:db8" /etc/hosts 2>/dev/null \
        | grep -v "^0\.0\.0\.0\s\+0\.0\.0\.0")
    if [[ -z "$hosts_hits" ]]; then
        result_pass "/etc/hosts содержит только стандартные записи"
    else
        while read -r line; do
            result_warn "/etc/hosts: $line"
            bd_found=$((bd_found+1))
        done <<< "$hosts_hits"
    fi

    # ── 10. Файлы .bash_history с подозрительными командами ──────────────────
    echo ""
    result_info "${BOLD}Анализ bash_history (подозрительные команды):${RESET}"
    local sus_patterns="base64 -d|curl.*sh|wget.*sh|\bchmod.*777\b|/dev/tcp/|\bnc -e\b|\bncat -e\b|python.*-c.*import|perl.*-e|/dev/shm|mkfifo"
    local history_found=0
    while IFS=: read -r uname _ uid _ _ home _; do
        (( uid < 1000 )) && [[ "$uname" != "root" ]] && continue
        local hfile="${home}/.bash_history"
        [[ -f "$hfile" ]] || continue
        local hits
        hits=$(grep -nE "$sus_patterns" "$hfile" 2>/dev/null | head -5)
        if [[ -n "$hits" ]]; then
            result_warn "Подозрительные команды в истории ${uname}:"
            while read -r h; do
                log "    ${DIM}${h}${RESET}"
            done <<< "$hits"
            history_found=$((history_found+1))
            bd_found=$((bd_found+1))
        fi
    done < /etc/passwd
    (( history_found == 0 )) && result_pass "Подозрительных команд в истории не найдено"

    # ── 11. LD_PRELOAD / /etc/ld.so.preload ──────────────────────────────────
    echo ""
    result_info "${BOLD}LD_PRELOAD и /etc/ld.so.preload (перехват библиотек):${RESET}"
    if [[ -f /etc/ld.so.preload ]]; then
        local preload_content
        preload_content=$(cat /etc/ld.so.preload 2>/dev/null)
        if [[ -n "$preload_content" ]]; then
            result_fail "/etc/ld.so.preload НЕ ПУСТОЙ — возможен перехват функций!"
            while read -r line; do
                log "    ${RED}${line}${RESET}"
            done <<< "$preload_content"
            bd_found=$((bd_found+1))
        else
            result_pass "/etc/ld.so.preload существует, но пуст"
        fi
    else
        result_pass "/etc/ld.so.preload отсутствует (норма)"
    fi

    # ── 12. PAM-модули не от пакетного менеджера ─────────────────────────────
    echo ""
    result_info "${BOLD}PAM-модули вне стандартных путей:${RESET}"
    local pam_dirs=()
    while read -r d; do
        [[ -d "$d" ]] && pam_dirs+=("$d")
    done < <(find /usr/lib /lib /lib64 -maxdepth 4 -type d -name "security" 2>/dev/null | sort -u)
    [[ ${#pam_dirs[@]} -eq 0 ]] && pam_dirs=("/usr/lib/x86_64-linux-gnu/security" "/lib/x86_64-linux-gnu/security")
    # Проверяем что dpkg реально знает файлы системы (в контейнерах база может быть пустой)
    local dpkg_functional=0
    if command -v dpkg &>/dev/null; then
        # Проверяем что база dpkg не пустая - /usr/bin/env должен быть в coreutils
        if dpkg -S /usr/bin/env &>/dev/null 2>&1; then
            dpkg_functional=1
        fi
    fi

    local pam_sus=0
    local pam_sus_found=0
    for pdir in "${pam_dirs[@]}"; do
        [[ -d "$pdir" ]] || continue
        while read -r mod; do
            pam_sus=$((pam_sus+1))
            local mod_owner
            mod_owner=$(stat -c "%U" "$mod" 2>/dev/null)
            local mod_perm
            mod_perm=$(stat -c "%a" "$mod" 2>/dev/null)
            local pkg_known=0
            # Проверяем принадлежность пакету только если dpkg реально работает
            if (( dpkg_functional == 1 )); then
                dpkg -S "$mod" &>/dev/null 2>&1 && pkg_known=1
            elif command -v rpm &>/dev/null; then
                rpm -qf "$mod" &>/dev/null 2>&1 && pkg_known=1
            else
                pkg_known=1  # Нет пакетного менеджера — не можем проверить, пропускаем
            fi
            # Проверяем реальные признаки подозрительности независимо от dpkg
            if [[ "$mod_owner" != "root" ]]; then
                result_fail "PAM-модуль не принадлежит root (владелец: ${mod_owner}): $mod"
                pam_sus_found=$((pam_sus_found+1))
            else
                # Проверяем write-биты для group или other: 3-й или 6-й символ prm = w
                local perm_str
                perm_str=$(stat -c "%A" "$mod" 2>/dev/null)
                local g_write="${perm_str:5:1}"
                local o_write="${perm_str:8:1}"
                if [[ "$g_write" == "w" || "$o_write" == "w" ]]; then
                    result_fail "PAM-модуль доступен для записи group/other (${mod_perm}): $mod"
                    pam_sus_found=$((pam_sus_found+1))
                elif (( pkg_known == 0 )); then
                    # pkg_known уже вычислен выше через dpkg/rpm — повторно
                    # дёргать пакетный менеджер незачем
                    result_warn "PAM-модуль не найден в базе пакетов: $(basename "$mod")"
                    pam_sus_found=$((pam_sus_found+1))
                fi
            fi
        done < <(find "$pdir" -name "*.so" -type f 2>/dev/null)
    done
    if (( pam_sus == 0 )); then
        result_pass "Нестандартных PAM-модулей не обнаружено"
    elif (( pam_sus_found == 0 )); then
        result_pass "Все PAM-модули принадлежат root с нормальными правами"
    fi

    # ── 13. /etc/passwd и /etc/shadow — изменения за последние 7 дней ────────
    echo ""
    result_info "${BOLD}Критические файлы, изменённые за последние 7 дней:${RESET}"
    local critical_watch=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/sudoers"
                          "/etc/ssh/sshd_config" "/etc/pam.d" "/etc/crontab"
                          "/root/.bashrc" "/root/.bash_profile" "/root/.profile")
    local changes_found=0
    for f in "${critical_watch[@]}"; do
        [[ -e "$f" ]] || continue
        if find "$f" -mtime -7 2>/dev/null | grep -q .; then
            local mtime
            mtime=$(stat -c "%y" "$f" 2>/dev/null | cut -d. -f1)
            result_warn "Изменён недавно: $f (${mtime})"
            changes_found=$((changes_found+1))
        fi
    done
    (( changes_found == 0 )) && result_pass "Критических файлов, изменённых за 7 дней, не найдено"

    # ── 14. Известные руткиты — проверка через chkrootkit/rkhunter ───────────
    echo ""
    result_info "${BOLD}Известные руткиты (chkrootkit / rkhunter):${RESET}"
    if command -v chkrootkit &>/dev/null; then
        result_info "Запускаю chkrootkit..."
        local ckr_out
        ckr_out=$(chkrootkit 2>/dev/null | grep -iE "INFECTED|Suspicious|Warning" | head -10)
        if [[ -n "$ckr_out" ]]; then
            result_fail "chkrootkit обнаружил проблемы:"
            while read -r line; do log "    ${RED}${line}${RESET}"; done <<< "$ckr_out"
            bd_found=$((bd_found+1))
        else
            result_pass "chkrootkit: подозрений не обнаружено"
        fi
    elif command -v rkhunter &>/dev/null; then
        result_info "Запускаю rkhunter..."
        local rkh_out
        rkh_out=$(rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | head -20)
        if [[ -n "$rkh_out" ]]; then
            result_warn "rkhunter обнаружил предупреждения:"
            while read -r line; do log "    ${YELLOW}${line}${RESET}"; done <<< "$rkh_out"
        else
            result_pass "rkhunter: подозрений не обнаружено"
        fi
    else
        result_warn "chkrootkit и rkhunter не установлены"
        add_fix "Установить rkhunter для проверки руткитов" "simple" "apt-get install -y rkhunter 2>/dev/null || yum install -y rkhunter 2>/dev/null; echo 'rkhunter установлен'"
    fi

    # ── Итог ─────────────────────────────────────────────────────────────────
    echo ""
    if (( bd_found == 0 )); then
        log "  ${GREEN}${BOLD}✔ Явных признаков бэкдоров не обнаружено${RESET}"
    else
        log "  ${RED}${BOLD}✘ Обнаружено подозрительных признаков: ${bd_found}${RESET}"
        log "  ${YELLOW}  Рекомендуется ручная проверка каждого найденного объекта${RESET}"
    fi
}

# ─────────────────────────── МЕНЮ И ОСНОВНОЙ ЦИКЛ ────────────────────────────

MENU_CHOICE=""

show_menu() {
    echo "" >/dev/tty
    echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════╗${RESET}" >/dev/tty
    echo -e "${BOLD}${MAGENTA}║              Выберите раздел для проверки                   ║${RESET}" >/dev/tty
    echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════╝${RESET}" >/dev/tty
    echo "" >/dev/tty
    echo -e "  ${WHITE}${BOLD}1)${RESET} Полный аудит (все разделы)" >/dev/tty
    echo -e "  ${WHITE}${BOLD}2)${RESET} Парольная политика + PAM" >/dev/tty
    echo -e "  ${WHITE}${BOLD}3)${RESET} SSH — конфигурация и криптография" >/dev/tty
    echo -e "  ${WHITE}${BOLD}4)${RESET} Учётные записи и права" >/dev/tty
    echo -e "  ${WHITE}${BOLD}5)${RESET} Сеть и брандмауэр" >/dev/tty
    echo -e "  ${WHITE}${BOLD}6)${RESET} Ядро, файловая система, шифрование" >/dev/tty
    echo -e "  ${WHITE}${BOLD}7)${RESET} Логирование, SELinux/AppArmor" >/dev/tty
    echo -e "  ${WHITE}${BOLD}8)${RESET}  ${RED}Поиск бэкдоров и закладок${RESET} ${DIM}(отдельный модуль, долго)${RESET}" >/dev/tty
    echo -e "  ${WHITE}${BOLD}9)${RESET}  NTP — синхронизация времени" >/dev/tty
    echo -e "  ${WHITE}${BOLD}10)${RESET} DNS — конфигурация и безопасность" >/dev/tty
    echo -e "  ${DIM}─────────────────────────────────────────────────────────────${RESET}" >/dev/tty
    echo -e "  ${CYAN}${BOLD}s)${RESET} Настройки параметров аудита" >/dev/tty
    echo -e "  ${WHITE}${BOLD}q)${RESET} Выход" >/dev/tty
    echo "" >/dev/tty
    while true; do
        printf "%b" "${CYAN}Ваш выбор: ${RESET}" >/dev/tty
        read -r MENU_CHOICE </dev/tty
        MENU_CHOICE="${MENU_CHOICE//[[:space:]]/}"
        case "$MENU_CHOICE" in
            1|2|3|4|5|6|7|8|9|10|s|S|q|Q) break ;;
            *) echo -e "${RED}  Введите цифру 1–10, s или q${RESET}" >/dev/tty ;;
        esac
    done
}

run_checks() {
    local mode="${1:-1}"
    # Сбрасываем накопленные исправления перед новым прогоном
    FIXES=()
    FIXES_SSH=()
    FIXES_FW=()
    PASS_POLICY_ISSUES=0
    NOPASS_USERS=()
    case "$mode" in
        1)
            check_password_policy; check_pam_pwquality
            check_accounts
            check_ssh; check_ssh_crypto
            check_shell_timeout
            check_firewall; check_updates
            check_services
            check_filesystem; check_kernel
            check_logging; check_mac; check_encryption
            check_cron; check_network
            check_ntp; check_dns
            ;;
        2) check_password_policy; check_pam_pwquality ;;
        0) : ;;   # ничего не запускать
        3) check_ssh; check_ssh_crypto ;;
        4) check_accounts ;;
        5) check_network; check_firewall ;;
        6) check_kernel; check_filesystem; check_encryption ;;
        7) check_logging; check_mac ;;
        8) check_backdoors ;;
        9) check_ntp ;;
        10) check_dns ;;
    esac
}

# ─────────────────────────── MAIN ───────────────────────────────────────────

main() {
    local skip_interactive=0
    local oneshot_mode=""
    local report_only=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --full|-f)        oneshot_mode="1"; skip_interactive=1 ;;
            --password|--pam) oneshot_mode="2"; skip_interactive=1 ;;
            --ssh)            oneshot_mode="3"; skip_interactive=1 ;;
            --accounts)       oneshot_mode="4"; skip_interactive=1 ;;
            --network)        oneshot_mode="5"; skip_interactive=1 ;;
            --kernel)         oneshot_mode="6"; skip_interactive=1 ;;
            --logging)        oneshot_mode="7"; skip_interactive=1 ;;
            --backdoors)      oneshot_mode="8"; skip_interactive=1 ;;
            --ntp)            oneshot_mode="9"; skip_interactive=1 ;;
            --dns)            oneshot_mode="10"; skip_interactive=1 ;;
            --no-interactive) skip_interactive=1 ;;
            --report-only)    report_only=1 ;;
            --timeout)
                shift
                # БЫЛО: shift без проверки — `--timeout` последним аргументом
                # падал на unbound variable из-за set -u
                [[ $# -gt 0 ]] || { echo "Ошибка: --timeout требует значение"; exit 2; }
                CONFIRM_TIMEOUT="$1"
                ;;
            --no-rollback-guard) DO_ROLLBACK_GUARD=0 ;;
            --help|-h)
                echo "Использование: $0 [ОПЦИЯ]"
                echo "  --full           Полный аудит"
                echo "  --password       Только парольная политика и PAM"
                echo "  --ssh            Только SSH"
                echo "  --accounts       Только учётные записи"
                echo "  --network        Только сеть"
                echo "  --kernel         Ядро и ФС"
                echo "  --logging        Логирование"
                echo "  --backdoors      Поиск бэкдоров"
                echo "  --ntp            Проверка NTP"
                echo "  --dns            Проверка DNS"
                echo "  --no-interactive Без интерактива (пороги по умолчанию)"
                echo "  --report-only    Только отчёт, без предложения исправлений"
                echo "  --timeout N      Секунд на подтверждение перед авто-откатом (безопасное применение)"
                echo "  --no-rollback-guard  Отключить авто-откат по таймауту (не рекомендуется на проде)"
                echo "  --help           Справка"
                exit 0
                ;;
            *) echo "Неизвестный аргумент: $1"; exit 1 ;;
        esac
        shift
    done

    if [[ ! "$CONFIRM_TIMEOUT" =~ ^[0-9]+$ ]] || (( CONFIRM_TIMEOUT < 10 )); then
        echo "Некорректный --timeout: '${CONFIRM_TIMEOUT}' (нужно целое >= 10)"
        exit 2
    fi

    # print_banner делает clear — предупреждение о запуске без root должно
    # выводиться ПОСЛЕ него, иначе пользователь его никогда не видел.
    print_banner
    check_root

    if [[ "$skip_interactive" -eq 0 ]]; then
        interactive_setup
    fi

    # ── Режим одиночного запуска (из аргументов CLI) ─────────────────────────
    if [[ -n "$oneshot_mode" ]]; then
        run_checks "$oneshot_mode"
        print_summary
        [[ "$report_only" -eq 0 ]] && offer_remediation
        echo ""
        echo -e "${DIM}Отчёт сохранён: ${WHITE}${REPORT_FILE}${RESET}"
        echo ""
        exit 0
    fi

    # ── Интерактивный цикл меню (параметры вводятся ОДИН РАЗ) ────────────────
    while true; do
        show_menu

        case "$MENU_CHOICE" in
            s|S)
                # Повторная настройка параметров без перезапуска
                interactive_setup
                continue
                ;;
            q|Q)
                echo ""
                echo -e "${CYAN}До свидания!${RESET}"
                echo -e "${DIM}Отчёт сохранён: ${WHITE}${REPORT_FILE}${RESET}"
                echo ""
                exit 0
                ;;
            *)
                run_checks "$MENU_CHOICE"
                print_summary
                (( report_only == 0 )) && offer_remediation
                echo ""
                echo -e "${DIM}Отчёт дополнен: ${WHITE}${REPORT_FILE}${RESET}"
                echo ""
                echo -e "${DIM}Нажмите Enter для возврата в меню...${RESET}"
                read -r </dev/tty
                ;;
        esac
    done
}

main "$@"
