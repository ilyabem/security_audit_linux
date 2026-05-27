#!/usr/bin/env bash
# =============================================================================
#  Linux Security Audit Multitool v2.0
#  Автор: github.com/ilyabem
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
REPORT_FILE="/tmp/security_audit_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"
ISSUES=0
NOPASS_USERS=()
REMEDIATION_ACTIONS=()
WARNINGS=0
PASSES=0

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
LOGIN_RETRIES=3

# ─────────────────────────── Вспомогательные функции ────────────────────────

log() {
    echo -e "$*" | tee -a "$REPORT_FILE"
}

log_only() {
    echo -e "$*" >> "$REPORT_FILE"
}

print_banner() {
    clear
    log ""
    log "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    log "${CYAN}${BOLD}║         🛡  Linux Security Audit Multitool v2.0  🛡               ║${RESET}"
    log "${CYAN}${BOLD}║       github: github.com/ilyabem/security_audit_linux            ║${RESET}"
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

result_pass() { log "  ${PASS} $*"; PASSES=$((PASSES+1)); }
result_fail() { log "  ${FAIL} $*"; ISSUES=$((ISSUES+1)); }
result_warn() { log "  ${WARN} $*"; WARNINGS=$((WARNINGS+1)); }
result_info() { log "  ${INFO} $*"; }

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

# ─────────────────────────── Интерактивная настройка ────────────────────────

interactive_setup() {
    echo ""
    echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${MAGENTA}║   Интерактивная настройка параметров     ║${RESET}"
    echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${DIM}Настройте пороговые значения для аудита. Enter = значение по умолчанию.${RESET}"
    echo ""

    echo -e "${WHITE}${BOLD}── Парольная политика ──────────────────────────${RESET}"
    read_int "Минимальная длина пароля" "$MIN_PASS_LEN" 6 128; MIN_PASS_LEN="$INT_RESULT"
    read_int "Максимальный срок действия пароля (дни)" "$PASS_MAX_AGE" 1 365; PASS_MAX_AGE="$INT_RESULT"
    read_int "Минимальный срок до смены пароля (дни)" "$PASS_MIN_AGE" 0 30; PASS_MIN_AGE="$INT_RESULT"
    read_int "Предупреждение до истечения пароля (дни)" "$PASS_WARN_AGE" 1 30; PASS_WARN_AGE="$INT_RESULT"
    read_int "Количество запоминаемых паролей (история)" "$PASS_HISTORY" 0 24; PASS_HISTORY="$INT_RESULT"

    echo ""
    echo -e "${WHITE}${BOLD}── Сложность пароля ────────────────────────────${RESET}"
    if confirm "Требовать ЗАГЛАВНЫЕ буквы"; then REQUIRE_UPPERCASE=1; else REQUIRE_UPPERCASE=0; fi
    if confirm "Требовать строчные буквы"; then REQUIRE_LOWERCASE=1; else REQUIRE_LOWERCASE=0; fi
    if confirm "Требовать цифры"; then REQUIRE_DIGITS=1; else REQUIRE_DIGITS=0; fi
    if confirm "Требовать спецсимволы"; then REQUIRE_SPECIAL=1; else REQUIRE_SPECIAL=0; fi

    echo ""
    echo -e "${WHITE}${BOLD}── Таймауты ────────────────────────────────────${RESET}"
    read_int "Таймаут бездействия SSH (секунды)" "$SSH_IDLE_TIMEOUT" 60 3600; SSH_IDLE_TIMEOUT="$INT_RESULT"
    read_int "Таймаут бездействия shell (секунды)" "$SHELL_TIMEOUT" 60 7200; SHELL_TIMEOUT="$INT_RESULT"

    echo ""
    echo -e "${WHITE}${BOLD}── SSH параметры ───────────────────────────────${RESET}"
    read_int "Максимум попыток аутентификации SSH" "$MAX_AUTH_TRIES" 1 10; MAX_AUTH_TRIES="$INT_RESULT"

    echo ""
    echo -e "${GREEN}${BOLD}✔ Параметры сохранены. Начинаю аудит...${RESET}"
    sleep 1
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
    elif (( max_days <= PASS_MAX_AGE )); then
        result_pass "PASS_MAX_DAYS = $max_days (≤ ${PASS_MAX_AGE} дней)"
    else
        result_fail "PASS_MAX_DAYS = $max_days (требуется ≤ ${PASS_MAX_AGE})"
        add_fix "Установить PASS_MAX_DAYS=${PASS_MAX_AGE} в /etc/login.defs" "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t${PASS_MAX_AGE}/' /etc/login.defs"
    fi

    # PASS_MIN_DAYS
    local min_days
    min_days=$(grep -E "^PASS_MIN_DAYS" "$file" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ -z "$min_days" ]]; then
        result_fail "PASS_MIN_DAYS не задан"
    elif (( min_days >= PASS_MIN_AGE )); then
        result_pass "PASS_MIN_DAYS = $min_days (≥ ${PASS_MIN_AGE} дней)"
    else
        result_warn "PASS_MIN_DAYS = $min_days (рекомендуется ≥ ${PASS_MIN_AGE})"
        add_fix "Установить PASS_MIN_DAYS=${PASS_MIN_AGE} в /etc/login.defs" "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t${PASS_MIN_AGE}/' /etc/login.defs"
    fi

    # PASS_WARN_AGE
    local warn_age
    warn_age=$(grep -E "^PASS_WARN_AGE" "$file" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ -z "$warn_age" ]]; then
        result_fail "PASS_WARN_AGE не задан"
    elif (( warn_age >= PASS_WARN_AGE )); then
        result_pass "PASS_WARN_AGE = $warn_age (≥ ${PASS_WARN_AGE} дней)"
    else
        result_warn "PASS_WARN_AGE = $warn_age (рекомендуется ≥ ${PASS_WARN_AGE} дней)"
        add_fix "Установить PASS_WARN_AGE=${PASS_WARN_AGE} в /etc/login.defs" "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t${PASS_WARN_AGE}/' /etc/login.defs"
    fi

    # PASS_MIN_LEN
    local min_len
    min_len=$(grep -E "^PASS_MIN_LEN" "$file" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ -z "$min_len" ]]; then
        result_warn "PASS_MIN_LEN не задан в login.defs"
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
    if [[ -n "$sha_rounds" ]]; then
        if (( sha_rounds >= 500000 )); then
            result_pass "SHA_CRYPT_MIN_ROUNDS = $sha_rounds"
        else
            result_warn "SHA_CRYPT_MIN_ROUNDS = $sha_rounds (рекомендуется ≥ 500000)"
        fi
    else
        result_info "SHA_CRYPT_MIN_ROUNDS не задан (используется значение по умолчанию)"
    fi
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
    local pam_quality_active=0
    if grep -rq "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null; then
        result_pass "Модуль проверки сложности паролей (pam_pwquality/pam_cracklib) подключён"
        pam_quality_active=1
    else
        result_fail "Модуль pam_pwquality/pam_cracklib НЕ подключён в PAM"
        add_fix "Установить и включить libpam-pwquality" "apt-get install -y libpam-pwquality 2>/dev/null || yum install -y pam_pwquality 2>/dev/null; echo 'Установлен libpam-pwquality'"
    fi

    # minlen
    local pwq_minlen
    pwq_minlen=$(grep -rE "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    if [[ -z "$pwq_minlen" ]]; then
        pwq_minlen=$(grep -rE "minlen=" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -oP "minlen=\K[0-9]+" | head -1)
    fi
    if [[ -n "$pwq_minlen" ]]; then
        if (( pwq_minlen >= MIN_PASS_LEN )); then
            result_pass "minlen = $pwq_minlen (≥ ${MIN_PASS_LEN})"
        else
            result_fail "minlen = $pwq_minlen (требуется ≥ ${MIN_PASS_LEN})"
        add_fix "Установить minlen=${MIN_PASS_LEN} в /etc/security/pwquality.conf" "grep -q '^minlen' /etc/security/pwquality.conf && sed -i 's/^minlen.*/minlen = ${MIN_PASS_LEN}/' /etc/security/pwquality.conf || echo 'minlen = ${MIN_PASS_LEN}' >> /etc/security/pwquality.conf"
        fi
    else
        result_warn "minlen не задан в pwquality.conf"
    fi

    # Заглавные буквы (ucredit)
    local ucredit
    ucredit=$(grep -rE "^\s*ucredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    [[ -z "$ucredit" ]] && ucredit=$(grep -rE "ucredit=" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -oP "ucredit=\K[-0-9]+" | head -1)
    if (( REQUIRE_UPPERCASE == 1 )); then
        if [[ -n "$ucredit" ]] && (( ucredit <= -1 )); then
            result_pass "ucredit = $ucredit (заглавные буквы обязательны)"
        else
            result_fail "ucredit не требует заглавных букв (текущее: ${ucredit:-не задано})"
        add_fix "Требовать заглавные буквы (ucredit=-1)" "grep -q '^ucredit' /etc/security/pwquality.conf && sed -i 's/^ucredit.*/ucredit = -1/' /etc/security/pwquality.conf || echo 'ucredit = -1' >> /etc/security/pwquality.conf"
        fi
    fi

    # Строчные буквы (lcredit)
    local lcredit
    lcredit=$(grep -rE "^\s*lcredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    [[ -z "$lcredit" ]] && lcredit=$(grep -rE "lcredit=" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -oP "lcredit=\K[-0-9]+" | head -1)
    if (( REQUIRE_LOWERCASE == 1 )); then
        if [[ -n "$lcredit" ]] && (( lcredit <= -1 )); then
            result_pass "lcredit = $lcredit (строчные буквы обязательны)"
        else
            result_fail "lcredit не требует строчных букв (текущее: ${lcredit:-не задано})"
        fi
    fi

    # Цифры (dcredit)
    local dcredit
    dcredit=$(grep -rE "^\s*dcredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    [[ -z "$dcredit" ]] && dcredit=$(grep -rE "dcredit=" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -oP "dcredit=\K[-0-9]+" | head -1)
    if (( REQUIRE_DIGITS == 1 )); then
        if [[ -n "$dcredit" ]] && (( dcredit <= -1 )); then
            result_pass "dcredit = $dcredit (цифры обязательны)"
        else
            result_fail "dcredit не требует цифр (текущее: ${dcredit:-не задано})"
        add_fix "Требовать цифры (dcredit=-1)" "grep -q '^dcredit' /etc/security/pwquality.conf && sed -i 's/^dcredit.*/dcredit = -1/' /etc/security/pwquality.conf || echo 'dcredit = -1' >> /etc/security/pwquality.conf"
        fi
    fi

    # Спецсимволы (ocredit)
    local ocredit
    ocredit=$(grep -rE "^\s*ocredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    [[ -z "$ocredit" ]] && ocredit=$(grep -rE "ocredit=" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -oP "ocredit=\K[-0-9]+" | head -1)
    if (( REQUIRE_SPECIAL == 1 )); then
        if [[ -n "$ocredit" ]] && (( ocredit <= -1 )); then
            result_pass "ocredit = $ocredit (спецсимволы обязательны)"
        else
            result_fail "ocredit не требует спецсимволов (текущее: ${ocredit:-не задано})"
        add_fix "Требовать спецсимволы (ocredit=-1)" "grep -q '^ocredit' /etc/security/pwquality.conf && sed -i 's/^ocredit.*/ocredit = -1/' /etc/security/pwquality.conf || echo 'ocredit = -1' >> /etc/security/pwquality.conf"
        fi
    fi

    # История паролей (remember)
    local remember
    remember=$(grep -rE "remember=" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -oP "remember=\K[0-9]+" | head -1)
    if [[ -n "$remember" ]] && (( remember >= PASS_HISTORY )); then
        result_pass "История паролей: remember=$remember (≥ ${PASS_HISTORY})"
    else
        result_fail "История паролей не задана или недостаточна (текущее: ${remember:-0}, требуется ≥ ${PASS_HISTORY})"
    fi

    # Блокировка после неудачных попыток (pam_faillock / pam_tally2)
    if grep -rq "pam_faillock\|pam_tally2" /etc/pam.d/ 2>/dev/null; then
        result_pass "Блокировка после неудачных попыток входа настроена (pam_faillock/pam_tally2)"
        local deny
        deny=$(grep -rE "deny=" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -oP "deny=\K[0-9]+" | head -1)
        [[ -n "$deny" ]] && result_info "  Блокировка после $deny неудачных попыток"
    else
        result_fail "pam_faillock/pam_tally2 не настроен — нет блокировки после неудачных попыток"
        add_fix "Включить pam_faillock (блокировка после 5 неудач на 15 мин)" "pam-auth-update --enable faillock 2>/dev/null; echo 'deny = 5' >> /etc/security/faillock.conf 2>/dev/null; echo 'unlock_time = 900' >> /etc/security/faillock.conf 2>/dev/null; echo 'Faillock настроен'"
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
        while IFS=: read -r uname _ uid gid _ home shell; do
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
        local nopass
        nopass=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null || echo "")
        if [[ -z "$nopass" ]]; then
            result_pass "Все аккаунты имеют пароль (или заблокированы)"
        else
            local real_nopass=0
            while read -r u; do
                # Получаем UID пользователя
                local u_uid
                u_uid=$(awk -F: -v user="$u" '$1==user{print $3}' /etc/passwd 2>/dev/null)
                local u_shell
                u_shell=$(awk -F: -v user="$u" '$1==user{print $7}' /etc/passwd 2>/dev/null)
                # Системные аккаунты (uid < 1000) с nologin/false — это норма
                if [[ -n "$u_uid" ]] && (( u_uid < 1000 )) && [[ "$u_shell" =~ nologin|false|/bin/sync ]]; then
                    result_info "  ${u} (uid=${u_uid}) — системный сервисный аккаунт без пароля ${DIM}[норма]${RESET}"
                elif [[ -n "$u_uid" ]] && (( u_uid < 1000 )); then
                    result_warn "  Системный аккаунт '${u}' (uid=${u_uid}) без пароля, shell=${u_shell}"
                else
                    result_fail "  Пользователь '${u}' (uid=${u_uid}) не имеет пароля!"
                    real_nopass=$((real_nopass+1))
                    NOPASS_USERS+=("$u")
                fi
            done <<< "$nopass"
            (( real_nopass == 0 )) && result_pass "Интерактивных аккаунтов без пароля не обнаружено"
        fi
    else
        result_warn "Требуется root для проверки /etc/shadow"
    fi

    echo ""
    # Аккаунты с UID 0 (кроме root)
    result_info "${BOLD}Аккаунты с UID=0 (суперпользователи):${RESET}"
    local uid0
    uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    local uid0_count=0
    while read -r u; do
        uid0_count=$((uid0_count+1))
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
        securetty_entries=$(grep -v "^#\|^$" /etc/securetty | wc -l)
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
            (( uid < 1000 )) && [[ "$uname" != "root" ]] && continue
            local exp
            exp=$(chage -l "$uname" 2>/dev/null | grep "Password expires" | awk -F: '{print $2}' | xargs)
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

# 4. SSH конфигурация
check_ssh() {
    section "КОНФИГУРАЦИЯ SSH"

    local sshd_conf="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_conf" ]]; then
        result_warn "SSH не установлен или конфиг не найден"
        return
    fi

    # Вспомогательная функция получения значения из sshd_config
    get_ssh_param() {
        local param="$1"
        grep -Ei "^\s*${param}\s" "$sshd_conf" 2>/dev/null | tail -1 | awk '{print $2}'
    }

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
        add_fix "Запретить прямой root-вход SSH (PermitRootLogin no)" "sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null"
    fi

    # Пустые пароли
    local empty_pw
    empty_pw=$(get_ssh_param "PermitEmptyPasswords")
    if [[ "${empty_pw,,}" == "no" || -z "$empty_pw" ]]; then
        result_pass "PermitEmptyPasswords = ${empty_pw:-no (по умолчанию)}"
    else
        result_fail "PermitEmptyPasswords = $empty_pw — КРИТИЧНО!"
        add_fix "Запретить пустые пароли SSH (PermitEmptyPasswords no)" "sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config && systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null"
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
    local effective_timeout=0
    if [[ -n "$client_alive_int" && -n "$client_alive_cnt" ]]; then
        effective_timeout=$(( client_alive_int * client_alive_cnt ))
    elif [[ -n "$client_alive_int" ]]; then
        effective_timeout=$client_alive_int
    fi

    if [[ -z "$client_alive_int" ]]; then
        result_fail "ClientAliveInterval не задан — SSH-сессии не прерываются по таймауту"
        add_fix "Установить таймаут SSH (ClientAliveInterval=300, CountMax=3)" "grep -q '^ClientAliveInterval' /etc/ssh/sshd_config && sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config || echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config; grep -q '^ClientAliveCountMax' /etc/ssh/sshd_config && sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 3' >> /etc/ssh/sshd_config; systemctl reload sshd 2>/dev/null"
    elif (( effective_timeout <= SSH_IDLE_TIMEOUT )); then
        result_pass "Таймаут SSH: ClientAliveInterval=${client_alive_int}×ClientAliveCountMax=${client_alive_cnt:-1} = ${effective_timeout}с (≤ ${SSH_IDLE_TIMEOUT}с)"
    else
        result_fail "Таймаут SSH слишком велик: ${effective_timeout}с (требуется ≤ ${SSH_IDLE_TIMEOUT}с)"
    fi

    # MaxAuthTries
    local max_auth
    max_auth=$(get_ssh_param "MaxAuthTries")
    if [[ -z "$max_auth" ]]; then
        result_warn "MaxAuthTries не задан (по умолчанию 6)"
    elif (( max_auth <= MAX_AUTH_TRIES )); then
        result_pass "MaxAuthTries = $max_auth (≤ ${MAX_AUTH_TRIES})"
    else
        result_fail "MaxAuthTries = $max_auth (рекомендуется ≤ ${MAX_AUTH_TRIES})"
        add_fix "Установить MaxAuthTries=${MAX_AUTH_TRIES} в sshd_config" "sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries ${MAX_AUTH_TRIES}/' /etc/ssh/sshd_config && systemctl reload sshd 2>/dev/null"
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
    if [[ -z "$grace" ]]; then
        result_warn "LoginGraceTime не задан (по умолчанию 120с)"
    elif (( grace <= 60 )); then
        result_pass "LoginGraceTime = ${grace}с"
    else
        result_warn "LoginGraceTime = ${grace}с (рекомендуется ≤ 60с)"
    fi

    # AllowUsers / AllowGroups
    local allow_users allow_groups
    allow_users=$(get_ssh_param "AllowUsers")
    allow_groups=$(get_ssh_param "AllowGroups")
    if [[ -n "$allow_users" || -n "$allow_groups" ]]; then
        result_pass "Ограничение доступа: AllowUsers='${allow_users:-}' AllowGroups='${allow_groups:-}'"
    else
        result_warn "AllowUsers/AllowGroups не заданы — все пользователи могут подключаться по SSH"
    fi

    # Banner
    local banner
    banner=$(get_ssh_param "Banner")
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
        val=$(grep -E "^\s*(export\s+)?TMOUT\s*=" "$f" 2>/dev/null | grep -oP "TMOUT=\K[0-9]+" | head -1)
        if [[ -n "$val" ]]; then
            tmout_val="$val"
            timeout_found=1
            result_info "TMOUT=$val найден в $f"
        fi
    done

    if [[ "$timeout_found" -eq 0 ]]; then
        result_fail "TMOUT не задан в глобальных профилях — shell не завершается по таймауту"
        add_fix "Установить TMOUT=${SHELL_TIMEOUT} (таймаут shell) в /etc/profile.d/timeout.sh" "echo 'readonly TMOUT=${SHELL_TIMEOUT}' > /etc/profile.d/timeout.sh && chmod 644 /etc/profile.d/timeout.sh"
    elif [[ -n "$tmout_val" ]] && (( tmout_val <= SHELL_TIMEOUT )); then
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
        ipt_rules=$(iptables -L INPUT --line-numbers 2>/dev/null | grep -c "^[0-9]" || echo 0)
        if (( ipt_rules > 0 )); then
            result_pass "iptables: $ipt_rules правил в цепочке INPUT"
            fw_active=1
        else
            result_warn "iptables: цепочка INPUT пуста"
        fi
    fi

    (( fw_active == 0 )) && result_fail "Ни один брандмауэр не обнаружен в активном состоянии!"
        add_fix "Включить UFW (минимальные правила: deny all in, allow ssh)" "ufw --force reset; ufw default deny incoming; ufw default allow outgoing; ufw allow ssh; ufw --force enable"

    # IPv6 firewall
    if command -v ip6tables &>/dev/null; then
        local ip6t_rules
        ip6t_rules=$(ip6tables -L INPUT 2>/dev/null | grep -c "^[A-Z]" || echo 0)
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

        # Доступные обновления безопасности
        if command -v apt-check &>/dev/null; then
            local security_updates
            security_updates=$(apt-check 2>&1 | awk -F';' '{print $2}')
            if [[ "$security_updates" == "0" ]]; then
                result_pass "Нет ожидающих обновлений безопасности"
            else
                result_fail "Ожидает установки обновлений безопасности: $security_updates"
            fi
        fi

        # unattended-upgrades
        if dpkg -l unattended-upgrades &>/dev/null 2>&1 && \
           systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
            result_pass "unattended-upgrades активен (автоматические обновления)"
        else
            result_warn "unattended-upgrades не активен"
        fi

    elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
        local pkg_mgr="yum"
        command -v dnf &>/dev/null && pkg_mgr="dnf"
        local sec_updates
        sec_updates=$($pkg_mgr check-update --security 2>/dev/null | grep -c "^[a-zA-Z]" || echo "?")
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

    # SUID/SGID файлы
    result_info "${BOLD}Файлы с SUID/SGID (вне стандартных путей):${RESET}"
    local suid_count=0
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | \
    grep -Ev "^(/usr/bin|/usr/sbin|/bin|/sbin|/usr/lib|/usr/libexec)" | \
    while read -r f; do
        result_warn "  SUID/SGID: $f"
        suid_count=$((suid_count+1)) || true
    done
    (( suid_count == 0 )) && result_pass "Нестандартных SUID/SGID файлов не обнаружено"

    echo ""
    # Мировозаписываемые файлы
    result_info "${BOLD}Мировозаписываемые файлы (world-writable):${RESET}"
    local ww_files
    ww_files=$(find / -xdev -perm -o+w -not -type l -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -20)
    if [[ -z "$ww_files" ]]; then
        result_pass "Мировозаписываемых файлов не обнаружено"
    else
        echo "$ww_files" | while read -r f; do
            result_warn "  world-writable: $f"
        done
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
            add_fix "Установить ${param}=${expected} (${desc})" \
                "sysctl -w '${param}=${expected}'; grep -q '${param}' /etc/sysctl.conf && sed -i 's|${param}.*|${param}=${expected}|' /etc/sysctl.conf || echo '${param}=${expected}' >> /etc/sysctl.conf"
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
            audit_rules=$(auditctl -l 2>/dev/null | grep -v "^No rules" | wc -l)
            result_info "  Правил аудита: $audit_rules"
        else
            result_fail "auditd установлен, но НЕ запущен"
        fi
    else
        result_warn "auditd не установлен (рекомендуется для STIG/CIS)"
        add_fix "Установить и включить auditd" "apt-get install -y auditd audispd-plugins 2>/dev/null || yum install -y audit 2>/dev/null; systemctl enable --now auditd"
    fi

    # rsyslog / syslog-ng
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        result_pass "rsyslog активен"
    elif systemctl is-active --quiet syslog-ng 2>/dev/null; then
        result_pass "syslog-ng активен"
    else
        result_fail "rsyslog/syslog-ng не запущен — системные логи могут не писаться"
        add_fix "Установить и запустить rsyslog" "apt-get install -y rsyslog 2>/dev/null || yum install -y rsyslog 2>/dev/null; systemctl enable --now rsyslog"
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
        encrypted=$(lsblk -o TYPE 2>/dev/null | grep -c "crypt" || echo 0)
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
        cat /etc/cron.allow | while read -r u; do
            result_info "  cron.allow: $u"
        done
    elif [[ -f /etc/cron.deny ]]; then
        result_warn "/etc/cron.deny используется (менее безопасно, чем cron.allow)"
    else
        result_warn "Ни cron.allow, ни cron.deny не настроены"
    fi

    # Пользовательские crontab
    result_info "${BOLD}Пользовательские crontab:${RESET}"
    if [[ -d /var/spool/cron/crontabs ]]; then
        ls /var/spool/cron/crontabs/ 2>/dev/null | while read -r u; do
            result_warn "  Пользовательский crontab: $u"
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

    # Слабые алгоритмы
    local sshd_conf="/etc/ssh/sshd_config"
    [[ ! -f "$sshd_conf" ]] && return

    get_ssh_param() {
        grep -Ei "^\s*${1}\s" "$sshd_conf" 2>/dev/null | tail -1 | cut -d' ' -f2-
    }

    # Ciphers
    local ciphers
    ciphers=$(get_ssh_param "Ciphers")
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
    macs=$(get_ssh_param "MACs")
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
    kex=$(get_ssh_param "KexAlgorithms")
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
    if grep -qi "HostKey.*ssh_host_dsa_key" "$sshd_conf" 2>/dev/null; then
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

# ─────────────────────────── МЕНЮ ВЫБОРА ПРОВЕРОК ───────────────────────────


# ─────────────────────────── МЕХАНИЗМ ИСПРАВЛЕНИЙ ───────────────────────────

# Глобальный список: каждый элемент = "описание|||команда"
FIXES=()

add_fix() {
    local desc="$1"
    local cmd="$2"
    FIXES+=("${desc}|||${cmd}")
}

# Вызывается после всех проверок — предлагает исправления
offer_remediation() {
    [[ ${#FIXES[@]} -eq 0 ]] && return

    echo ""
    log "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    log "${BOLD}${MAGENTA}║           🔧  АВТОМАТИЧЕСКОЕ ИСПРАВЛЕНИЕ ПРОБЛЕМ  🔧             ║${RESET}"
    log "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    log ""
    log "  Найдено ${#FIXES[@]} исправлений. Каждое требует вашего подтверждения."
    log ""

    if [[ $EUID -ne 0 ]]; then
        log "  ${YELLOW}${BOLD}⚠ Для применения исправлений требуется root.${RESET}"
        log "  Запустите скрипт через: ${WHITE}sudo $0${RESET}"
        return
    fi

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

MENU_CHOICE=""

# ─────────────────────────── ПОИСК БЭКДОРОВ ──────────────────────────────────

check_backdoors() {
    section "🔍 ПОИСК БЭКДОРОВ И ЗАКЛАДОК"
    log "  ${DIM}Глубокое сканирование — может занять несколько минут...${RESET}"

    local bd_found=0

    # ── 1. Подозрительные SUID/SGID бинарники ────────────────────────────────
    result_info "${BOLD}SUID/SGID файлы вне стандартных путей:${RESET}"
    local suid_list
    suid_list=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
        | grep -Ev "^(/usr/(bin|sbin|lib|libexec)|/bin|/sbin|/usr/local/(bin|sbin))" \
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
    local del_procs
    del_procs=$(ls -la /proc/*/exe 2>/dev/null | grep "deleted" | awk '{print $NF}')
    if [[ -z "$del_procs" ]]; then
        result_pass "Процессов с удалённым exe не обнаружено"
    else
        while read -r p; do
            local pid
            pid=$(echo "$p" | grep -oP '/proc/\K[0-9]+')
            local cmd
            cmd=$(cat /proc/"$pid"/cmdline 2>/dev/null | tr ' ' ' ' | head -c 80)
            result_fail "Процесс PID=$pid запущен из удалённого файла: $cmd"
            bd_found=$((bd_found+1))
        done <<< "$del_procs"
    fi

    # ── 4. Нестандартные cron-задачи ─────────────────────────────────────────
    echo ""
    result_info "${BOLD}Нестандартные и пользовательские cron-задачи:${RESET}"
    local cron_found=0
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly; do
        [[ -d "$crondir" ]] || continue
        find "$crondir" -type f 2>/dev/null | while read -r f; do
            local owner
            owner=$(stat -c "%U" "$f" 2>/dev/null)
            if [[ "$owner" != "root" ]]; then
                result_fail "Cron-файл не от root: $f (владелец: $owner)"
                bd_found=$((bd_found+1))
            else
                result_info "  $f ${DIM}(root)${RESET}"
            fi
        done
        cron_found=$((cron_found+1))
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
    local unit_hits=0
    find /etc/systemd /run/systemd /usr/local/lib/systemd -name "*.service" -type f 2>/dev/null | while read -r u; do
        # Смотрим ExecStart на подозрительные пути
        local exec_start
        exec_start=$(grep -E "^\s*ExecStart" "$u" 2>/dev/null | head -1)
        if echo "$exec_start" | grep -qE "/tmp/|/dev/shm/|/var/tmp/|base64|eval|curl.*sh|wget.*sh|nc|ncat"; then
            result_fail "Подозрительный ExecStart в юните $u: $exec_start"
            bd_found=$((bd_found+1))
        else
            result_info "  $(basename $u): $exec_start"
        fi
        unit_hits=$((unit_hits+1))
    done
    (( unit_hits == 0 )) && result_pass "Нестандартных systemd-юнитов не найдено"

    # ── 6. Подозрительные ~/.ssh/authorized_keys ─────────────────────────────
    echo ""
    result_info "${BOLD}SSH authorized_keys — нестандартные записи:${RESET}"
    local ak_count=0
    while IFS=: read -r uname _ uid _ _ home _; do
        (( uid < 1000 )) && [[ "$uname" != "root" ]] && continue
        local akfile="${home}/.ssh/authorized_keys"
        [[ -f "$akfile" ]] || continue
        local key_count
        key_count=$(grep -cv "^#\|^$" "$akfile" 2>/dev/null || echo 0)
        result_info "  ${uname}: ${akfile} — ${key_count} ключ(ей)"
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
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep LISTEN | while read -r line; do
            local port
            port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
            local proc
            proc=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "?")
            if [[ "$port" =~ ^[0-9]+$ ]] && (( port > 1024 )) && ! echo "$port" | grep -qE "^(${common_ports})$"; then
                result_warn "Нестандартный порт $port — процесс: $proc"
                bd_found=$((bd_found+1))
            fi
        done
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
    local sus_patterns="base64 -d|curl.*sh|wget.*sh|chmod.*777|/dev/tcp/|nc -e|ncat -e|python.*-c.*import|perl.*-e|/dev/shm|mkfifo"
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
    if command -v dpkg &>/dev/null 2>/dev/null; then
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
            elif command -v rpm &>/dev/null 2>/dev/null; then
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
                    # Если пакетный менеджер доступен, но модуль не найден — подозрительно
                    if command -v dpkg &>/dev/null 2>/dev/null; then
                        if ! dpkg -S "$mod" &>/dev/null 2>&1; then
                            result_warn "PAM-модуль не найден в базе пакетов: $(basename $mod)"
                            pam_sus_found=$((pam_sus_found+1))
                        fi
                    elif command -v rpm &>/dev/null 2>/dev/null; then
                        if ! rpm -qf "$mod" &>/dev/null 2>&1; then
                            result_warn "PAM-модуль не найден в базе пакетов: $(basename $mod)"
                            pam_sus_found=$((pam_sus_found+1))
                        fi
                    fi
                    # Если dpkg/rpm недоступен — файл от root с нормальными правами, молчим
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
        add_fix "Установить rkhunter для проверки руткитов"             "apt-get install -y rkhunter 2>/dev/null || yum install -y rkhunter 2>/dev/null; echo 'rkhunter установлен'"
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
    echo -e "  ${RED}${BOLD}8)${RESET}${RED} Поиск бэкдоров и закладок ${DIM}(отдельный модуль)${RESET}" >/dev/tty
    echo -e "  ${DIM}─────────────────────────────────────────────────────────────${RESET}" >/dev/tty
    echo -e "  ${CYAN}${BOLD}s)${RESET} Настройки параметров аудита" >/dev/tty
    echo -e "  ${WHITE}${BOLD}q)${RESET} Выход" >/dev/tty
    echo "" >/dev/tty
    while true; do
        printf "%b" "${CYAN}Ваш выбор: ${RESET}" >/dev/tty
        read -r MENU_CHOICE </dev/tty
        MENU_CHOICE="${MENU_CHOICE//[[:space:]]/}"
        case "$MENU_CHOICE" in
            1|2|3|4|5|6|7|8|s|S|q|Q) break ;;
            *) echo -e "${RED}  Введите цифру 1–8, s или q${RESET}" >/dev/tty ;;
        esac
    done
}

run_checks() {
    local mode="${1:-1}"
    # Сбрасываем накопленные исправления перед новым прогоном
    FIXES=()
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
            ;;
        2) check_password_policy; check_pam_pwquality ;;
        3) check_ssh; check_ssh_crypto ;;
        4) check_accounts ;;
        5) check_network; check_firewall ;;
        6) check_kernel; check_filesystem; check_encryption ;;
        7) check_logging; check_mac ;;
        8) check_backdoors ;;
    esac
}

# ─────────────────────────── MAIN ───────────────────────────────────────────

main() {
    local skip_interactive=0
    local oneshot_mode=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --full|-f)        oneshot_mode="1"; skip_interactive=1 ;;
            --ssh)            oneshot_mode="3"; skip_interactive=1 ;;
            --accounts)       oneshot_mode="4"; skip_interactive=1 ;;
            --network)        oneshot_mode="5"; skip_interactive=1 ;;
            --kernel)         oneshot_mode="6"; skip_interactive=1 ;;
            --logging)        oneshot_mode="7"; skip_interactive=1 ;;
            --backdoors)      oneshot_mode="8"; skip_interactive=1 ;;
            --no-interactive) skip_interactive=1 ;;
            --help|-h)
                echo "Использование: $0 [ОПЦИЯ]"
                echo "  --full           Полный аудит"
                echo "  --ssh            Только SSH"
                echo "  --accounts       Только учётные записи"
                echo "  --network        Только сеть"
                echo "  --kernel         Ядро и ФС"
                echo "  --logging        Логирование"
                echo "  --backdoors      Поиск бэкдоров"
                echo "  --no-interactive Без интерактива"
                echo "  --help           Справка"
                exit 0
                ;;
            *) echo "Неизвестный аргумент: $1"; exit 1 ;;
        esac
        shift
    done

    check_root
    print_banner

    if [[ "$skip_interactive" -eq 0 ]]; then
        interactive_setup
    fi

    # ── Режим одиночного запуска (из аргументов CLI) ─────────────────────────
    if [[ -n "$oneshot_mode" ]]; then
        run_checks "$oneshot_mode"
        print_summary
        offer_remediation
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
                offer_remediation
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
