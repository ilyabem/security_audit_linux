#  Linux CIS Hardening Multitool

Интерактивный харденинг Linux-серверов по **CIS Benchmark** (Level 1 / Level 2
Server) на чистом Bash. Это развитие
[security_audit_linux](https://github.com/ilyabem/security_audit_linux): тот же
движок применения и предохранитель от самоблокировки, но задача другая. Аудит
показывает проблемы, а этот скрипт сначала расспрашивает, что это за сервер, и
затем приводит его к CIS. Изменения применяются только с бэкапом и
возможностью отката.

```
── Роль сервера ────────────────────────────────
Сервер маршрутизирует трафик (Docker/Kubernetes/VPN/шлюз — нужен ip_forward)? [y/N]:
Используется ли IPv6? [Y/n]:
...
  [✘ FAIL] [CIS 5.1.20] PermitRootLogin = yes (прямой вход root запрещён)
  Обнаружен Samba (SMB) (smbd.service). Нужен ли он на этом сервере? [y/N]:
  Порт 8080/tcp (java) слушает сеть, но не разрешён в брандмауэре. Должен быть доступен извне? [Y/n]:
```

---

## Что нового по сравнению с security_audit.sh

| | security_audit.sh | linux_cis_hardening.sh |
|---|---|---|
| Назначение | аудит + точечные фиксы | харденинг по CIS с опросником |
| Проверки | 19 разделов | разделы CIS 1–7, 150+ проверок с номерами пунктов CIS и уровнем L1/L2 |
| Вопросы | пороги паролей и таймаутов | + роль сервера, IPv6, USB, GUI, SSH-доступ, порты, сервисы, syslog, auditd |
| Бэкап `simple`-фиксов | нет | у каждого фикса: файлы, права, юниты systemd, sysctl, пакеты |
| Откат | только password/ssh/firewall | у любой категории; `rollback.sh` в каждом бэкапе, `--rollback DIR`, пункт меню `r` |
| Сторож автоотката | фоновый подпроцесс | `systemd-run` (переживает обрыв SSH и `KillUserProcesses=yes`), запасной вариант `setsid` |
| Критичные категории | password, ssh, firewall | + **sudo** (`visudo -c` + предохранитель) |
| Firewall-фикс | `ufw --force reset` + `allow ssh` (порт 22) | без reset; разрешает реальные порты sshd (`sshd -T` + `ss`) и спрашивает про каждый слушающий порт; проверяет SSH-порты до подтверждения |
| Результат | список проблем | повторный аудит после фиксов: «соответствие 52% → 91%» |
| Флот | — | `--save-profile` / `--profile` (профиль не исполняется, ключи по белому списку) |

Попутно исправлены баги исходного движка:

- `ssh_set_param` комментирует строки в `sshd_config.d/*.conf`, а бэкап
  брал только `sshd_config`, поэтому после отката drop-in'ы оставались
  закомментированными. Теперь бэкапится весь `sshd_config.d`.
- `apply_password_policy` записывал `ucredit/lcredit/dcredit/ocredit = -1`
  независимо от ответов «Требовать заглавные/цифры/...». Теперь ответы
  учитываются.
- `cur_profile="$(authselect current | awk ...)"` под `set -e -o pipefail`
  обрывал модуль на системах без активного профиля authselect вместо
  ожидаемого предупреждения.
- `sysctl_persist` нейтрализовал только `/etc/sysctl.conf`, но
  `/etc/sysctl.d/99-sysctl.conf` сортируется после `99-security-audit.conf`
  и перебивал значение. Теперь обрабатываются все файлы `/etc/sysctl.d`.

---

## Разделы

| Меню | CLI | CIS | Что делает |
|---|---|---|---|
| 2 | `--fs` | 1.1 | cramfs/freevxfs/hfs/hfsplus/jffs2 (+squashfs/udf на L2), usb-storage; `/tmp` как tmpfs, `nodev,nosuid,noexec` для `/tmp`, `/dev/shm`, `/var/tmp`, `/home`...; sticky bit; autofs |
| 3 | `--boot` | 1.2–1.5 | gpgcheck/trusted=yes, автообновления безопасности; права `grub.cfg`, пароль GRUB; ASLR, ptrace, core dumps, prelink, apport, dmesg/kptr |
| 4 | `--mac` | 1.6–1.7 | SELinux (не disabled, targeted, enforcing на L2) / AppArmor (включён, enforce на L2); баннеры `/etc/issue`, `issue.net`, `motd` |
| 5 | `--services` | 2.x | ~20 серверных сервисов (спрашивает только про найденные), MTA только на loopback, небезопасные клиенты, один демон времени, cron/at и `cron.allow` |
| 6 | `--network` | 3.x | IPv6, Wi-Fi, dccp/tipc/rds/sctp (L2), все sysctl 3.3.x (текущее значение **и** сохранение в конфиге) |
| 7 | `--firewall` | 4.x | ufw (Debian) / firewalld (RHEL): одна утилита, deny incoming, loopback, правила для открытых портов, опционально deny outgoing |
| 8 | `--ssh` | 5.1 | права на конфиг и ключи, AllowUsers, Banner, Ciphers/MACs/Kex (по `ssh -Q`), ClientAlive, DisableForwarding, GSSAPI, LoginGraceTime, LogLevel, MaxAuthTries/Sessions/Startups, PermitRootLogin, PasswordAuthentication |
| 9 | `--access` | 5.2–5.4 | sudo (use_pty, logfile, timestamp_timeout), PAM (pwquality, faillock, pwhistory, nullok, pam_wheel), login.defs, INACTIVE, UMASK, TMOUT, системные учётки, UID 0, PATH root |
| 10 | `--logging` | 6.x | journald, rsyslog (+удалённый сервер), права `/var/log`, auditd (параметры ядра, ~20 групп правил CIS, `auditd.conf`, `-e 2` на L2), AIDE |
| 11 | `--maintenance` | 7.x | права passwd/shadow/group/gshadow, world-writable, файлы без владельца, SUID, дубликаты UID/GID/имён, домашние каталоги и dot-файлы |

Нумерация пунктов дана по CIS Ubuntu 24.04 / RHEL 9. В других редакциях
бенчмарка номера могут немного отличаться.

---

## Использование

```bash
sudo ./linux_cis_hardening.sh                       # меню (пункт 0 — аудит без вопросов)
sudo ./linux_cis_hardening.sh --audit               # сразу аудит текущих настроек, ничего не меняет
sudo ./linux_cis_hardening.sh --full --report-only  # аудит с учётом ответов опросника
sudo ./linux_cis_hardening.sh --ssh --level 2       # один раздел, профиль L2
sudo ./linux_cis_hardening.sh --save-profile web.conf     # ответить один раз
sudo ./linux_cis_hardening.sh --profile web.conf --full   # повторить на другом сервере
sudo ./linux_cis_hardening.sh --list-backups
sudo ./linux_cis_hardening.sh --rollback /root/security-toolkit-backup-20261102-141500-ssh
```

### Аудит текущих настроек

Пункт **0** в меню (или `--audit`) показывает, как сервер выглядит сейчас
относительно CIS. Он проходит все разделы и выдаёт процент соответствия и
список того, что можно исправить. При этом скрипт ничего не спрашивает и
ничего не меняет, даже бэкапы не создаются. Пока опросник не пройден, пороги
берутся из рекомендаций CIS, а всё, о чём опросник спросил бы (нужен ли
сервис, открыт ли порт, нужен ли SSH-проброс), оценивается по строгому CIS.
Если опросник уже пройден, учитываются ваши ответы.

Опросник запускается только перед первым применением (разделы 1–11), поэтому
пункт 0 открывается сразу после старта.

| Опция | Что делает |
|---|---|
| `--audit` | Аудит текущих настроек: без вопросов, ничего не меняет |
| `--full`, `-f` | Все разделы |
| `--fs`, `--boot`, `--mac`, `--services`, `--network`, `--firewall`, `--ssh`, `--access`, `--logging`, `--maintenance` | Один раздел (есть алиасы из аудита: `--password`, `--pam`, `--accounts`, `--kernel`) |
| `--level 1\|2` | Профиль CIS |
| `--report-only`, `--dry-run` | Только аудит, исправления не предлагаются |
| `--no-interactive` | Без вопросов: пороги из системы, ответы безопасные («ничего не отрезать») |
| `--profile FILE` / `--save-profile FILE` | Загрузить / сохранить ответы |
| `--timeout N` | Секунд на подтверждение перед автооткатом (по умолчанию 180) |
| `--no-rollback-guard` | Отключить автооткат. На проде так делать не надо |
| `--rollback DIR`, `--list-backups` | Ручной откат |
| `--help`, `-h` | Справка |

Без терминала (`/dev/tty`, например в CI) скрипт сам переходит в режим
`--no-interactive --report-only`.

---

## Как применяются исправления

Сценарии те же, что в аудите. Добавлены категория `sudo` и бэкап у `simple`.

| Категория | Как применяется | Валидация до подтверждения |
|---|---|---|
| `password` | цельный модуль `apply_password_policy()` (без точечных sed) | структура PAM-стека, `pam_unix.so`, `/etc/pam.d/su`, `pamtester` |
| `ssh` | батч через `ssh_set_param()` | `sshd -t`, затем `reload` |
| `sudo` | drop-in `/etc/sudoers.d/60-cis-hardening` | `visudo -c` |
| `firewall` | `fw_ufw_configure` / `fw_firewalld_configure` | все SSH-порты разрешены |
| `simple` | каждый фикс отдельно: `[y/N/a(все)/q]` | откат именно этого фикса, если команда упала |

Для `password`, `ssh`, `sudo` и `firewall` после успешной валидации включается
предохранитель. Нужно открыть **новое** SSH-подключение, проверить вход и sudo и
ввести `YES`. Если не ввести, закрыть терминал, нажать Ctrl-C или оборвётся
связь, изменения откатятся. Сторож запускается как
`systemd-run --on-active=…` в `system.slice`, поэтому переживает и обрыв сессии,
и `KillUserProcesses=yes`. Лог пишется в
`/var/log/security_toolkit_autorollback.log`.

### Что лежит в каталоге бэкапа

```
/root/security-toolkit-backup-20261102-141500-ssh/
├── CATEGORY        ssh
├── MANIFEST        F|/etc/ssh/sshd_config|present
│                   F|/etc/ssh/sshd_config.d|present
│                   F|/etc/issue.net|absent          ← при откате будет удалён
├── files/etc/ssh/…  копии с полными путями
└── rollback.sh     самодостаточный: sudo bash rollback.sh
```

Кроме файлов в `MANIFEST` записываются права (`M|путь|mode|uid|gid`),
состояние юнитов (`U|юнит|enabled|active`), прежние значения sysctl
(`S|ключ|значение`), удалённые пакеты (`P|пакет`, при откате переустанавливаются),
фичи authselect (`A|…`) и сервисы, которые нужно перезапустить (`R|…`).

### Защита от самоблокировки

- SSH-порты определяются через `sshd -T` и `ss`, а не берутся как «22». Они
  разрешаются первыми, до смены политики, и проверяются после применения.
- `PasswordAuthentication no` предлагается, только если у администратора
  (`$SUDO_USER`) есть `authorized_keys`.
- В `AllowUsers` администратор добавляется автоматически.
- Если вы зашли по SSH напрямую как root, по умолчанию выбирается
  `PermitRootLogin prohibit-password`, а не `no`, с предупреждением.
- `cron.allow` и `at.allow` создаются вместе с пользователями, у которых уже
  есть crontab.
- Изменения, рискованные для доступа или загрузки, по умолчанию выключены и
  требуют явного «да»: пароль GRUB, `admin_space_left_action=single`,
  `even_deny_root`, `aa-enforce` для всех профилей, включение SELinux из
  disabled, `deny outgoing`.

---

## Соответствие требованиям security_audit_linux

| Требование (README исходного репозитория) | Как выполнено |
|---|---|
| Чистый Bash, один файл, без зависимостей вне базовой системы | один файл; опциональные утилиты используются, если установлены |
| Bash 4.3+, GNU coreutils/grep/sed, systemd | проверка версии Bash при старте; пустые массивы раскрываются через `${a[@]+…}` (безопасно под `set -u` в 4.3) |
| Интерактивная настройка порогов, дефолты из текущих настроек системы | `seed_defaults_from_system()`. Рекомендация CIS показывается рядом, и при более слабом значении скрипт спрашивает, оставить ли его |
| Меню: параметры вводятся один раз, `s` перенастроить, `q` выход | да, плюс `0` (аудит без вопросов), `r` (откат) и `p` (сохранить профиль). Опросник проходится один раз, но не при старте, а перед первым применением |
| One-shot режим, `--no-interactive`, `--report-only`, `--timeout N`, `--no-rollback-guard`, `--help` | все есть, `--timeout` проверяется (целое ≥ 10) |
| Отчёт в `/tmp`, права `600`, без ANSI | `/tmp/cis_hardening_<host>_<дата>.txt`, создаётся под `umask 077`, ANSI вырезается |
| Без root: предупредить и продолжить | да; без root фиксы не предлагаются |
| password: без точечных правок, бэкап, `set -e`-подпроцесс, валидация + `pamtester`, откат при ошибке | да |
| Debian: вставка `pam_faillock` в `common-auth`; RHEL: `authselect enable-feature`; нештатный стек (SSSD/LDAP/AD) или нет модуля → не трогать | да, логика перенесена без изменений, добавлены `without-nullok` и проверка поддержки фичи профилем |
| ssh/firewall: бэкап, `sshd -t` перед `reload`, откат при невалидном конфиге | да |
| `ssh_set_param`: комментировать в drop-in'ах, вставлять первой строкой | да, плюс бэкап drop-in'ов |
| simple: показать описание и команду, подтверждение `[y/N/q]` | да, плюс `a` (все оставшиеся) |
| sysctl в `/etc/sysctl.d/99-security-audit.conf`, идемпотентно, нейтрализация `sysctl.conf` | тот же файл, что у аудита, поэтому инструменты не конфликтуют |
| Предохранитель: YES из нового сеанса, таймаут, Ctrl-C/закрытие терминала → откат, лог в `/var/log/security_toolkit_autorollback.log` | да, плюс SIGHUP и атомарный «захват» маркера (без гонки сторожа и ввода YES) |
| `bash -n` чисто, `shellcheck -s bash -S style` чисто | чисто (ShellCheck 0.11.0) |
| `--full --report-only` → 0 байт в stderr | 0 байт на L1 и L2 и в каждом разделе отдельно |
| Никаких изменений в обход `add_fix` / `safe_apply_batch` | все изменения регистрируются через `add_fix` и выполняются движком |

---

## Требования

- **Bash 4.3+**, GNU coreutils, `grep`, `sed`, `awk`, `find`
- `systemd` (юниты, journald, `systemd-run` для сторожа)
- root, чтобы применять исправления
- Debian/Ubuntu/Astra или RHEL/CentOS/Rocky/Alma/Oracle. На Alpine/busybox
  работать не будет.

Опционально: `ss`, `findmnt`, `ausyscall`, `aa-status`/`getenforce`,
`authselect`, `pamtester`, `grubby`, `ufw`/`firewall-cmd`, `aide`.

## Как протестировано

Скрипт гонялся на стенде: копия, в которой все системные пути (`/etc`, `/root`,
`/var`, `/boot`, `/home`) перенаправлены в фейковый корень Ubuntu 24.04 или
Rocky 9, а `systemctl`, `sysctl`, `sshd`, `ssh -Q`, `ufw`, `firewall-cmd`,
`authselect`, `visudo`, `apt-get`/`dnf`, `chage`, `useradd` заменены заглушками,
которые ведут журнал вызовов и хранят состояние. Проверено:

| Сценарий | Результат |
|---|---|
| SSH: 14 фиксов, `sshd -t`, YES | применено, повторный аудит 33% → 81% |
| SSH: ответ «no» / EOF в окне подтверждения | `/etc/ssh` и `issue.net` побайтово как до запуска |
| SSH: невалидный конфиг (`sshd -t` падает) | откат до окна подтверждения |
| Основной процесс убит `kill -9` в окне подтверждения | фоновый сторож откатил изменения и записал лог |
| PAM/пароли Debian | faillock вокруг `pam_unix`, pwquality, pwhistory, nullok убран, pam_wheel; 22% → 88% |
| PAM/пароли RHEL (authselect) | включены 3 фичи; откат выключает только их, фичи пользователя остаются |
| ufw / firewalld | SSH-порт 2222 найден и проверен; cockpit убран и порт 80 открыт по ответам; 50% → 100% |
| Сервисы | avahi и cups замаскированы; откат возвращает enabled + active |
| `--full`, «да» на всё, затем откат всех бэкапов | `/etc` и `/home` побайтово как до запуска, sysctl и юниты идентичны, удалённый `telnet` переустановлен |
| `--full --report-only` от root | ни одного изменения и бэкапа, 0 байт в stderr |

На настоящем ядре (живые `sshd -T`, `augenrules`, `aideinit`, `update-grub`,
SELinux) скрипт не запускался. Перед продом прогоните его на тестовой ВМ.

## Ограничения

- Пакеты, которые скрипт **установил** (auditd, aide, chrony, ufw,
  libpam-pwquality...), при откате не удаляются: удаление может задеть
  зависимости. Пакеты, которые скрипт **удалил**, при откате переустанавливаются.
- Переразметку дисков (`/var`, `/var/log/audit`, `/home` на отдельных
  разделах) скрипт только отмечает в отчёте. Делать её нужно вручную.
- Часть изменений вступает в силу после перезагрузки: параметры ядра в GRUB,
  `/tmp` как tmpfs, запрет модулей, `-e 2`, включение SELinux. Скрипт об этом
  пишет.
- Транзиентный таймер `systemd-run` не переживает перезагрузку. Если сервер
  перезагрузится в окне подтверждения, откатите вручную через `rollback.sh`.
- Скрипт не заменяет официальный CIS-CAT и Lynis. Для формального аудита
  прогоните ещё и их.

## Разработка

```bash
bash -n linux_cis_hardening.sh
shellcheck -s bash -S style linux_cis_hardening.sh       # должно быть чисто
sudo ./linux_cis_hardening.sh --full --report-only --no-interactive 2>/tmp/err && wc -c /tmp/err   # 0 байт
```

Новые проверки добавляйте только через `add_fix` с примитивами `conf_set`,
`write_file`, `fix_perm`, `sysctl_set`, `svc_disable`, `pkg_remove`,
`kmod_disable`. Они сами пишут бэкап, поэтому откат работает автоматически.

## Лицензия

MIT
