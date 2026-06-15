# BitNinja nftables Verification Flow

Ручная проверка работы BitNinja Feature beta на nf_tables/nftables (VAP / AlmaLinux).

Только команды, без скриптов. На каждом шаге, где указано **до / после**, выполните
команду дважды и сравните вывод вручную.

---

## Подготовка (требования тикета)

### 1. Feature beta

**Установка на Feature beta:**

```bash
curl https://get.bitninja.io/install.sh | sudo /bin/bash -s - \
  --license_key=YOUR_KEY_HERE \
  --updateChannel=feature
```

**Проверка Feature beta (обязательно):**

```bash
bitninjacli --version
yum info bitninja
```

Ожидается: версия/build соответствует Feature beta (сверить с BitNinja support / frontend).

**Проверка канала (опционально, best-effort):**

```bash
grep -R "feature" /etc/bitninja/ /opt/bitninja/ 2>/dev/null
```

### 2. IpFilter.json (CloudConfig пока не поддерживает)

CloudConfig **не содержит** настройку для этого релиза — правка только вручную.

Файл: `/opt/bitninja/Common/AgentConfigSchema/IpFilter.json`

На **строке 58** в массиве `"required"` удалить `"networkManager"`.

Проверка (ожидается **пустой вывод**):

```bash
grep -n "networkManager" /opt/bitninja/Common/AgentConfigSchema/IpFilter.json
```

Справочно — ожидаемый `"required"`:

```json
"required": ["depends", "message_pull_limit", "message_polling_time", "apiservers", "closeDirectAccess", "ipc_num"]
```

Перезапуск:

```bash
service bitninja restart
```

### 3. Системные требования (KB)

```bash
uname -r
bpftool --version
jq --version
yum install -y iproute-tc
```

Ожидается: kernel ≥ 5.14, `bpftool` и `jq` установлены.

---

## Step 1 — Хост на nf_tables backend

### Команды

```bash
cat /etc/system-release
uname -r
iptables -V
readlink -f /usr/sbin/iptables
lsmod | grep nf_tables
```

### Ожидается

- В выводе `iptables -V` есть `(nf_tables)`.
- Путь не указывает на `iptables-legacy`.

### Ошибка

- `(nf_tables)` отсутствует или backend — legacy.

---

## Step 2 — nftables-интеграция BitNinja активна

### До (агент остановлен)

```bash
service bitninja stop
iptables -V
iptables-save
iptables -L -n -v
nft list ruleset
nft list table ip bitninja
ls -la /sys/fs/bpf/
service bitninja start
```

Подождать 2–5 минут.

### После (агент запущен)

```bash
service bitninja status
bitninjacli --module=IpFilter --status
iptables -V
iptables-save
iptables-save | grep -i bitninja
iptables -L -n -v
iptables -L -n -v | grep -i bitninja
nft list ruleset
nft list table ip bitninja
ls -la /sys/fs/bpf/
```

### Ожидается

| Проверка | До | После |
|---|---|---|
| `iptables -V` | nf_tables | **тот же backend** |
| `table ip bitninja` | нет или пусто | **есть**, с chains/sets/rules |
| `/sys/fs/bpf/` | без BitNinja | **есть** pinned maps |
| IpFilter | — | модуль **running** |

В `nft list ruleset` должна быть таблица:

```
table ip bitninja { ... }
```

### Логи

```bash
tail -30 /var/log/bitninja/IpFilter.log
tail -30 /var/log/bitninja/main.log
grep -i nft /var/log/bitninja/main.log | tail -20
grep -i policier /var/log/bitninja/main.log | tail -20
```

### Ошибка

- После старта нет `table ip bitninja`.
- `iptables -V` сменился на legacy.
- В логах: `compatibility check failed`, `failed to initialize nftables`, `networkManager`.

---

## Step 3 — iptables не требует legacy

### До перезапуска агента

```bash
iptables -V
update-alternatives --display iptables
iptables-save | grep -i bitninja
nft list table ip bitninja
```

### Действие

```bash
service bitninja restart
```

Подождать 30–60 секунд.

### После перезапуска

```bash
iptables -V
update-alternatives --display iptables
rpm -q iptables-legacy
iptables-save | grep -i bitninja
iptables -L -n -v | grep -i bitninja
nft list table ip bitninja
```

### Ожидается

- Backend `iptables -V` **не изменился** (до = после).
- `table ip bitninja` **восстановилась** после restart.
- В логах **нет** требования перейти на iptables-legacy.
- Если BitNinja виден в `iptables-save`, таблица `ip bitninja` **тоже** должна быть.

### Логи

```bash
grep -i iptables-legacy /var/log/bitninja/main.log | tail -20
grep -i legacy /var/log/bitninja/IpFilter.log | tail -20
```

### Ошибка

- Блокировка только в `iptables-save`, но нет `nft list table ip bitninja`.
- Логи требуют `update-alternatives --set iptables /usr/sbin/iptables-legacy`.

---

## Step 4 — Блокировка IP (KB: bitninja-policier)

### До блокировки

```bash
iptables -V
iptables-save | grep -i bitninja
nft list table ip bitninja
```

### Действие

С внешнего IP вызвать блокировку (failed login, honeypot) или заблокировать IP в BitNinja console.

Подождать ~30 секунд.

### После блокировки

Заменить `1.2.3.4` на тестовый IP:

```bash
/var/lib/bitninja/policier/bitninja-policier check --elem 1.2.3.4
/var/lib/bitninja/policier/bitninja-policier check --elem 1.2.3.4 --show-range
iptables -V
iptables-save | grep -i bitninja
iptables-save | grep 1.2.3.4
nft list table ip bitninja
nft list table ip bitninja | grep -i counter
ls -la /sys/fs/bpf/
```

С заблокированного хоста:

```bash
curl -v --max-time 10 http://SERVER_IP/
curl -v --max-time 10 https://DOMAIN/
```

### Ожидается

- `bitninja-policier check` **находит** IP.
- С заблокированного хоста — timeout / refused / captcha, **не** HTTP 200.
- `iptables -V` до и после **одинаковый**.
- IP виден в BitNinja console.

### Логи

```bash
grep 1.2.3.4 /var/log/bitninja/IpFilter.log | tail -20
```

### Ошибка

- IP в console, но `bitninja-policier check` — пусто.
- Блок только в iptables, не в nft/BPF.

---

## Step 5 — Редиректы / white screen

### До теста в браузере

```bash
iptables -V
iptables-save | grep -i bitninja
nft list table ip bitninja
grep redirection_mode /etc/bitninja/WAFManager/config.ini
```

### Действие

В incognito открыть:

- `https://yourdomain/` — обычная страница
- path с captcha/challenge — страница challenge
- `http://yourdomain/` — редирект на HTTPS

### После теста в браузере

```bash
iptables -V
iptables-save | grep -i bitninja
nft list table ip bitninja
curl -sS -o /tmp/page.html -w '%{http_code} %{size_download}\n' https://yourdomain/
wc -c /tmp/page.html
```

### Ожидается

- Страницы **не** белый экран; HTML с `<body>`.
- `iptables -V` и nft table **без неожиданных изменений** до/после.
- HTTP→HTTPS работает.

### Логи

```bash
tail -30 /var/log/bitninja/WAFManager.log
grep -i redirect /var/log/bitninja/WAFManager.log | tail -20
grep -i captch /var/log/bitninja/WAFManager.log | tail -20
```

### Ошибка

- Белый экран в браузере при HTTP 200.
- В логах WAF: ошибки `iptables` / `REDIRECT` / `TPROXY`.

---

## Step 6 — Проверка после lifecycle-событий

Для **каждого** события: выполнить блок **«До»**, провести событие, выполнить **«После»**, сравнить.

### Команды «До» (одинаковые для всех событий)

```bash
service bitninja status
iptables -V
iptables-save
iptables-save | grep -i bitninja
nft list table ip bitninja
ls -la /sys/fs/bpf/
grep -n "networkManager" /opt/bitninja/Common/AgentConfigSchema/IpFilter.json
```

### События

| # | Событие | Действие |
|---|---|---|
| 6.1 | Restart agent | `service bitninja restart` или VAP → Restart Agent |
| 6.2 | Node restart | Перезапуск контейнера в VAP |
| 6.3 | Environment restart | Stop / Start environment |
| 6.4 | Agent Update | VAP add-on → Agent Update |
| 6.5 | syncConfigs | `bitninjacli --syncconfigs` |
| 6.6 | Uninstall | Удалить add-on BitNinja |

### Команды «После»

```bash
service bitninja status
iptables -V
iptables-save
iptables-save | grep -i bitninja
nft list table ip bitninja
ls -la /sys/fs/bpf/
grep -n "networkManager" /opt/bitninja/Common/AgentConfigSchema/IpFilter.json
bitninjacli --module=IpFilter --status
```

Для 6.1–6.5 дополнительно повторить Step 4 (блокировка IP).

### Ожидается

| Событие | После |
|---|---|
| 6.1–6.5 | `table ip bitninja` **есть**; `iptables -V` **не сменился**; `grep networkManager` — **пусто**; блокировка работает |
| 6.5 syncConfigs | `grep networkManager` по-прежнему **пусто** (риск отката — проверить явно) |
| 6.6 Uninstall | `rpm -qa bitninja` пусто; `table ip bitninja` **нет**; в `iptables-save` **нет** bitninja |

После uninstall:

```bash
rpm -qa | grep bitninja
nft list ruleset | grep bitninja
iptables-save | grep -i bitninja
ls /opt/bitninja
```

### Ошибка

- После restart/update пропала `table ip bitninja`.
- `grep -n "networkManager" …` возвращает строки (должен быть пустой вывод).
- Backend переключился на legacy.
- После uninstall остались orphan rules.

---

## Pass criteria

| # | Критерий |
|---|---|
| 1 | Feature beta: `bitninjacli --version` + `yum info bitninja`; `grep networkManager` — пусто (подготовка) |
| 2 | Kernel ≥ 5.14, `bpftool`, `jq` (Step 1) |
| 3 | `table ip bitninja` populated; iptables backend стабилен до/после (Step 2–3) |
| 4 | `bitninja-policier check` + блокировка с внешнего IP (Step 4) |
| 5 | Нет white screen; WAF/captcha работают (Step 5) |
| 6 | nft + iptables стабильны после lifecycle; `IpFilter.json` не откатывается (Step 6) |

## References

- [BitNinja nftables Compatibility Guide](https://knowledgebase.bitninja.io/kb/bitninja-nftables-compatibility-guide/)
