# JE-76574 — прогресс по findings

Рабочий файл для передачи состояния между AI-агентами. Тикет: [JE-76574](https://virtuozzo.atlassian.net/browse/JE-76574)
«[Bitninja] Update WAF module configuration to latest changes on vendor side», Critical, In Progress.
Первичный отчёт QA: `bitninja-waf-pro-report-2026-09-15.pdf` (вложение в тикете, 7 findings).

**Суть тикета:** в BitNinja 3.16.0 WAF 2.0 (`WAFManager`, nginx/HAProxy) заменён на WAF Pro
(`WAF3`, Caddy + coraza/CRS). Add-on на новый модуль не миграли. При `"enabled": true` публичная
LFI-проба возвращает HTTP 200 и весь `/etc/passwd` — правила не оцениваются.

## Стенды

| Стенд | Кто использовал | Конфигурация |
| --- | --- | --- |
| `node826538-bitninja-firewall-enabled.madrid.jele.io` | QA (отчёт 14–15 сен) | manifest v6.0.1, агент 3.17.1, bitninja-waf3 1.1.1, триал-лицензия |
| `node420139-env-111222333.demo.jelastic.com` (`164.132.8.67`) | текущая сессия (17 сен) | манифест из рабочей копии, агент 3.17.3, AlmaLinux 9.8, лицензия `no_payment` |
| `bitninja-firewallqquota0` | QA | парный контрольный env, firewall quota = 0 |

Версия манифеста в работе: **6.1.0** (была 6.0.1).

## Сводка статусов

| # | Finding | Severity / Owner | Статус |
| --- | --- | --- | --- |
| 1 | WAF Pro не генерирует proxy-конфиг, WAF инертен | Critical / вендор | подтверждён, нужна эскалация |
| 2 | `configureWAF` правит мёртвый компонент, extIP-хуки устарели | High / JPS | закрыт частично |
| 3 | Несовпадение паттерна `retain_rights` ломает File Manager | High / JPS | закрыт |
| 4 | `makeLogsVisible` не создаёт симлинки, логи нечитаемы | Medium / JPS | закрыт, не проверен на ноде |
| 5 | Устаревший список портов: нет 60415, мертвы 60300/60301 | Low / JPS | закрыт |
| 6 | Несовпадение паттерна в `denyPortHoneypot` | Low / JPS | закрыт, остаётся union с облаком |
| 7 | Нет enforcement IPv6 за IPv6-ветвью кода | Low / JPS | закрыт |

Дополнительно найдено в этой сессии и не входит в тикет: см. раздел «Инфраструктурные проблемы».

---

## Finding 1 — WAF Pro не генерирует proxy-конфиг

**Проблема из тикета.** Critical, owner — BitNinja vendor. `/opt/bitninja-waf3/config.json` это
вендорская демка: Caddy `static_response` «Hello, World!» на `:6001`, timestamp совпадает с
RPM-бинарём, конфиг никогда не регенерируется. Модуль принимает console toggle, логирует
`Received command [\TurnOnOffCommand]` → `Subscribed to the message queue`, шага генерации конфига
нет и ошибки нет. Итог: ничего не слушает 60414/60415, все 13 WAF3 nft-цепочек пусты, правила не
оцениваются. Всё остальное на диске есть: CRS в `coreruleset/`, блок-страница `www/403.html`,
honeypot-ассеты, полный nginx в `nginx/sbin/nginx` без systemd-юнита.

**Описание.** Подтверждено независимо на `164.132.8.67` (агент 3.17.3, то есть свежее, чем у QA):
`config.json` дословно содержит `static_response` «Hello, World!» и `"listen": [":6001"]`,
`N-BN_WAF_REDIR` пуста при девяти существующих WAF-цепочках, `backendServer='Auto'`,
nginx-бинарь лежит в `/opt/bitninja-waf3/nginx/sbin/nginx`, `bitninjacli --module=WAF3 --regenerate`
не меняет mtime `config.json`.

Два расхождения с отчётом, важных для эскалации:

- QA пишет «Caddy does not fail to start ... just running the demo config» и упоминает admin API на
  `localhost:2019`. На нашем стенде Caddy **не запущен вообще**: не слушаются ни `:6001`, ни `:2019`,
  `/var/log/bitninja-waf3/` пустой, юнит `bitninja-waf3.service` в состоянии `disabled/disabled`.
- Лицензия у нас `no_payment`, у QA — триал. В `main.log` есть прямые записи вида
  `Module [WorkerAuditManager] hasn't been started because of no_payment licence` (также
  MalwareScanner, OutboundHoneypot), но `WorkerWAF3` при этом стартует. Это усиливает
  «secondary candidate» из отчёта про лицензионный гейтинг: два разных типа лицензии дают
  одинаковую инертность WAF.

**Фикс.** На стороне JPS не лечится. Что сделано: `enableWAF3` больше не выдаёт ложный сигнал
успеха. После включения проверяются слушатель на 60414/60415 и непустая `N-BN_WAF_REDIR`, и при их
отсутствии печатается предупреждение со ссылкой на этот finding. Отчёт отдельно предупреждает, что
`--module=WAF3 --status` обманчив: непустой `pid` — это PHP-модуль, а не прокси.

**Как проверить.**

```bash
bitninjacli --module=WAF3 --status              # "enabled": true, pid — это PHP-модуль
ss -tlnp | grep -E '60414|60415'                # пусто == инертен
cat /opt/bitninja-waf3/config.json              # ищем static_response "Hello, World!" и :6001
ls -l /opt/bitninja-waf3/config.json            # 688 байт, дата сборки RPM
nft list chain ip bitninja N-BN_WAF_REDIR       # {} == редиректов нет
systemctl status bitninja-waf3                  # на нашем стенде disabled
curl -sI "http://127.0.0.1/?f=../../../../etc/passwd"   # 200 + Server: Apache == WAF не перехватывает
```

**Следующий шаг.** Эскалация в BitNinja support с `config.json`, `mod.waf3.log` и обоими случаями
(триал 3.17.1 и `no_payment` 3.17.3). Пока не решено — add-on не должен утверждать, что WAF-защита
доступна.

---

## Finding 2 — `configureWAF` правит мёртвый компонент, extIP-хуки устарели

**Проблема из тикета.** High. `globals.WAFConfig` указывал на `/etc/bitninja/WAFManager/config.ini`.
Каталог всё ещё поставляется, поэтому ошибки нет, но строки `redirection_mode` в файле больше нет —
`sed` не матчит ничего и выходит с 0. Вся WAF-логика в JPS была молчаливым no-op. То же относится к
`onAfterAttachExtIp`, `onBeforeDetachExtIp` и `onAfterSetExtIpCount` → `manageWAFModule`: они
существовали только потому, что WAF 2.0 в transparent-режиме создавал редиректы для публичных IP.
WAF Pro не привязан к интерфейсам. Рекомендация отчёта: удалить `configureWAF`, `disableWAF`,
`checkExtIPs`, `globals.WAFConfig` и три extIP-хука, а локальное управление вести через
`bitninjacli --module=WAF3 --status|--enabled|--disabled`.

**Описание.** Мёртвый компонент из манифеста убран полностью: `grep -nE
'WAFConfig|configureWAF|disableWAF|checkExtIPs|WAFManager'` по `manifest.jps` пустой. Управление идёт
через `bitninjacli --module=WAF3`, как рекомендует отчёт. Дополнительно проверено на ноде: в агенте
3.17.3 модуля `WAFManager` больше нет — `bitninjacli --module=WAFManager --status` отвечает
`Module name is required` и перечисляет доступные модули, среди которых только `WAF3`.

**Не закрыто:** три extIP-хука сохранены и теперь вызывают `waitBitNinjaReady` → `enableWAF3` →
`persistCloudConfig`. Отчёт считает их бессмысленными для WAF Pro. Решение за человеком: удалить
хуки или оставить (аргумент «оставить» — `--regenerate` после смены IP, но поскольку генерации
конфига нет вообще (finding 1), аргумент пока пустой).

**Как проверить.**

```bash
# в репозитории
grep -nE 'WAFConfig|configureWAF|disableWAF|checkExtIPs|WAFManager' manifest.jps   # пусто
# на ноде
bitninjacli --module=WAFManager --status    # "Module name is required" == модуля нет
grep -nE "^;?(redirection_mode|interface)" /etc/bitninja/WAFManager/config.ini     # пусто
```

---

## Finding 3 — `retain_rights` и доступ File Manager к `/etc/bitninja`

**Проблема из тикета.** High. Формат конфига изменился, подстановка не матчила: JPS ожидал
`;retain_rights = 0`, в файле `retain_rights=0`. При `retain_rights=0` BitNinja переужесточает
`/etc/bitninja` до `700`, что уводит ACL-маску в `mask::---` и делает `group:ssh-access:rwx`
неэффективным — favourite в File Manager нечитаем для пользователя контейнера. Отчёт отдельно
подчёркивает: **ключ теперь присутствует в обоих файлах** — `System/config.ini:23` и
`WAF3/config.ini:23`. Рекомендация: исправить паттерн на `^retain_rights=0` в обоих файлах, затем
`chmod 755 /etc/bitninja` + `jem filemanager extendperm`.

**Описание.** Паттерн был исправлен раньше (`sed -E` с `^[;[:space:]]*retain_rights...`), но правка
применялась только к `System/config.ini`. На ноде это видно буквально:
`System/config.ini:23:retain_rights=1` (наша правка работает, каталог 775, `mask::rwx`), а
`WAF3/config.ini:23:retain_rights=0` — то самое, о чём предупреждал отчёт.

**Фикс.** `addFavoriteDir` теперь проходит по всем `/etc/bitninja/*/config.ini`, где встречается
ключ, и печатает список исправленных файлов. Права и `extendperm` вынесены в отдельный
`fixBitNinjaPerms`, который в `applyPlatformConfig` вызывается ещё раз **после**
`persistCloudConfig` — чтобы восстановить права, если облачный sync/reload их переужесточил.
Порядок важен: правки конфигов идут до `persistCloudConfig`, иначе они не попадут ни в push, ни в
reload.

**Как проверить.**

```bash
grep -n retain_rights /etc/bitninja/*/config.ini   # везде должно быть 1
stat -c '%a' /etc/bitninja                          # 775 (не 700)
getfacl -p /etc/bitninja | grep mask                # mask::rwx (не mask::---)
grep -q '/etc/bitninja' /etc/jelastic/extendperm.conf && echo extendperm-ok
```

---

## Finding 4 — `makeLogsVisible` не создаёт симлинки, логи нечитаемы

**Проблема из тикета.** Medium. В `/var/log/httpd/` нет записей BitNinja, в `/var/log/` нет
симлинков — действие no-op. `/var/log/bitninja-ssl-termination` не существует вообще (мёртвая ветка
WAF 2.0). WAF Pro пишет в `/var/log/bitninja-waf3/` (`current.log`, `audit.log`, `tls.log`), это не
экспонируется. Отдельно: все `/var/log/bitninja/mod.*.log` имели `-rw------- root:bitninja` и были
нечитаемы для пользователя `apache`, под которым работает дашборд.

**Описание.** Права починены ранее и подтверждены на ноде: `mod.waf3.log` теперь `-rw-r--r--`,
каталоги 755, apache читает `main.log` и waf3-логи. Ветки `bitninja-ssl-termination` в манифесте нет.
Но симлинков по-прежнему не было: при пустом `${response.path}` путь становился `/var/log`, где
`link_log` пропускал создание, потому что `/var/log/bitninja` там уже существует как настоящий
каталог. То есть JS-часть (`GetLogsList`) на этом типе ноды не отдаёт путь, а shell-фолбэк был
бесполезен.

**Фикс.** В shell-части `makeLogsVisible` добавлено определение реального каталога веб-сервера:
если `${response.path}` пуст или не существует, перебираются `/var/log/httpd`, `/var/log/nginx`,
`/var/log/apache2`, `/var/log/litespeed`, и только потом фолбэк на `/var/log`. Выбранный путь
печатается в лог действия. Линкуются оба каталога — `/var/log/bitninja` и `/var/log/bitninja-waf3`.

**Как проверить.**

```bash
ls -la /var/log/httpd/ | grep -i bitninja    # ожидаем bitninja и bitninja-waf3 симлинками
ls -l /var/log/bitninja/mod.waf3.log          # -rw-r--r--
ls -ld /var/log/bitninja /var/log/bitninja-waf3   # 755
sudo -u apache head -1 /var/log/bitninja/main.log # читается
```

**Не проверено:** на `164.132.8.67` фикс ещё не прогонялся (создание симлинков — мутация).
На момент последней проверки `/var/log/httpd` существует, записей bitninja в нём нет — то есть
условия для срабатывания фикса корректные.

---

## Finding 5 — устаревший список портов firewall

**Проблема из тикета.** Low. Список открывал 60300/60301 (мёртвые прокси WAF 2.0) и не открывал
60415 (WAF Pro HTTP; 60414 — HTTPS). Отчёт отмечает, что сейчас это безвредно: BitNinja ставит свою
базовую цепочку `F-INPUT` с приоритетом `filter - 1` и выдаёт terminating accept раньше платформенного
firewall, а `M-BN_SD_IP` уже отбрасывает 60414/60415 из нелокальных источников. Это уборка, а не
функциональный баг, но перепроверить надо после исправления finding 1.

**Описание и фикс.** В `allowFirewallPorts` список сейчас `60412, 60413, 60201, 60210, 60211-60250,
60414, 60415`: 60415 добавлен, 60300/60301 отсутствуют. На ноде видны DNAT-правила
`60415 → :80` и `60414 → :443` в `N-OUTPUT-DNAT`, 60300/60301 нет.

**Как проверить.**

```bash
grep -n 'var ports' manifest.jps                      # 60415 есть, 60300/60301 нет
nft -a list chain ip filter INPUT | grep -E 'dport 604'
nft list ruleset | grep -E '60414|60415'
```

---

## Finding 6 — `denyPortHoneypot`

**Проблема из тикета.** Low. Действие должно добавлять `ports[]=12345` и `ports[]=12346` в
`[ports_never_use]`. Ни одного из них нет — фактический список `110, 11211, 113, 143`. Молчаливый
no-op. Отчёт также просит подтвердить, нужно ли вообще исключать 12345/12346 (это SSH-порты Jelastic).

**Описание.** Паттерн исправлен ранее и работает — это опровергает наблюдение отчёта. На ноде
`[ports_never_use]` сейчас содержит `110, 11211, 113, 12345, 12346, 143, 2082, 2083`.

**Остаточная проблема.** 12345/12346 присутствуют **одновременно** в `[ports_never_use]` и
`[ports_always_use]`: наш `never_use` остался на диске, а облачный `always_use` дописался при pull,
потому что при установке `--syncconfigs` упал из-за неготового Redis (см. инфраструктурные проблемы).
Порты при этом не слушаются, так как заняты SSH. Новый порядок в `applyPlatformConfig`
(`waitCloudConfigSync` до правок, затем успешный `--syncconfigs`) должен это закрыть — end-to-end
не проверено, проверка мутирует конфиг и пушит его в BitNinja Central.

**Как проверить.**

```bash
sed -n '/\[ports_never_use\]/,/^\[/p'  /etc/bitninja/PortHoneypot/config.ini | grep -E '1234[56]'  # должны быть
sed -n '/\[ports_always_use\]/,/^\[/p' /etc/bitninja/PortHoneypot/config.ini | grep -E '1234[56]'  # должно быть пусто
ss -lntp | grep -E ':(12345|12346)'   # слушает sshd, не bitninja
```

---

## Finding 7 — IPv6

**Проблема из тикета.** Low. Таблицы `ip6 bitninja` не существует — BitNinja управляет только
IPv4-nftables, поэтому за веткой `configureWAF type: ipv6` не стоит никакого enforcement. Отдельно
отмечено, что `ip6 filter INPUT` имеет policy drop без финального reject-правила, в отличие от
IPv4-аналога. Рекомендация: удалить IPv6-ветку вместе с finding 2 либо задокументировать IPv6 как
незащищённый.

**Описание и фикс.** WAF-ветки `type: ipv6` в манифесте больше нет (удалена вместе с `configureWAF`).
Оставшийся IPv6-код — это только sysctl-форвардинг (`disableIPForwarding` / `backupIPForwarding` /
`restoreIPForwarding`), который к WAF не относится и работает: на ноде live-значения 0/0, бэкап
содержит обе строки. На ноде `nft list tables` даёт `ip filter, ip nat, ip bitninja, ip6 filter,
ip6 nat` — таблицы `ip6 bitninja` действительно нет, вывод отчёта точен.

**Как проверить.**

```bash
nft list tables                                   # ip6 bitninja отсутствовать
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding   # 0 и 0
cat /var/lib/jelastic/keys/bitninja.sysctl.conf.backup    # обе строки
```

---

## Инфраструктурные проблемы (не из тикета, найдены в этой сессии)

Эти пункты объясняют, почему часть findings выглядела «неисправленной» даже после правки паттернов.

### И1. CLI возвращает 0 при неготовом Redis — ретраи были мертвы

При установке `bitninjacli` вызывался до готовности message queue. В `mod.cli.log` видно
`[error] |Cli| Redis client is not available` для `--enabled`, `--regenerate`, `--syncconfigs` и трёх
`--reload`, но процесс завершался с кодом 0. Любая логика `until cmd; do ...` была бесполезна.

В коде агента это `$this->log->error("Could not send command [...]. Error was: $message")`
(`/opt/bitninja/framework/blue/BlueCommandExec.php:464`) — то есть надёжный канал ошибки это **лог**,
а не stdout и не exit code.

**Фикс.** Обёртка над `bitninjacli`, которая запоминает число строк в
`/var/log/bitninja/mod.cli.log` до вызова и грепает только новые строки на
`redis.*not available|could not send command`. Живёт в одном месте: действие `installCliHelper`
кладёт её на ноду как `/usr/local/bin/bn-cli` (heredoc, без сетевых зависимостей), а
`waitBitNinjaReady`, `enableWAF3`, `persistCloudConfig` и `reloadModules` объявляют однострочный
`bn_cli() { /usr/local/bin/bn-cli "$@"; }`. Хелпер проверен на моках: успех → 0, exit 0 с
Redis-ошибкой в логе → 1, реальный ненулевой код → проброс как есть.

**Важно:** `--status`, `--status-all` и `--show-config` выполняются **локально** (в `main.log`:
`Executing module [WAF3] RPC command class [\StatusCommand] locally`) и не касаются Redis, поэтому
как проба готовности они не годятся. Через Redis идут только «send command» операции. Проба в
`waitBitNinjaReady` — идемпотентный `bitninjacli --module=System --reload`.

**Как проверить.** На тёплой ноде `waitBitNinjaReady` печатает `BitNinja command dispatch is ready
after 0s`. Успешный вызов CLI добавляет в `mod.cli.log` одну `[info]`-строку, сбойный — `[error]`.

### И2. Гонка с облачным pull конфигурации

Агент сам подтягивает облачный конфиг через ~2–3 минуты после старта (`GetAndLoadCloudConfigCommand`
→ `Cloud configuration for <Module> saved to ini format successfully` → `Cloud configuration
downloaded.`). Если наши правки лечь раньше pull, они будут перезатёрты. Именно так honeypot попал
в оба списка.

**Фикс.** Действие `waitCloudConfigSync` ждёт маркер `Cloud configuration downloaded.` в
`/var/log/bitninja/main.log`, причём только **после последнего** старта агента:

```bash
tac /var/log/bitninja/main.log | awk '/Starting module initialization/{exit} index($0,"Cloud configuration downloaded."){found=1; exit} END{exit !found}'
```

Вызывается в `applyPlatformConfig` сразу после `waitBitNinjaReady`, то есть до всех правок конфигов.
Проверено на ноде на четырёх сценариях: маркер после последнего старта → готово; дописанный новый
старт без маркера → ждём; старт + маркер → готово; пустой лог → ждём.

**Грабли:** в awk `exit` внутри правила передаёт управление в `END`, и `exit` в `END` перезаписывает
статус. Первая версия из-за этого честно ждала все 180 с.

### И3. Включение WAF3 через CLI не персистентно

`bitninjacli --module=WAF3 --enabled` меняет только рантайм-состояние. Проверено: после
`bitninjacli --module=WAF3 --restart` модуль вернулся в `"enabled": false`. Это соответствует
документации по WAF («only will take effect until the agent is restarted»). Персистентного ключа
`enabled` для WAF3 нет ни в `/etc/bitninja/WAF3/config.ini`, ни в облачном кеше
`/var/lib/bitninja/config/WAF3.json` (там только `caddy`, `core`, `ja4`, `module`, `nginx`, `waf`,
`webserver`), ни в `Main.json` (только логгеры). Вывод: состояние модуля управляется со стороны
BitNinja (дашборд/аккаунт), и JPS не может включить WAF Pro так, чтобы это выжило перезапуск агента.

**Открытый вопрос для человека:** оставить попытку включения с громким WARN, искать способ включения
через облачный API BitNinja, или убрать `enableWAF3` и включать WAF Pro только из дашборда.

### И4. Ретраи по эффекту, а не по коду возврата

`enableWAF3` теперь крутит `--enabled` до тех пор, пока локальный `--status` не покажет
`"enabled": true` (до 5 попыток с интервалом 5 с), и только потом делает `--regenerate`. Проверено на
ноде: модуль перешёл из `false` в `true`, `--regenerate` и `--syncconfigs` прошли без ошибок в логе.

### И5. Порядок и дубли в `applyPlatformConfig`

Итоговый порядок `applyPlatformConfig` (важен, менять осторожно):

```
installCliHelper → waitBitNinjaReady → waitCloudConfigSync → addFavoriteDir
→ denyPortHoneypot → enableWAF3 → persistCloudConfig → reloadModules
→ fixBitNinjaPerms → makeLogsVisible
```

Логика: сначала дождаться готовности CLI и завершения облачного pull, затем все правки ini, затем
один `--syncconfigs` + reload модулей, и в конце восстановление прав и экспонирование логов.
Ранее `addFavoriteDir` вызывался дважды, причём второй раз после `persistCloudConfig` — правка
`config.ini` в нём не попадала ни в push, ни в reload.

### И6. Убранные `service bitninja restart` — не проверено

В рамках этой работы точечные `service bitninja restart` заменены на `--syncconfigs` + `--reload`
(документированный путь BitNinja). Два места требуют проверки на стенде:

- `updateAgent`: раньше было `yum -y install bitninja; service bitninja restart`, теперь рестарта нет.
  Надо убедиться, что `%post` RPM сам перезапускает сервис, иначе после «Agent Update» работает
  старый процесс, а `waitBitNinjaReady` увидит живой сокет старого агента и отрапортует успех.
- `onAfterRedeployContainer`: убран `&& service bitninja restart` после `yum -y install bitninja`.
  Если на свежем контейнере пакет не поднимает сервис, весь `applyPlatformConfig` отработает по
  таймауту и молча выйдет с 0.

Также не проверено: `--syncconfigs` вызывается на каждом `onAfterStart`. Он пушит локальные конфиги
в BitNinja Central, и теоретически может перезатереть настройки, сделанные в панели.

### И7. Автостарт после redeploy

`/etc/rc.d/init.d/jelastic-bitninja` не внесён в `redeploy.conf` (проверено: там только
`/etc/bitninja`, строка 27), поэтому init-скрипт и результат `chkconfig --add` теряются при
redeploy. **Исправлено:** `onAfterRedeployContainer` теперь вызывает `enableInitScript` и
`disableBitNinjaAutoLoad` после установки пакета.

### И8. `chkconfig --del bitninja` не отключает автозагрузку на AlmaLinux 9

Проверено на ноде: `bitninja.service` — нативный systemd-юнит
(`/etc/systemd/system/bitninja.service`), `systemctl is-enabled bitninja` возвращает `enabled`, а
`chkconfig --list bitninja` прямо отвечает, что показывает только SysV-сервисы и не включает
нативные systemd-юниты. То есть после установки агент по-прежнему стартует сам, а не через
`jelastic-bitninja`.

**Исправлено:** `disableBitNinjaAutoLoad` сначала пробует `systemctl disable bitninja`, при
отсутствии systemd падает на `chkconfig --del`, иначе печатает, что автозагрузка уже отключена.

**Как проверить.**

```bash
systemctl is-enabled bitninja        # ожидаем disabled
chkconfig --list jelastic-bitninja   # jelastic-скрипт остаётся on для уровней 2-5
```

Отдельно снята ложная тревога: конструкция `$(ps uax | ... | grep -q bitninja) && ...` в старой
версии действия выглядела сломанной, но статус подставляемой команды пробрасывается корректно —
проверено локально. Проблема была только в `chkconfig`, а не в guard-е.

---

## Оптимизация структуры (17 сен, после ревью)

Функционально эквивалентные изменения, важные для понимания, где что теперь лежит.

- **Три копии `bn_cli` заменены одним хелпером** — см. И1.
- **Полный и лёгкий пути разделены.** `applyPlatformConfig` (установка, redeploy, scale-out) делает
  всё; новый `reloadPlatformConfig` (`installCliHelper` → `waitBitNinjaReady` → `enableWAF3` →
  `reloadModules`) используется в `onAfterStart` и в обеих кнопках. На старте окружения больше нет
  `AddFavorite`, обхода прав по `/etc/bitninja`, `jem filemanager extendperm`, `GetLogsList`,
  симлинков и `--syncconfigs` — это и быстрее, и снимает риск перезатирания настроек дашборда.
- **`persistCloudConfig` разделён**: теперь только `--syncconfigs`, а reload модулей вынесен в
  `reloadModules`. Документированный порядок (правки ini → sync → reload) сохранён.
- **Три хука extIP свёрнуты** в действие `refreshNodeConfig` с `${this.nodeid}`. Вызов
  `persistCloudConfig` из этих путей убран: они не правят ini-файлы, поэтому пушить нечего.
- **`onAfterServiceScaleOut` упрощён** до `disableIPForwarding` → `applyPlatformConfig` →
  `cleanAction` вместо ручного повторения девяти шагов.
- **`allowFirewallPorts` стал идемпотентным** (сначала вызывает `denyFirewallPorts`) и больше не
  хардкодит `nodeGroup: "cp"` — подставляется `${targetNodes.nodeGroup}`, что важно для не-cp
  групп из списка `nodeType` (`mysql`, `storage`, `haproxy` и прочие).
- **`removeLogLinks`** удаляет симлинки логов при деинсталляции, чтобы в каталоге веб-сервера не
  оставались битые ссылки. Логика проверена локально: удаляются только ссылки, ведущие в
  `/var/log/bitninja*`.
- **Адаптивный шаг ожидания** в `waitBitNinjaReady` и `waitCloudConfigSync`: 2 с первые 30 с, затем
  5 с. Окно осталось 180 с, число итераций упало с 90 до 45.
- **Мелочи:** `removeRedeployConfDir` использует `sed '/bitninja/d'` вместо зачистки содержимого
  строки; в `makeLogsVisible` три прохода `chmod` объединены в один `find` с `-o` (группировка
  проверена локально); `api.env.security` приведён к `api.environment.security`; в
  `fixBitNinjaPerms` убран `cat | awk`.

## Открытые решения (нужен человек)

1. **Finding 1** — эскалация в BitNinja support; до её результата WAF Pro неработоспособен.
2. **Finding 2** — удалять ли три extIP-хука (`onAfterSetExtIpCount`, `onAfterAttachExtIp`,
   `onBeforeDetachExtIp`).
3. **И3** — стратегия включения WAF Pro (WARN / облачный API / убрать из JPS).
4. **И6** — вернуть ли явный `service bitninja restart` в `updateAgent` и redeploy; оставлять ли
   `--syncconfigs` на каждом старте окружения.
5. **Finding 6** — прогнать `denyPortHoneypot` + `persistCloudConfig` на стенде (мутирует конфиг и
   пушит в облако).

## Что уже изменено на тестовой ноде `164.132.8.67`

Для честности последующих проверок: рантайм-состояние WAF3 переводилось в `enabled: true`, модуль
WAF3 один раз перезапущен (после чего вернулся в `false`, затем снова включён), модули
`System`/`PortHoneypot`/`WAF3` перезагружены, и несколько раз выполнен `bitninjacli --syncconfigs` —
то есть локальные конфиги (включая `retain_rights=1` и honeypot `never_use`) запушены в
BitNinja Central. Honeypot-конфиг вручную не правился; симлинки логов не создавались.

## Валидация манифеста без стенда

```bash
# YAML + синтаксис всех shell-блоков
python3 - <<'EOF'
import yaml, re, subprocess
d = yaml.safe_load(open('manifest.jps'))
def walk(o, p=""):
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(k, str) and k.strip().startswith('cmd') and isinstance(v, str): yield p+"/"+k, v
            else: yield from walk(v, p+"/"+str(k))
    elif isinstance(o, list):
        for i, v in enumerate(o): yield from walk(v, p+f"[{i}]")
bad = 0
for p, s in walk(d):
    t = re.sub(r'\$\{[a-zA-Z@][\w@.]*\.[\w@.:\[\]]*\}', 'DUMMY', s).replace('${baseUrl}', 'DUMMY')
    r = subprocess.run(['bash', '-n'], input=t, capture_output=True, text=True)
    if r.returncode: bad += 1; print('FAIL', p, r.stderr)
print('YAML OK v%s | cmd blocks failures: %d' % (d['version'], bad))
EOF
```

Placeholder-плейсхолдеры JPS (`${globals.*}`, `${this.nodeid:group}`) при проверке заменяются на
заглушки; shell-переменные (`$n`, `$module`, `$cfg`) остаются как есть.
