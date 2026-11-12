# Настройка конкретной машины и перенос стенда

## Два разных окружения

Текущая лабораторная ВМ пользователя и конечный стенд — **разные машины**. UUID, устройства, mountpoints, объёмы дисков, RAM/CPU, адреса и результаты испытаний текущей ВМ не становятся конфигурацией конечной машины автоматически.

`docs/VM_STORAGE.md` — свидетельства только лабораторной ВМ, а не универсальная инструкция монтирования. Строку fstab из него нельзя копировать на другую машину без проверки и замены параметров. Даже одинаковая метка тома не подтверждает нужную идентичность.

Переносится проект и утверждённые политики; окружение подготавливается и проверяется отдельно. Сам запрос на переносимость не разрешает форматирование, миграцию данных или установку ПО.

## Какие числа относятся к окружению, а какие — к политике

- UUID, пути, адреса и измеренные мощности машины определяются для каждого deployment. Лабораторные ресурсные defaults не являются универсальным профилем.
- **Порог 50% — общее решение пользователя для проекта**, сохраняемое при смене машины. Он не является характеристикой ВМ и не должен становиться произвольно редактируемым пользовательским параметром. Существующее лабораторное наблюдение `would_deny` и принудительный отказ в `final` различаются режимом применения, не величиной порога; в этом изменении режимы не менялись.
- Окно CPU 60 секунд и свежесть метрик 10 секунд — технический baseline текущей политики. При реализации coordinator предусмотреть централизованную версионированную политику для этих параметров с валидацией. Загрузчик именно параметров алгоритма ещё не реализован: deployment-профиль ниже их не изменяет. Само наличие констант не является ошибкой переносимости.
- Ограничения схем API, длины полей и правила idempotency — правила приложения, не host-настройки. Не выносить все числовые константы в `.env` ради формальной настраиваемости.
- Обязательные ограничения задаются только доверенной платформой, а не пользователем/агентом. Нужные параметры должны быть корректны и подтверждены проверками; иначе будущие create/start отклоняются до записи, без небезопасных defaults. Это требование к интеграции, не утверждение о уже подключённом runtime.

## Где менять и смотреть сейчас

| Что | Где смотреть/менять | Правило для новой машины |
| --- | --- | --- |
| Порт веба | `WEB_PORT` в локальной `.env`; описание в `.env.example` | Выбрать доступный порт; проверить фактическую публикацию Compose. |
| Публичный origin кабинета | `AGENT_PLATFORM_PUBLIC_ORIGIN` в `.env` | Указать фактические схему, hostname и порт доступа, не копировать лабораторный localhost без проверки. Для Control UI launch нужен HTTPS origin. |
| Суффикс отдельного Control UI origin | `AGENT_CONTROL_UI_DOMAIN` в `.env` и `control_ui_domain` в `supervisor/runtime.json` | Пусто по умолчанию. Заполнять одинаково только после wildcard DNS/TLS и owner-scoped HTTP/WS proxy; API требует `agent_proxy_v1`, готовый server-resolved sidecar target и смонтированный proxy. Поля сами по себе не создают DNS/TLS/reverse proxy; см. `docs/CONTROL_UI_NETWORKING.md`. |
| Пулы per-agent IPAM | `agent_network_pool` и `frontend_network_pool` в `supervisor/runtime.json` | Оба обязательны только для `agent_proxy_v1`; defaults отсутствуют. Указать два непересекающихся RFC1918 IPv4 supernet, выбранных для целевой машины, после проверки всех host routes и Docker networks. Не копировать диапазоны из лабораторной конфигурации. |
| Приёмка firewall semantics | `state_dir/firewall-acceptance.json`, созданный `scripts/activate_agent_proxy.py` | Отсутствует по умолчанию. Оркестратор повторяет Linux route/nftables и Docker packet-isolation checks и записывает receipt только после обоих PASS. Receipt root-owned, bound к SHA256 `/etc/machine-id`, policy version и точным pools; любой mismatch закрывает gate. |
| Приёмка прямого Ollama-маршрута | `state_dir/ollama-route-acceptance.json`; `ollama_network_pool` и `ollama_egress_interface` в `supervisor/runtime.json` | Отдельный receipt обязателен наряду с базовым proxy/firewall receipt; он привязан к host ID, обоим proxy pools, exact Ollama IPv4 endpoint, отдельному route pool и egress interface. Production IP/pool/interface не выбраны; не использовать синтетические тестовые значения. Linux/nftables/Docker route acceptance не проводилась, поэтому конфигуратор откажет включать Ollama без совпадающего receipt. |
| Network profile | `network_profile_default` в `supervisor/runtime.json` | Default `legacy_none`. `agent_proxy_v1` задавать только после host-bound receipt и с теми же pools/explicit domain; setup CLI откажет при отсутствующем или mismatched receipt. Это не подтверждает Control UI browser/WSS acceptance. |
| Политика Ollama | Первоначальный объект `ollama` в root-owned `supervisor/runtime.json`; выбранная модель хранится в root-owned SQLite `admin_settings` | `null` сохраняет прежний запуск без Ollama. Начальный ID модели переносится в БД один раз; последующие смены сохраняются в SQLite и не переписывают `runtime.json`. Конфигурация OpenClaw фиксирует только выбранную модель: `models.mode=replace`, явный список `models.providers.ollama.models`, точный `agents.defaults.modelPolicy.allow`; встроенные Ollama discovery и node-inference отключены. `contextWindow`/`contextTokens` совпадают с Ollama `params.num_ctx`, `max_tokens` обязателен, `think` по умолчанию false. Для новых Gateway-specs включены `OPENCLAW_CONFIG_READONLY=1`, отдельный read-only bind для `openclaw.json`, владелец root:1000 и mode 0440; при Ollama-policy дополнительно устанавливается/проверяется `FS_IMMUTABLE_FL`. Старые specs без этой политики не запускаются при включённой Ollama. Это пока локальная реализация: вложенный Docker mount, XFS ioctl, запрет RPC и `/api/chat` ещё не приняты на Linux. Для сети добавлены отдельная per-instance bridge/IPAM-планировка, отдельная таблица nft и receipt-first attach/recovery gate; без route receipt Docker network не создаётся и контейнер не стартует. Прямой сырой API всё ещё не ограничивает HTTP-путь или `model` в JSON body; до Broker/upstream enforcement SEC-09 полностью закрытым не считается, а `chat` остаётся выключенным. |
| Смена модели существующих экземпляров | `scripts/update_ollama_model.py` | После применения доверенного runtime config: `sudo python3 scripts/update_ollama_model.py status --config <runtime.json> --enable-host-maintenance`, затем `sudo python3 scripts/update_ollama_model.py set --config <runtime.json> --model-id <APPROVED_ID> --enable-host-maintenance`. Root-only AF_UNIX RPC с проверкой peer UID; compare-and-swap, атомарная замена защищённого конфига, тот же instance ID/data path и перезапуск после firewall/quota/resource checks. Неизвестные конфигурационные изменения приводят к отказу, а не к перезаписи. Пройдены только synthetic local tests; Linux RPC и Docker remount не проверялись. |
| Восстановление после reboot | `desired_state` в `supervisor/runtime.sqlite3`; шаблон `ops/systemd/bezr-supervisor.service.in` | `RestartPolicy=no`; `RuntimeService.reconcile()` восстанавливает только сохранённое намерение `running` после storage/resource gates и подтверждённого firewall receipt; отсутствующие контейнеры не создаёт. Шаблон не отрендерен и не установлен. Linux/systemd reboot и firewall-first приёмка не проведены. |
| Память/CPU веба | `WEB_MEMORY_LIMIT`, `WEB_CPU_LIMIT` в `.env` | Подобрать по ресурсам и замерам новой машины. |
| Доверенные proxy IP | `FORWARDED_ALLOW_IPS` в `.env` | Web-only default — `127.0.0.1`; для host Nginx добавить точный live gateway сети Compose `web`. Supervisor проверяет фактические Docker IPAM/endpoint и не принимает `*` или CIDR. Инструкция: `docs/CONTROL_UI_NETWORKING.md`. |
| Ключ веб-сессий | `WEBUI_SECRET_KEY` в `.env` | Для независимого нового стенда сгенерировать локально через `scripts/init_env.py`; не копировать лабораторный секрет. Генератор не перезаписывает существующую `.env`. |
| Начальная установка веба | `docs/deployment.md`, `compose.yaml` | Инструкция относится к веб-части, не к готовому персональному provisioning. |
| Лабораторный OpenClaw | `lab/openclaw/README.md`, локальная конфигурация лаборатории | Не переносить автоматически лабораторные volumes, pairing и credentials пользователям конечного стенда. |
| Факты текущей ВМ | `docs/VM_STORAGE.md`, исторические снимки в `docs/STAGE3_CONTRACT.md` | Использовать как свидетельства/пример, не как defaults. |
| Стадии и приёмка | `docs/ROADMAP.md`, `docs/verification.md` | Различать проверку текущей ВМ и приёмку нового окружения. |

Реальную `.env` и credentials не коммитить. Не редактировать код вместо локальной конфигурации только ради смены машины. Перенос существующих пользователей, БД, ключей и данных — отдельная миграция, не обычная установка независимого стенда.

## Реализованный загрузчик deployment-профиля

`supervisor/config.py` реализует `validate_profile(data)` и `load_profile(path)`: закрытая schema v1, параметры целевой машины задаются явно, нет hardware defaults или подстановок из `.env`. Профиль используется предшествующим библиотечным coordinator и новой host-service/Docker runtime через доверенный административный snapshot; это не доказывает EDQUOT или поддержку любого другого storage host.

Шаблон — `supervisor/deployment.example.json`. Локальная копия для настройки — `supervisor/deployment.local.json`: этот точный путь исключён из Git и Docker build context. Существующую локальную копию не перезаписывать. Пока автоматически ничего не создаётся.

| Поле JSON | Правило |
| --- | --- |
| `schema_version` | Строго integer `1`, не boolean/float/string. |
| `profile_version` | Явная версия административного профиля, 1–64 ASCII буквы/цифры/`_`/`-`. Coordinator закрепляет SHA256 всего валидированного профиля в SQLite при первом успешном резерве; при изменении содержания нужна новая версия. Hash не является подписью или аутентификацией администратора. |
| `mode` | Явно `lab` либо `final`, выбирается доверенной платформой, не агентом. Смысл режимов не изменён. |
| `storage.backend` | В схеме v1 описан только `xfs_project_quota`. Реальный исполнитель квот ещё не реализован; указание строки backend не подтверждает поддержку на хосте. |
| `storage.mountpoint` | Ожидаемая точка монтирования этой машины: абсолютный POSIX-путь, не `/`, без `.`/`..`, повторных/концевых слэшей. В текущей схеме компоненты ограничены ASCII буквами/цифрами/`_`/`-`/`.` без пробелов; длина пути не более 4096 символов. Это лексическая проверка, не resolve/probe/symlink guard. |
| `storage.expected_uuid` | Ожидаемый UUID именно этой ФС, явно в форме `8-4-4-4-12` hex-символов. Регистр сохраняется; повреждённые значения не нормализуются и не исправляются. |
| `agent_limits.ram_bytes`, `agent_limits.disk_bytes` | Точные байты, положительный integer до `2**63-1`. Квота диска без default: `null` в шаблоне требует явного решения вместо скрытого выбора из 10–15 ГБ. |
| `agent_limits.cpu_millicores` | Положительный integer в millicores: 1000 означает один CPU. Coordinator передаёт их в registry как `cpu_units`; общий CPU-бюджет и физический CPU total задаются в тех же millicores. Конвертация в лимиты Docker ещё не подключена. |
| `agent_limits.pids_limit` | Явный положительный integer до `2**63-1`. Шаблон содержит проверенное лабораторное отправное значение, не универсальный профиль. |

Стартовые RAM/CPU/PIDs в шаблоне соответствуют принятому исходному профилю, но требуют оценки на конечном стенде. `storage.mountpoint`, `storage.expected_uuid` и `agent_limits.disk_bytes` намеренно равны `null`: неизменённый шаблон должен отклоняться, а не подставлять UUID/диск лабораторной ВМ. Все integer-лимиты отвергают bool, дроби, строки и переполнение; грамматическая допустимость числа не доказывает, что хост/backend способен его реализовать.

Проверка из корня проекта после заполнения локальной копии:

```bash
python -m supervisor.config --check supervisor/deployment.local.json
```

Exit 0 означает **только корректность файла профиля**; вывод явно говорит, что storage/runtime не проверены. Exit 2 означает отсутствующий/нечитаемый/невалидный профиль. Профиль читается как UTF-8 JSON размером не более 65536 байт с ограничением самого чтения; дубли ключей на любом уровне, невалидные/нефинитные числа и неизвестные поля отвергаются. Содержимое файла не печатается. Команда не создаёт БД, каталоги агентов, mount или квоты, не вызывает Docker и не разрешает provisioning.

Файл должен задаваться администратором и находиться вне путей, доступных агентам на запись. Проверка владельца/прав самого файла и безопасное подключение к службе ещё не реализованы; чтение JSON не является аутентификацией администратора. В профиль нельзя добавлять `disk_quota_verified`, живые capacity snapshots, `image`, actor или произвольный порог: закрытая схема их отклоняет. Порог 50%, окно CPU 60 секунд и свежесть 10 секунд остаются в действующей чистой политике; этот срез их не меняет.

## Read-only проверка подготовленного XFS backend

После проверки файла на Linux-ВМ выполнить `sudo python3 -m supervisor.storage --check supervisor/deployment.local.json`. Проверяются именно UUID/mountpoint из профиля этой машины, без автоматического принятия обнаруженной идентичности. Выход 0 / backend_ready не разрешает create и не устанавливает disk_quota_verified: назначение и подтверждение персональной hard quota остаются отдельным механизмом. Выход 2 / blocked означает отказ без fallback и изменений ФС. Команды, ограничения и VM-приёмка — `docs/STORAGE_PREFLIGHT.md`.

## Реализованная связка допуска и резервирования

`supervisor/coordinator.py`: `CreateCoordinator(registry, profile, observe, clock)` и `create(actor_id, payload, current_settings_revision=...)`. Это доверенный внутрипроцессный API, не HTTP endpoint. Actor/current draft revision даёт будущая проверенная служба, не поля JSON. Клиент по-прежнему передаёт только action/create, idempotency key и ожидаемую ревизию.

Порядок: валидировать запрос/профиль → BEGIN IMMEDIATE → проверить привязку версии профиля и idempotent replay → для нового запроса проверить ревизию, свежий snapshot и допуск → проверить суммарные бюджеты → атомарно записать profile binding, instance/reserved и operation/queued. Проверка допуска и бюджета не разделены ожиданием SQLite-lock. Изменённый payload под тем же ключом конфликтует. Точный повтор возвращает прежние IDs без нового observe/clock и без повторного допуска; `admission=None, replayed=True` не утверждает, что текущее окружение разрешает запуск.

Provider `observe()` должен быстро читать доверенный cache, без Docker, network, внешних команд или ожидания CPU-окна внутри транзакции. Он возвращает `ResourceObservation`:

- `sampled_at`, `cpu_window_seconds`, `cpu_percent` — одна временная шкала с `clock()`, средняя CPU всей машины; действуют прежние 60 секунд / свежесть не старше 10 секунд / 50%.
- `total_ram_bytes`, `available_ram_bytes`, `total_cpu_millicores`, `total_disk_bytes`, `free_disk_bytes` — физические данные именно целевой машины/настроенного data pool, не снимок лаборатории из документации.
- `capacity_ram_bytes`, `capacity_cpu_millicores`, `capacity_disk_bytes` — **общие потолки суммарных резервов**, после системного/модельного/retained бюджета, не остаток с уже вычтенными резервами экземпляров. Coordinator проверяет типы/int64 и что потолки не превышают physical totals; выбор численных резервов/их реальный сбор не реализован и не заменяется defaults.
- `disk_floor_bytes` — явный свободный остаток для policy; `disk_quota_verified` — только реальное свидетельство доверенного будущего storage backend. Ни корректный профиль, ни XFS Accounting/Enforcement ON сами не устанавливают флаг. До такого backend реальные создания остаются закрытыми.

Несовпадение версии/settings, malformed/stale/future snapshot, нехватка бюджета, исключение provider или ошибка INSERT не оставляют частичный резерв/новый profile binding. Библиотека не ловит их как успешное создание. Новый coordinator не принимает чужой необоснованный `profile_fingerprint`: вычисляет его сам из профиля; registry сохраняет привязку транзакционно и после reopen.

Существующие standalone registry-вызовы со статическими capacities сохранены для прежнего ядра. Но без fingerprint нельзя записывать под уже закреплённой версией; старые записи без истории профиля нельзя молча объявить соответствующими новому JSON. Для них новая привязка той же версии отклоняется (`ProfileVersionConflict`), данные не удаляются; новой конфигурации нужна новая версия. Будущий executor обязан иметь доступ к точному историческому профилю, совпадающему с закреплённым hash, а не применять текущий файл к старой операции. Сейчас хранится fingerprint, не каталог полных исторических профилей.

Ревизия draft — проверенный вызывающей службой snapshot, не блокировка отдельной DraftStore БД. До реального исполнения нужны согласованный snapshot настроек, повторная сверка профиля и свежий runtime admission. Сохранённый queued не является бессрочным разрешением на Docker create/start. Служебная аутентификация, host collector и quota/runtime executor по-прежнему отсутствуют.

## Конфигурация запуска host-service

`supervisor/runtime.example.json` перечисляет отдельные параметры службы и общие budgets; `ollama: null` сохраняет прежний запуск без модели. `scripts/configure_supervisor.py --prepare-host-config` при явном запуске оператором от root создаёт административный snapshot профиля и runtime.json вне user-writable checkout; источник deployment.local.json не переписывается. RuntimeStore закрепляет полный deployment-профиль для этого журнала: менять binding или удалять DB ради нового профиля нельзя, нужна отдельная миграция.

Для явной конфигурации Ollama задаются `--ollama-api-url http://<PRIVATE_IPV4>:11434`, `--ollama-default-model-id <APPROVED_MODEL_ID>` и `--ollama-max-tokens <EXPLICIT_LIMIT>`. Закрытый операторский каталог содержит оба утверждённых ID; provider config каждого нового экземпляра включает только выбранный оператором ID. `contextWindow`, `contextTokens` и `params.num_ctx` согласованы; `--ollama-context-tokens` принимает только 8192 или 16384 (по умолчанию 8192), `--ollama-think` по умолчанию false. 16K требует отдельной проверки совместимости и VRAM. Конфигурация не разрешает маршрут к host, не проверяет health/readiness и не включает chat capability. Без всех обязательных значений Ollama остаётся отключённой. Никогда не использовать loopback, публичный адрес или произвольный URL; endpoint должен быть согласован с отдельной сетевой политикой.

### Защита и смена выбранной модели

Новые Gateway containers используют конфигурационную ревизию 1, отдельный read-only bind mount только для `state/openclaw.json` и `OPENCLAW_CONFIG_READONLY=1`. Файл создаётся владельцем root:1000 с mode 0440; при включённой Ollama policy Supervisor также устанавливает и проверяет `FS_IMMUTABLE_FL`. Каталог с остальным OpenClaw state остаётся writable для сессий и пользовательских данных. В конфиге задан `models.mode=replace`, единственный provider entry содержит только выбранный ID, `modelPolicy.allow` ограничен тем же ID, а Ollama discovery и node-inference выключены. Для закреплённого OpenClaw `7c12438929e5d198616fe8f602d896e011647d39` проверены `docs/concepts/models.md`, `docs/cli/config.md`, `docs/gateway/configuration/config-rpc.md`, `src/gateway/methods/core-descriptors.ts` и `extensions/ollama/index.ts`: config-write RPC требуют `operator.admin`, а встроенный gateway tool имеет только чтение конфигурации; `OPENCLAW_CONFIG_READONLY=1` блокирует config-write пути. Наш trusted-proxy owner не получает `operator.admin`, а `gateway`/`openclaw` tools дополнительно запрещены. Это source review, не live RPC test. Вложенный Docker bind, XFS ioctl и реальный RPC denial ещё требуют Linux acceptance; до неё нельзя закрывать SEC-09. Кроме того, прямой HTTP к Ollama после прокладки сети позволит коду агента послать запрос с иным model ID: сетевой L3/L4 filter не проверяет HTTP path/body. Полная гарантия выбранной модели требует upstream enforcement или отдельного Broker; он остаётся отложенным до приёмки MVP.

Выбранная модель изначально берётся из root-owned `runtime.json` и один раз записывается в таблицу `admin_settings` runtime SQLite. Для смены модели уже созданных экземпляров предусмотрен root-only admin socket и `scripts/update_ollama_model.py`; он не переписывает `runtime.json`, не меняет instance ID или data path и не удаляет Gateway/user data. Операция сверяет ожидаемый текущий ID, останавливает затронутые экземпляры, атомарно меняет управляемые model/tool/plugin subtrees в защищённом `openclaw.json`, записывает новый ID через compare-and-swap и запускает экземпляры через readiness gates. Неизвестный drift в model/agent policy вызывает отказ вместо перезаписи; несвязанные plugin/Gateway settings сохраняются. Пройдены только synthetic local tests; настоящий Linux admin RPC и Docker remount после замены файла не проверялись.

Для существующей runtime DB миграция desired state и таблицы admin selection выполняется только отдельной backup-based процедурой после остановки Supervisor: `python3 scripts/migrate_runtime_desired_state.py --database <runtime.sqlite3> --backup <new-protected-backup.sqlite3> --apply`. Скрипт не запускался на пользовательской DB. После migration running intent сохраняется отдельно от фактического Docker state; при reboot Supervisor не создаёт отсутствующие контейнеры и запускает только ранее desired-running экземпляры после storage/resource/firewall checks.

`ops/systemd/bezr-supervisor.service.in` — только шаблон автозапуска с явными path placeholders. Он не отрендерен, не установлен и не включён. `RestartPolicy=no` сохраняется; Docker не должен самостоятельно запускать Gateway/Sidecar до Supervisor.


Host-service и opt-in Compose bridge реализованы; основной lifecycle на лабораторной ВМ принят по отчёту пользователя для commit `4494d7575b0c7534076684e6d8547477b527a42f`. Это не переносная приёмка для новой машины и не EDQUOT proof. Команды и безопасные границы — `docs/SUPERVISOR_RUN.md`; disk bytes runtime XFS должны делиться на 1024, inode hard limit выводится технически.

## Текущее состояние runtime и перенос

Старая таблица этапов проектирования выше описывает требования, часть которых теперь реализована. Основной host-runtime функционально принят на лабораторной ВМ по пользовательскому отчёту для `4494d7575b0c7534076684e6d8547477b527a42f`; конкретные свидетельства и незакрытые проверки — `docs/verification.md`.

| Параметр | Текущее правило | Остаток |
| --- | --- | --- |
| Host identity/storage | Профиль конкретной машины явно закрепляет mountpoint/UUID и проверяется до runtime provisioning. | На другой машине определить значения заново; не копировать лабораторный UUID/path. |
| Метрики/admission | Есть collector `/proc`/`statvfs`, 60-секундное CPU window, freshness 10 секунд, 50% lab/final policy и durable reservations. | Численные budgets для отдельной машины/модели задавать по её ресурсам. |
| Per-instance resources | На лабораторной ВМ в отчёте показаны 2 GiB RAM, 1 CPU, 256 PIDs, 10 GiB XFS quota assignment/readback. | EDQUOT и полный охват записи не проверены; это не proof для нового host. |
| Host bridge | AF_UNIX + backend credential, web-only default и opt-in Compose bridge; create/lifecycle подтверждены user report. | Есть вопрос по старому контейнеру со старой seccomp при старте нового supervisor; выяснить до следующего rollout, не очищая DB. |
| Data lifecycle | Для commit `2afe2b5` user report подтверждает remove-retain и purge test. Локально есть restore и owner-scoped workspace-only browser с preview/download. | Новые restore/browser изменения не приняты на ВМ; secrets/state исключены; browser E2E/real XFS всё ещё нужен после согласованной доставки. |
| Gateway/model | Gateway health показан отдельно от container state; сеть runtime — none. | Browser Gateway/chat, apply draft updates, model and Telegram не подключены. |

## Проверки перед допуском на новом стенде

1. Администратор задаёт ожидаемые storage identity/path этой машины; не принимать обнаруженный UUID автоматически.
2. Проверить mount/UUID/FSType и quota backend с профильной конфигурацией; отсутствие/несовпадение — отказ без fallback.
3. Задать и подтвердить новые machine budgets; не переносить RAM/CPU/disk values из лаборатории.
4. Перед началом эксплуатации проверить именно новую среду: per-instance EDQUOT, direct API ownership, supervisor recovery и data-preserving lifecycle в пределах согласованного плана.
5. Не включать deployment, systemd/autostart, migration, purge или системные изменения только на основании этой документации; требуется отдельное согласование оператора.

В unit-тестах использовать синтетические device/UUID/resource values. Лабораторная приёмка остаётся действительной для той ВМ, но не заменяет переносную приёмку.
