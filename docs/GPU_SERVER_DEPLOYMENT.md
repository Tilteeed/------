# BEZR: развёртывание на GPU-сервере

Этот документ описывает последовательность подготовки **нового** сервера и
проверку уже работающего стенда. Примеры в [`ops/examples/gpu-server/`](../ops/examples/gpu-server/)
основаны на настройках `sbergigachat`, повторно сверенных с активными файлами
сервера 15 ноября 2026 года. Это **не универсальные значения**: перед применением проверьте адреса, устройства,
лимиты, сертификаты и состояние конкретного хоста. Не запускайте все блоки как
один скрипт. Команды подготовки, записи и запуска меняют систему; проверки
показаны отдельно. На занятом сервере сначала сохраните действующие данные и
проверьте, не существуют ли уже указанные пути и службы.

## Что уже известно о данном стенде

| Компонент | Пример / наблюдение |
| --- | --- |
| Сервер | Ubuntu 22.04, `10.40.240.103`, GPU NVIDIA Tesla P100 12 ГБ; адрес доступен только в соответствующей сети. |
| WebUI | `https://bezr.space`, контейнер публикуется на `127.0.0.1:3000`, перед ним Nginx. |
| Control UI | Предполагаемый отдельный origin для экземпляра `https://<instance-id>.agents.bezr.space`; нужны wildcard DNS, соответствующий сертификат и проверка браузером. |
| Ollama | Уже работает на хосте на `127.0.0.1:11434`. Дополнительный локальный Nginx endpoint — `172.24.3.1:11434`. Вторую Ollama запускать не нужно. |
| Пулы | Agent `172.24.0.0/24`, frontend `172.24.1.0/24`, Ollama `172.24.2.0/24`; endpoint расположен вне этих пулов. |
| Данные | Проект `/opt/bezr`, Docker data-root `/mnt/sdd/docker`, XFS с project quota `/mnt/xfs_data`, исходники OpenClaw `/mnt/sdd/bezr-openclaw-src/openclaw`. |
| Процесс Supervisor | Python 3.12 в `/opt/bezr-python/cpython-3.12.16-linux-x86_64-gnu/bin/python3.12`, runtime `/var/lib/personal-agent-supervisor/runtime.json`, служба `bezr-supervisor.service`. Системный Python 3.10 не заменяется. |

Проверенная программно-аппаратная база: Ubuntu 22.04.1, kernel 5.15,
systemd 249.11, Docker Engine 29, nftables 1.0.2, Nginx 1.18.0,
NVIDIA Tesla P100 12 GiB с driver 580.178.04, 56 логических CPU и 125 GiB RAM.
Версию Ollama нужно записать с конкретного хоста командой `ollama --version`;
не подставляйте версию из чужой установки.

### Снимок активных конфигураций сервера

Следующие reference-файлы отражают прочитанные конфигурации `sbergigachat` на
15 ноября 2026 года. Это копии для аудита и воспроизведения, а не набор для
безусловной установки на другой машине. В примерах сохранены адреса, лимиты,
пути и digest образа; приватный TLS-ключ, `WEBUI_SECRET_KEY` и содержимое
Supervisor token не копировались.

| Активный файл на сервере | Файл в репозитории |
| --- | --- |
| `/etc/fstab` (только две BEZR data filesystems) | [`fstab.reference`](../ops/examples/gpu-server/fstab.reference) |
| `/opt/bezr/.env` (секрет заменён) | [`web.env.example`](../ops/examples/gpu-server/web.env.example) |
| `/etc/docker/daemon.json` | [`docker-daemon.reference.json`](../ops/examples/gpu-server/docker-daemon.reference.json) |
| `/etc/systemd/system/bezr-supervisor.service` | [`bezr-supervisor.service.reference`](../ops/examples/gpu-server/bezr-supervisor.service.reference) |
| `/etc/systemd/system/bezr-ollama-endpoint.service` | [`bezr-ollama-endpoint.service.example`](../ops/examples/gpu-server/bezr-ollama-endpoint.service.example) |
| `/etc/systemd/system/ollama.service.d/bezr.conf` | [`ollama.service.d.conf.example`](../ops/examples/gpu-server/ollama.service.d.conf.example) |
| `/etc/systemd/system/nftables.service.d/bezr.conf` | [`nftables.service.d.conf.example`](../ops/examples/gpu-server/nftables.service.d.conf.example) |
| `/etc/nginx/sites-available/bezr.conf` | [`nginx-web.conf.example`](../ops/examples/gpu-server/nginx-web.conf.example) |
| `/etc/nginx/conf.d/bezr-websocket.conf` | [`nginx-websocket.conf.example`](../ops/examples/gpu-server/nginx-websocket.conf.example) |
| `/etc/nginx/conf.d/bezr-ollama.conf` | [`nginx-ollama.conf.example`](../ops/examples/gpu-server/nginx-ollama.conf.example) |
| `/etc/nftables.d/bezr-ollama-guard.nft` | [`bezr-ollama-guard.nft.example`](../ops/examples/gpu-server/bezr-ollama-guard.nft.example) |
| `/var/lib/personal-agent-supervisor/deployment.json` | [`deployment.reference.json`](../ops/examples/gpu-server/deployment.reference.json) |
| `/var/lib/personal-agent-supervisor/runtime.json` | [`runtime.reference.json`](../ops/examples/gpu-server/runtime.reference.json) |
| Compose WebUI + Supervisor mount | [`compose.yaml`](../compose.yaml) + [`compose.supervisor.yaml`](../compose.supervisor.yaml) |
| BEZR WebUI build | [`Dockerfile`](../Dockerfile), pinned Open WebUI base image; upstream Open WebUI source is not vendored |

`deployment.example.json` остаётся переносимым шаблоном с нулевым UUID. В
`deployment.reference.json` записан UUID именно текущего XFS; на новом диске
его обязательно заменяют результатом `findmnt`/`blkid`. В файле
`runtime.json` заданы общий лимит диска **80 ГиБ** и начальный контекст Ollama
**16 384**. Действующий административный выбор контекста —
**`qwen3.5:9b` и 65 536 токенов**; оба текущих административных значения
прочитаны из SQLite Supervisor 15 ноября 2026 года. Контекст может отличаться
от значения в `runtime.json`. Значение 40 ГиБ было предложением и сейчас не
является установленным общим бюджетом.

Установленный unit Supervisor тоже содержит два исторических комментария
`Template only` и `Do not enable this unit`. Они не являются настройками systemd;
рабочие поля unit уже содержат конкретные пути и службу запустили. Для установки
на другом хосте используйте шаблон [`bezr-supervisor.service.in`](../ops/systemd/bezr-supervisor.service.in),
а не копируйте reference-файл без проверки.

`.env` не хранится в репозитории. Создайте локальный файл командой
`python3 scripts/init_env.py`; она генерирует новый `WEBUI_SECRET_KEY`.
Supervisor сам создаёт `/var/lib/personal-agent-supervisor/service.token`
при первом запуске, с правами `0640` внутри закрытого state-каталога. Не
вставляйте ни один из этих секретов в reference-файлы или Git. TLS-сертификат
и закрытый ключ устанавливаются отдельно по указанным в Nginx путям.

## Справочник файлов и параметров

В этом разделе описано, где менять каждую настройку, какие значения сейчас
используются и какие значения принимает код BEZR. Проверка схемы подтверждает
только допустимый формат. Она не подтверждает, что диску хватает места, IP-пул
свободен, GPU выдержит выбранный контекст или сертификат корректен.

### Как связаны настройки

| Источник | Что задаёт | Что имеет приоритет |
| --- | --- | --- |
| `.env` + `compose.yaml` | WebUI, его внешний адрес, локальный порт, лимиты контейнера и адрес доверенного Nginx | Только параметры WebUI; не задаёт лимиты агентов и модель Supervisor |
| `deployment.json` | Ограничения одного агента и идентичность XFS | Используется Supervisor как неизменяемый профиль сайта; после создания state не менять профиль произвольно |
| `runtime.json` | Общие лимиты Supervisor, образ OpenClaw, сети и начальные настройки Ollama | Задаёт начальные значения административной настройки модели/контекста |
| `runtime.sqlite3` | Учётные записи владельцев, экземпляры, операции и сохранённые администратором модель/контекст | Текущая настройка модели и контекста может отличаться от начальных значений `runtime.json` |
| systemd, Docker, Nginx, nftables | Запуск служб, хранение Docker, публичный вход и сетевой доступ к Ollama | Это системная конфигурация хоста; она не создаётся из `.env` |
| `gpu-acceptance.local.json` | Явные ресурсы и пути одноразовых испытаний | Используется только для приёмки, не задаёт рабочие лимиты агентов |

Не копируйте каталог `state_dir` между разными серверами: БД привязана к версии
профиля, а успешные receipts привязаны к конкретному хосту, сетям и интерфейсу.
Для повторного развёртывания используйте новую приёмку и новый state-каталог;
для работающего сервера сначала подготовьте резервную копию и план миграции.

### WebUI: `.env` и Compose

Файл `.env` содержит настройки одного WebUI и секрет его сессий. Шаблоны:
[`web.env.example`](../ops/examples/gpu-server/web.env.example) — значения GPU-сервера,
а [`.env.example`](../.env.example) — безопасные localhost-значения для разработки.
Скрипт `scripts/init_env.py` создаёт `.env` с правами владельца и отказывает,
если файл уже существует. После генерации отредактируйте несекретные значения
под сервер; не заменяйте сгенерированный ключ пустым значением.

| Переменная | Значение GPU-сервера | Допустимое назначение / правило |
| --- | --- | --- |
| `WEBUI_SECRET_KEY` | Сгенерированный, в Git не публикуется | `init_env.py` создаёт случайные 32 байта в hex. Значение должно оставаться постоянным между рестартами, не показываться в логах и не попадать в commit. Пустое значение не работает с Compose |
| `WEB_PORT` | `3000` | Свободный TCP-порт хоста. Compose связывает его только с `127.0.0.1`, внешний трафик идёт через Nginx |
| `AGENT_PLATFORM_PUBLIC_ORIGIN` | `https://bezr.space` | Origin WebUI, видимый браузеру; указывайте схему, доменное имя и при необходимости порт, без пути страницы |
| `AGENT_CONTROL_UI_DOMAIN` | `agents.bezr.space` | Нижний регистр, DNS-суффикс без `*`; должен соответствовать wildcard DNS, TLS и Nginx для `<instance-id>.agents.bezr.space` |
| `FORWARDED_ALLOW_IPS` | `172.18.0.1` | Точный IP доверенного reverse proxy в Docker bridge. Укажите только реальные peer IP, не `*` и не CIDR; Supervisor проверяет наличие актуального gateway WebUI |
| `WEB_MEMORY_LIMIT` | `2g` | Лимит памяти WebUI в формате Compose/Docker; подбирается по измерению хоста |
| `WEB_CPU_LIMIT` | `2.0` | Доля CPU в формате Compose; `2.0` означает до двух CPU. Настраивается под хост |

Compose-параметры, для которых нет `.env`-переменной, намеренно заданы в
[`compose.yaml`](../compose.yaml): порт контейнера `8080`, named volume
`webui_data`, bridge-сеть `web`, лимит процессов `256`, удаление всех
capabilities и `no-new-privileges`. Значения `WEB_MEMORY_LIMIT` и
`WEB_CPU_LIMIT` можно менять в `.env`, остальные значения фиксированы в YAML.
Переход от `127.0.0.1` в host port mapping к `0.0.0.0` откроет WebUI в сеть и
не нужен при наличии Nginx на том же хосте.

`compose.yaml` собирает и запускает только WebUI, публикует `127.0.0.1:${WEB_PORT}:8080`,
хранит его данные в named volume `webui_data` и задаёт ограничения контейнера.
`compose.supervisor.yaml` — обязательный opt-in overlay: он добавляет только
read-only bind mounts сокета и token-файла Supervisor. Docker socket WebUI не
получает. При любом пересоздании WebUI передавайте **оба** файла и те же
`SUPERVISOR_SOCKET_DIR`/`SUPERVISOR_TOKEN_FILE`, иначе кабинет останется healthy,
но управление агентами перестанет работать.

В `compose.yaml` также зафиксированы следующие параметры безопасности WebUI:
авторизация и форма входа включены; новые пользователи получают роль `user`;
OpenAI API, встроенный Ollama API, выполнение кода и Code Interpreter выключены;
контейнер работает в offline mode, без Linux capabilities и с
`no-new-privileges`. `pids_limit=256`, `mem_limit` и `cpus` ограничивают только
WebUI, не агентов. WebUI подключён к отдельной Docker bridge-сети `web`.
Меняйте эти фиксированные значения в Compose только как осознанное изменение
архитектуры, а после изменения повторно проверьте регистрацию, права пользователей,
сеть и отсутствие Docker socket в mounts.

`Dockerfile` закрепляет базовый образ
`ghcr.io/open-webui/open-webui:v0.12.5-slim@sha256:9a4db3e6c8d6174d4ed8952304115e90dcc36e9a8b98c2f8984eab321f29505e`
(upstream version `v0.12.5`, reviewed source commit
`f7ac7ee10962ddec0017f5c29b6740d9b9c5faca`) и накладывает BEZR integration/static
files. Полный исходный код Open WebUI в этом репозитории не хранится. Этапы Docker build выполняют frontend
и Python проверки; успешная сборка ещё не означает, что образ применён к running
контейнеру. На существующем стенде обновляйте WebUI и связанные Sidecar по
[`WEBUI_SIDECAR_UPGRADE.md`](WEBUI_SIDECAR_UPGRADE.md); не пересоздавайте контейнер
только одним `compose.yaml` и не используйте `down -v`.

Переменные `ENABLE_OLLAMA_API=false`, `ENABLE_CODE_EXECUTION=false`, авторизация,
регистрация и прочие фиксированные параметры безопасности заданы в Compose,
а не в `.env`. Не дублируйте их в `.env` и не включайте без отдельного изменения
архитектуры и проверки.

### Профиль агентов: `deployment.json`

Для редактирования берите [`deployment.example.json`](../ops/examples/gpu-server/deployment.example.json)
и сохраняйте рабочую копию вне Git, например `supervisor/deployment.local.json`.
[`deployment.reference.json`](../ops/examples/gpu-server/deployment.reference.json)
показывает профиль GPU-сервера; в нём содержится UUID только этого диска.

| Поле | GPU-сервер | Принимаемые значения |
| --- | --- | --- |
| `schema_version` | `1` | Только целое число `1` |
| `profile_version` | `bezr-gpu-v1` | 1–64 символа из `A-Z`, `a-z`, цифр, `_` и `-`. После привязки state не меняйте: несовпадение версии/отпечатка профиля блокирует запуск |
| `mode` | `final` | Только `lab` или `final`; GPU-сервер использует `final` |
| `storage.backend` | `xfs_project_quota` | Единственный backend этой версии схемы |
| `storage.mountpoint` | `/mnt/xfs_data` | Канонический абсолютный POSIX-путь, не `/`, без `..`; путь должен быть отдельной XFS с включёнными project quota accounting и enforcement |
| `storage.expected_uuid` | `334df01f-93c4-4ab4-b24f-543ba05cf3df` | Точный UUID в формате `8-4-4-4-12`; должен совпасть с фактическим устройством при проверке |
| `agent_limits.ram_bytes` | `4294967296` (4 GiB) | Положительное целое число байтов; выбирайте после измерения RAM |
| `agent_limits.cpu_millicores` | `2000` (2 CPU) | Положительное целое число millicores; `1000` = один CPU |
| `agent_limits.pids_limit` | `512` | Положительное целое число процессов/потоков |
| `agent_limits.disk_bytes` | `10737418240` (10 GiB) | Положительное целое число байтов; для текущей XFS-проверки делится на 1024 |

На уровне JSON числовые лимиты — положительные int64; верхняя граница схемы
не означает, что хост физически выдержит такое значение. Общие лимиты из
`runtime.json` должны вместить хотя бы один агент. Профиль `agent_proxy_v1`
добавляет на экземпляр Access Proxy Sidecar с собственным ограничением 128 MiB,
100 millicores и 32 PIDs; Supervisor включает эту резервацию в расчёт ёмкости.
При ёмкости диска 80 GiB это не гарантирует восемь агентов: дополнительно
учитываются RAM, CPU, Sidecar, свободное место и резерв.

До использования профиля проверьте его синтаксис и фактическую файловую систему:

```bash
python3 -m supervisor.config --check /opt/bezr/supervisor/deployment.local.json
findmnt -no TARGET,SOURCE,FSTYPE,UUID,OPTIONS /mnt/xfs_data
xfs_quota -x -c 'state -p' /mnt/xfs_data
sudo python3 -m supervisor.storage --check /opt/bezr/supervisor/deployment.local.json
```

Успешный `supervisor.config --check` проверяет JSON-профиль, но не монтирует
диск и не проверяет квоту. Для нового хоста сравните обе проверки storage и
только затем продолжайте.

### Общие настройки: `runtime.json`

Рабочий файл создаёт `scripts/configure_supervisor.py --prepare-host-config`;
он записывается эксклюзивно и существующий runtime не перезаписывается.
[`runtime.reference.json`](../ops/examples/gpu-server/runtime.reference.json) —
снимок активного файла сервера, а не безопасная заготовка для другого хоста:
в нём указан digest локального образа, IP-пулы, сетевой интерфейс и пути.

| Поле | Текущее значение | Правило |
| --- | --- | --- |
| `profile_path` | `/var/lib/personal-agent-supervisor/deployment.json` | Абсолютный канонический путь к root-controlled копии профиля |
| `state_dir` | `/var/lib/personal-agent-supervisor` | Абсолютный закрытый root-каталог вне XFS данных агентов |
| `socket_path` | `/run/personal-agent-supervisor/control.sock` | Имя обязательно `control.sock`; абсолютный путь, длина Unix socket не более 107 байт; каталог отделён от state и data mount |
| `token_file` | `/var/lib/personal-agent-supervisor/service.token` | Обязательно `state_dir/service.token`; токен создаёт Supervisor, значение генерируется и не переносится в `.env` |
| `image` | `sha256:011a54c216af99895c727aff3c8e2a33b99a1952badf70e37a29793e83b9a056` | Неизменяемый digest существующего локального OpenClaw-образа. Генератор принимает локальный tag, сам разрешает его в digest; образ не скачивает |
| `capacity_ram_bytes` | `38654705664` (36 GiB) | Положительное int64, общая ёмкость Supervisor; должна вмещать профиль одного агента |
| `capacity_cpu_millicores` | `18000` (18 CPU) | Положительное int64, `1000` = один CPU; должна вмещать профиль одного агента |
| `capacity_disk_bytes` | `85899345920` (80 GiB) | Положительное int64; общий бюджет диска, не размер одного агента |
| `disk_floor_bytes` | `10737418240` (10 GiB) | Целое число от 0 до int64; минимум свободного места, резервируемый на хосте |
| `network_profile_default` | `agent_proxy_v1` | Одно из `legacy_none`, `agent_internal_v1`, `agent_proxy_v1`. Последний нужен для Control UI/Access Proxy и требует host-bound acceptance receipts |
| `control_ui_domain` | `agents.bezr.space` | Нижний регистр, DNS-суффикс из минимум двух меток, без wildcard-символа; wildcard ставится в DNS/Nginx, не в это поле |
| `agent_network_pool` | `172.24.0.0/24` | RFC1918 IPv4 supernet `/24` или крупнее; должен быть свободен и не пересекаться с другими пулами/маршрутами |
| `frontend_network_pool` | `172.24.1.0/24` | Те же правила; обязательно отдельный от `agent_network_pool` |
| `ollama` | См. ниже | `null` отключает native Ollama policy; при включении требуется весь набор полей |
| `ollama_network_pool` | `172.24.2.0/24` | RFC1918 `/24` или крупнее, отделён от agent/frontend пулов; адрес endpoint не должен входить в этот пул |
| `ollama_egress_interface` | `ens1f0` | Точное существующее имя Linux интерфейса, выбранное после проверки маршрута до endpoint |

В `ollama` задаются:

| Поле | Текущее bootstrap-значение | Разрешённые значения |
| --- | --- | --- |
| `base_url` | `http://172.24.3.1:11434` | Явный частный IPv4, только HTTP, порт `11434`, без URL-пути, credentials, query и fragment. `127.0.0.1` здесь неверен: внутри контейнера это сам контейнер |
| `default_model_id` | `qwen3.5:9b` в reference runtime | Только ID из фиксированного каталога: `qwen3.5:9b` или `hf.co/DavidAU/Qwen3.5-9B-The-Defiant-Fable-Uncensored-Heretic-NEO-IMATRIX-MAX-MTP-GGUF:Q4_K_M` |
| `context_tokens` | `16384` в файле runtime | Одно из `8192`, `16384`, `32768`, `65536`; это bootstrap, не обязательно текущий выбранный размер |
| `max_tokens` | `2048` | Целое от `1` до `context_tokens` включительно |
| `think` | `false` | JSON boolean `true` или `false`; текущее значение `false` |

На GPU-сервере текущая сохранённая настройка — `qwen3.5:9b` с контекстом
**65536**. Оба поля хранятся в `/var/lib/personal-agent-supervisor/runtime.sqlite3`;
контекст имеет приоритет над bootstrap `context_tokens: 16384` из `runtime.json`.
При чистом развёртывании передайте `--ollama-context-tokens 65536` генератору
runtime, чтобы при первом старте SQLite получила требуемое начальное значение.
При смене модели передайте соответствующий ID из фиксированного списка.
После запуска меняйте модель и контекст через `/agent/`; SQLite вручную не
редактируйте. Настройка общая для Supervisor и всех агентов, а не отдельная
на пользователя.

`agent_proxy_v1` нельзя включить только изменением JSON: сначала должны пройти
обе сетевые проверки — `linux_proxy_isolated_check` и
`linux_docker_proxy_acceptance` — и быть установлены подходящие host-bound
receipts. Если к runtime добавлена Ollama policy, требуется также отдельная
успешная приёмка изолированного Ollama-маршрута. Отсутствующий или несовпадающий
receipt должен оставить Supervisor fail-closed.

### Одноразовая конфигурация: `gpu-acceptance.local.json`

[`gpu-acceptance.example.json`](../ops/examples/gpu-server/gpu-acceptance.example.json)
задаёт ресурсы именно временной лаборатории. Её значения не изменяют квоты
пользовательских агентов и не являются настройками продакшн Docker.

| Поле | Значение-пример | Правило |
| --- | --- | --- |
| `schema_version` | `1` | Только версия схемы `1`; неизвестные/лишние поля запрещены |
| `site.*_pool`, `ollama_endpoint_ip`, `egress_interface` | Те же пулы, `172.24.3.1`, `ens1f0` | Должны точно совпадать с маршрутом/интерфейсом хоста и будущим runtime |
| `budget.cpu_quota_percent` | `200` | Положительное целое; системная служба получает это значение как CPU quota в процентах |
| `budget.memory_bytes` | `4294967296` (4 GiB) | Положительное число байтов, кратное 4096 |
| `budget.swap_bytes` | `0` | Целое не меньше нуля; `0` отключает swap для тестовой службы |
| `budget.tasks` | `512` | Положительное целое для `TasksMax` |
| `budget.runtime_seconds` / `stop_seconds` | `240` / `20` | Положительные целые секунды; ограничивают испытательную службу и остановку |
| `budget.tmpfs_bytes` / `tmpfs_inodes` | `2147483648` / `131072` | Положительные; tmpfs должен быть меньше memory budget, bytes кратны 4096 |
| `budget.io` | `/dev/sdd`, `8:48`, 40 MiB/s, 300 IOPS | Устройство и major/minor должны описывать один и тот же выделенный диск. Rates положительные; major/minor неотрицательные |
| `probe_image` | SHA256 digest | Требуется digest уже доступного локального probe-образа из `images/acceptance`, не OpenClaw |
| `image_archive` | `/mnt/sdd/bezr-acceptance-probe/probe.tar` | Абсолютный безопасный путь на проверенном диске, отличный от socket и candidate |
| `production_docker_socket` | `/run/docker.sock` | Только источник read-only снимка существующих Docker-ресурсов; сами испытания используют отдельный daemon |
| `candidate_dir` | `/mnt/sdd/bezr-acceptance/candidate-REPLACE-ME` | Новый уникальный каталог; перед запуском не должен существовать |

Все budget-параметры, кроме swap, должны быть положительными целыми. RAM и
tmpfs должны быть выровнены по странице 4096 байт, tmpfs меньше RAM. Major и
minor устройства должны быть неотрицательными, а I/O rates положительными.
Укажите все поля явно: схема не подставляет безопасные по умолчанию бюджеты.

### Конфигурации служб и порядок запуска

| Файл | Назначение и что менять |
| --- | --- |
| `/etc/fstab` — [`fstab.reference`](../ops/examples/gpu-server/fstab.reference) | Два filesystem mount: `/mnt/sdd` (ext4) и `/mnt/xfs_data` (XFS с `prjquota`). На другом хосте сначала определите UUID и filesystem; не копируйте UUID. Проверка `mount -a` меняет состояние mount и выполняется только после проверки файла |
| `/etc/docker/daemon.json` — [`docker-daemon.reference.json`](../ops/examples/gpu-server/docker-daemon.reference.json) | `data-root` задаёт расположение всех Docker-данных; `runtimes.nvidia` регистрирует NVIDIA runtime. Это глобальная конфигурация Docker: интегрируйте в существующий JSON и планируйте restart, не заменяйте файл слепо |
| `bezr-ollama-endpoint.service` | Одноразовая служба добавляет `172.24.3.1/32` на `lo` и загружает только таблицу guard BEZR; `Before=nginx.service` гарантирует наличие listen IP перед запуском Nginx |
| `ollama.service.d/bezr.conf` | Настраивает native Ollama: `KEEP_ALIVE=24h`, `MAX_LOADED_MODELS=1`, `MAX_QUEUE=4`, `NUM_PARALLEL=2`. Это один общий runner и очередь; два параллельных запроса не означают два разных GPU-процесса/модели |
| `nftables.service.d/bezr.conf` | `ExecStop=` очищает у системной службы унаследованный stop command. Это не правило доступа; сами адресные правила находятся в таблице `bezr_ollama_guard` |
| `nginx-web.conf.example` | Принимает `bezr.space` и `*.agents.bezr.space`, перенаправляет HTTP на HTTPS и проксирует WebUI на `127.0.0.1:3000`; передаёт WebSocket и forwarded headers |
| `nginx-websocket.conf.example` | Отображает `$http_upgrade` в правильный `Connection` для WebSocket; включается вместе с основным vhost |
| `nginx-ollama.conf.example` | Слушает только `172.24.3.1:11434`, проксирует `/api/` на существующую Ollama `127.0.0.1:11434`, остальные URI возвращают 404 |
| `bezr-ollama-guard.nft.example` | Разрешает локальный host access и TCP/11434 от BEZR Ollama subnet на bridge `bzo*`; другой доступ к `172.24.3.1` сбрасывается. Команды меняют только таблицу BEZR, не используйте `flush ruleset` |
| `bezr-supervisor.service.reference` | Текущий unit запускает Supervisor от root с конкретным Python 3.12, runtime-путём и требованием смонтированного `/mnt/xfs_data`; для нового сервера заполняйте `bezr-supervisor.service.in`, а не копируйте reference как есть |

Ниже — назначение основных директив и то, какие из них привязаны к хосту.
Это объяснение файлов из таблицы, а не дополнительные значения по умолчанию.

| Файл / директива | Что делает и какое значение задавать |
| --- | --- |
| `fstab`: `UUID=… /mnt/sdd ext4 defaults 0 2` | Монтирует отдельный Docker data disk. Подставьте UUID из `lsblk -f`; filesystem и mountpoint должны соответствовать реальному диску. `defaults` — стандартный набор mount options; последние поля означают не запуск `dump` и проверку filesystem после root filesystem. Не меняйте UUID по примеру без сверки. |
| `fstab`: `UUID=… /mnt/xfs_data xfs defaults,prjquota 0 0` | Монтирует XFS с project quota. `prjquota` включает учёт и enforcement project quota. Для рабочего профиля это обязательный смысловой параметр; если у данного ядра или XFS mount он не действует, не запускайте агентов. `0 0` исключает dump/fsck для XFS data mount. |
| Docker `data-root` | Абсолютный каталог на смонтированном диске, здесь `/mnt/sdd/docker`. Это место хранения образов, контейнеров, слоёв и volumes всего Docker daemon; перенос уже используемого root требует отдельной миграции. |
| Docker `runtimes.nvidia.path` | Команда runtime, здесь `nvidia-container-runtime`. Её имя должно быть доступно Docker host и соответствовать установленному NVIDIA Container Toolkit; `docker info` должен показать runtime после контролируемого рестарта. |
| Supervisor unit `Requires=docker.service`, `After=…` | Требует Docker и задаёт порядок запуска после локальных mount, Docker и nftables. Если имя системной службы на новой ОС отличается, используйте фактическое имя unit. |
| Supervisor unit `RequiresMountsFor=` и `ConditionPathExists=` | Указывают обязательный агентский mountpoint и runtime-файл. Меняйте на значения из выбранных deployment/runtime paths; systemd не должен запускать службу, если обязательный mount отсутствует. |
| Supervisor unit `User=root`, `UMask=0077`, `KillMode=control-group` | Supervisor запускается с привилегиями для настройки host resources; umask закрывает создаваемые state-файлы; при stop systemd завершает всю группу процессов службы. Не запускайте его как непривилегированного пользователя без отдельной модели capabilities. |
| Supervisor unit `Restart=on-failure`, `RestartSec=3s`, `TimeoutStopSec=30s` | Перезапускает службу после отказа с паузой и задаёт время штатной остановки. На новом хосте оставляйте значения из шаблона, если не измерена необходимость другой политики. |
| Endpoint unit `Type=oneshot`, `RemainAfterExit=yes` | Выполняет однократную настройку loopback-адреса и firewall при старте; systemd считает подготовку активной после завершения `ExecStart`. Это не отдельный постоянно работающий сервер. |
| Endpoint unit `ExecStart=ip address replace …` | Добавляет ровно endpoint `/32` на указанный интерфейс; интерфейс и адрес должны совпасть с runtime, Nginx listener и acceptance config. Команда `replace` идемпотентна для того же адреса. |
| Endpoint unit `ExecStart=nft -f …` | Загружает отдельный файл правил BEZR. Исполняйте `nft --check -f` до установки; не заменяйте эту настройку общей очисткой ruleset. |
| Ollama `OLLAMA_KEEP_ALIVE=24h` | Длительность удержания загруженной модели без запросов. Значение примера оставляет одну модель warm до 24 часов; уменьшайте для экономии VRAM или задавайте проверенный формат длительности, поддерживаемый установленной Ollama. |
| Ollama `OLLAMA_MAX_LOADED_MODELS=1` | Ограничивает один одновременно загруженный model runner. Для GPU с общей памятью P100 это текущее выбранное значение; повышение может привести к нехватке VRAM. |
| Ollama `OLLAMA_MAX_QUEUE=4` | Ограничивает очередь ожидающих запросов. Не задавайте произвольно большую очередь: при долгой генерации она увеличивает ожидание и потребление памяти/ресурсов. |
| Ollama `OLLAMA_NUM_PARALLEL=2` | Число одновременно выполняемых запросов выбранного runner в этом примере. Это не означает запуск двух независимых процессов или закрепление модели за PID. Подберите через фактический тест с нужными моделями/контекстом; ограничение VRAM обязательно. |
| `nftables.service.d/bezr.conf`: `ExecStop=` | Пустой список очищает унаследованные команды остановки packaged `nftables.service`; цель — не дать общей stop-команде затронуть правила других компонентов. Проверяйте результат `systemctl cat nftables.service` и политику хоста до применения. |
| Nginx `listen 80` и `return 301` | Принимает HTTP на внешнем интерфейсе и перенаправляет на HTTPS с тем же host/path. Не публикуйте endpoint Ollama на внешнем интерфейсе. |
| Nginx `listen 443 ssl http2`, `ssl_protocols` | Включает TLS и HTTP/2 для публичных origin; разрешены TLS 1.2/1.3. Ключ/сертификат должны иметь SAN для основного и wildcard доменов. Самоподписанный сертификат допустим для MVP, но браузерное предупреждение о доверии ожидаемо. |
| Nginx `proxy_pass http://127.0.0.1:3000` | WebUI доступен Nginx только на loopback. Если изменить `WEB_PORT`, измените и upstream port; не связывайте WebUI на публичном интерфейсе без отдельного сетевого дизайна. |
| Nginx `proxy_set_header` | Передаёт исходный `Host`/`Origin`, адрес клиента, схему и WebSocket upgrade. Это важно для origin validation и Control UI; не подменяйте Origin константой без тестов. |
| Nginx `proxy_read_timeout 300s` | Максимальное ожидание upstream WebUI для ответа. Ollama API proxy отдельно использует `600s`; корректируйте только на основании длительности реальных запросов и ограничений приложения. |
| WebSocket `map` | Для запросов с `Upgrade` устанавливает `Connection: upgrade`, иначе `close`. Это отдельный файл в `http` context; не переносите директиву внутрь `server` block. |
| Ollama Nginx `listen 172.24.3.1:11434` | Внутренний endpoint, не внешний public listener. Адрес должен существовать до старта Nginx. `/api/` проксируется к native Ollama loopback; все иные URI возвращают 404. |
| Ollama Nginx `client_max_body_size 1m`, `proxy_buffering off` | Ограничивает размер HTTP запроса к прокси и отключает buffering ответа, чтобы streaming не задерживался. Меняйте размер только если конкретный API payload требует другого лимита. |
| nftables `input` chain `policy accept` и правила для endpoint | Правила относятся только к трафику с destination `172.24.3.1`. Сначала разрешается loopback, затем TCP/11434 от Ollama subnet через интерфейс `bzo*`; прочие пакеты к этому endpoint отбрасываются. Остальной host traffic этим набором не меняется. |
| nftables `priority -25` | Приоритет собственной input chain относительно других base chains. Не меняйте без проверки порядка всех host firewall chains и теста из разрешённой и запрещённой сети. |

Nginx должен иметь сертификат с SAN для `bezr.space` и `*.agents.bezr.space`.
Для MVP можно использовать самоподписанный сертификат: браузер покажет предупреждение,
пока сертификат/локальный CA не добавлен в доверенные. Это предупреждение допустимо
для текущего стенда; TLS и проверку origin в приложении оставляйте включёнными.
Не помещайте private key в репозиторий. На GPU-сервере Nginx
1.18.0 использует `http2`, WebSocket upgrade и upstream timeout 300 секунд;
Ollama API proxy ждёт ответ до 600 секунд.

### Сетевые пулы и значения с привязкой к хосту

Текущий сервер использует `172.24.0.0/24` для agent, `172.24.1.0/24` для
frontend и `172.24.2.0/24` для Ollama bridges. Код принимает канонические
частные IPv4 supernets с размером `/24` или крупнее, но требует отсутствия
пересечений; для Ollama endpoint адрес (`172.24.3.1`) должен быть вне всех
пулов. BEZR делит `/24` на 32 подсети `/29`, по одной на экземпляр и назначение.

Перед выбором других диапазонов проверяйте `ip route`, `ip addr`, существующие
Docker networks и VPN/университетские маршруты. На этом сервере отдельно
проверены `10.40.240.0/24`, Docker bridge `172.17.0.0/16`, WebUI `172.18.0.0/16`
и Ollama loopback endpoint. Эти результаты не переносятся автоматически на
другую машину.

На проверенном сервере один агент ограничен 4 ГиБ RAM, 2 CPU, 512 PIDs и
10 ГиБ диска. Общая ёмкость Supervisor — 36 ГиБ RAM, 18 CPU и 80 ГиБ диска,
с минимальным резервом свободного места 10 ГиБ. 40 ГиБ ранее обсуждались как
предложение и не являются текущим общим лимитом. Фактическое число агентов
также зависит от остальных ресурсов и свободного места.

Сетевая приёмка четырёх сценариев в изолированных службах была успешной;
она не подтверждает успешный запрос к модели, работоспособность TLS или всех
пользовательских функций. Отдельно обнаруживалась проблема загрузки Control UI
при большом числе одновременных обращений к Supervisor: увеличение очереди
устранило отказы в испытании 30 запросов, но они заняли около 94 секунд.
Быструю загрузку интерфейса и весь пользовательский сценарий ещё нужно принять.

## 1. Зафиксировать исходники и проверить площадку

Используйте проверенный коммит BEZR; сохраните свои незакоммиченные изменения
до `git pull`/переключения версии. OpenClaw — отдельный upstream
`https://github.com/openclaw/openclaw.git`, commit
`7c12438929e5d198616fe8f602d896e011647d39`; исходники его целиком в BEZR не
включены. Скрипт [`lab/openclaw/build_image.sh`](../lab/openclaw/build_image.sh)
требует чистый отдельный checkout этого commit и применяет закреплённый патч
из `lab/openclaw/patches/`. Сборка может скачать зависимости и базовые образы;
её не нужно повторять, если нужный уже проверенный локальный образ имеется.
После сборки фиксируйте фактический image ID: пересборка не гарантирует тот же ID.

Восстановление исходников OpenClaw на новом сервере (полная копия исходников
в BEZR Git не хранится):

```bash
test ! -e /mnt/sdd/bezr-openclaw-src/openclaw || {
  echo 'STOP: каталог уже существует; проверьте checkout вручную' >&2
  exit 1
}
git clone https://github.com/openclaw/openclaw.git /mnt/sdd/bezr-openclaw-src/openclaw
git -C /mnt/sdd/bezr-openclaw-src/openclaw checkout --detach 7c12438929e5d198616fe8f602d896e011647d39
test -z "$(git -C /mnt/sdd/bezr-openclaw-src/openclaw status --porcelain --untracked-files=all)"
bash /opt/bezr/lab/openclaw/build_image.sh /mnt/sdd/bezr-openclaw-src/openclaw
sudo docker image inspect --format '{{.Id}}' openclaw-stage2:7c12438929e5
```

Скрипт проверяет commit и чистоту checkout, архивирует исходники, применяет
репозиторный патч только к временному build context и удаляет этот контекст
после сборки. Перед запуском убедитесь, что диск имеет место для checkout,
временной копии и Docker layers. Полученный image ID запишите и используйте
в `configure_supervisor.py`; одной метки `openclaw-stage2:7c12438929e5`
недостаточно для доказательства идентичности образа.

Нужны Linux, cgroup v2, systemd, Docker/Compose, `ip`, `nft`, `unshare`,
`bpftool`, XFS tools, Python 3.12+, Nginx, доступный NVIDIA driver и уже
работающая Ollama. До установки или изменения системы проверьте существующие
службы, пространство, состояние контейнеров, портов и томов:

```bash
git -C /opt/bezr status --short --branch
uname -r
systemd --version | head -n 1
docker --version
docker compose version
nft --version
nginx -v
ollama --version
/opt/bezr-python/cpython-3.12.16-linux-x86_64-gnu/bin/python3.12 --version
systemctl is-active docker nginx ollama
docker info --format 'DockerRootDir={{.DockerRootDir}} Runtimes={{json .Runtimes}}'
docker ps -a
docker network ls
findmnt -no TARGET,SOURCE,FSTYPE,UUID,OPTIONS /mnt/xfs_data
xfs_quota -x -c 'state -p' /mnt/xfs_data
ip -4 route show table all
ip -4 addr show
nvidia-smi
```

Сравните пулы с маршрутами и Docker IPAM, в том числе с университетской сетью
`10.40.240.0/24` и существующими Docker-сетями. Указанные диапазоны нельзя
слепо переносить на другой хост. Не форматируйте существующий диск и не
меняйте глобальные Docker-сети или `data-root` ради этого руководства.
На чистом новом хосте настройте Docker до загрузки образов и создания контейнеров.
Если Docker уже использует другое хранилище, простая замена
`/etc/docker/daemon.json` с перезапуском не переносит образы/тома и может сделать
их недоступными. Сначала составьте отдельный план миграции, сохраните данные и
сверьте `DockerRootDir`/runtimes после контролируемого рестарта.

Только на новом хосте с пустым Docker можно создать `daemon.json` из reference
с явной проверкой отсутствия файла. На текущем сервере этот файл уже существует;
не запускайте команду там:

```bash
sudo bash -euc '
target=/etc/docker/daemon.json
test ! -e "$target" && test ! -L "$target" || {
  echo "STOP: target exists: $target" >&2
  exit 1
}
install -o root -g root -m 0644 \
  /opt/bezr/ops/examples/gpu-server/docker-daemon.reference.json "$target"
systemctl restart docker
'
docker info --format 'DockerRootDir={{.DockerRootDir}} Runtimes={{json .Runtimes}}'
```

После рестарта ожидаются `DockerRootDir=/mnt/sdd/docker` и runtime `nvidia`.
На хосте с уже работающими контейнерами сначала нужна проверка и окно
обслуживания: рестарт Docker влияет на все контейнеры этого daemon.

## 2. Профиль хранилища и агентов

Возьмите [`deployment.example.json`](../ops/examples/gpu-server/deployment.example.json),
замените нулевой `expected_uuid` на UUID фактически проверенной XFS и при
необходимости скорректируйте mountpoint/лимиты. `prjquota` должен быть
включён и для accounting, и для enforcement; не подставляйте UUID из другой
машины. Сохраните копию как `supervisor/deployment.local.json`: этот путь
исключён из Git. Существующий файл не перезаписывайте без проверки.

На новом хосте создайте приватную копию шаблона только если целевого файла ещё
нет, затем отредактируйте его от root:

```bash
cd /opt/bezr
sudo bash -euc '
target=/opt/bezr/supervisor/deployment.local.json
test ! -e "$target" && test ! -L "$target" || {
  echo "STOP: target exists: $target" >&2
  exit 1
}
install -o root -g root -m 0600 \
  /opt/bezr/ops/examples/gpu-server/deployment.example.json "$target"
'
sudoedit /opt/bezr/supervisor/deployment.local.json
```

Заполните `expected_uuid` по фактическому mount и проверьте значения одного
агента. Нулевой UUID в шаблоне намеренно требует ручной замены; он не является
рабочим значением. Не применяйте `deployment.reference.json` к другому диску.

```bash
cd /opt/bezr
python3 -m supervisor.config --check supervisor/deployment.local.json
sudo python3 -m supervisor.storage --check supervisor/deployment.local.json
```

`backend_ready` означает проверку backend, а не испытание реальной квоты.
Файловая система с `prjquota` должна корректно монтироваться после reboot;
редактирование `fstab`, создание ФС и миграция данных — отдельные операции.

[`fstab.reference`](../ops/examples/gpu-server/fstab.reference) показывает
конкретные UUID текущих двух дисков. На другой машине получите UUID через
`lsblk -f`/`blkid`, отредактируйте только нужные строки и сначала проверьте
синтаксис:

```bash
sudo findmnt --verify --verbose
```

Затем смонтируйте нужные точки и подтвердите фактические source, filesystem,
UUID и опции через `findmnt`. **Не выполняйте `mkfs` по этому гайду**: он
уничтожает данные, а форматирование существующего диска не является частью
развёртывания BEZR.

## 3. Ollama endpoint и фильтрация

Проверяйте действующую Ollama и выбранную модель, не запуская второй экземпляр:

```bash
systemctl status ollama --no-pager
curl -fsS http://127.0.0.1:11434/api/tags >/dev/null
```

Для указанной схемы нужны loopback-адрес `172.24.3.1/32`, отдельный Nginx
proxy только к локальной Ollama и nftables-ограничение. Примеры из реальной
схемы: [`nginx-ollama.conf.example`](../ops/examples/gpu-server/nginx-ollama.conf.example),
[`bezr-ollama-guard.nft.example`](../ops/examples/gpu-server/bezr-ollama-guard.nft.example),
[`bezr-ollama-endpoint.service.example`](../ops/examples/gpu-server/bezr-ollama-endpoint.service.example).
Пути в unit должны соответствовать размещению файлов в `/etc`. Сначала изучите
существующие правила и возможное пересечение адреса; подготовку/установку
выполняют только на согласованном хосте. Никогда не используйте `nft flush
ruleset`: пример затрагивает только собственную таблицу BEZR. Порядок запуска
адреса и guard до Nginx важен; поведение после перезагрузки нужно проверить.

На новой машине сначала установите endpoint unit, nftables-файл и drop-in,
только если целевые файлы ещё не существуют. Этот блок не перезаписывает
обнаруженную конфигурацию:

```bash
sudo bash -euc '
targets=(
  /etc/nftables.d/bezr-ollama-guard.nft
  /etc/systemd/system/bezr-ollama-endpoint.service
  /etc/systemd/system/nftables.service.d/bezr.conf
)
for target in "${targets[@]}"; do
  test ! -e "$target" && test ! -L "$target" || {
    echo "STOP: target exists: $target" >&2
    exit 1
  }
done
install -D -o root -g root -m 0644 /opt/bezr/ops/examples/gpu-server/bezr-ollama-guard.nft.example \
  /etc/nftables.d/bezr-ollama-guard.nft
install -D -o root -g root -m 0644 /opt/bezr/ops/examples/gpu-server/bezr-ollama-endpoint.service.example \
  /etc/systemd/system/bezr-ollama-endpoint.service
install -D -o root -g root -m 0644 /opt/bezr/ops/examples/gpu-server/nftables.service.d.conf.example \
  /etc/systemd/system/nftables.service.d/bezr.conf
nft --check -f /etc/nftables.d/bezr-ollama-guard.nft
systemctl daemon-reload
systemctl enable --now bezr-ollama-endpoint.service
'
```

`nftables.service.d/bezr.conf` очищает пакетный `ExecStop` у системной службы;
проверьте, что это соответствует политике хоста, прежде чем устанавливать.
`bezr-ollama-endpoint.service` добавляет loopback-адрес и загружает guard;
после его старта проверьте адрес и только затем устанавливайте Nginx vhost.
Для уже работающей Ollama установите drop-in с ограничениями параллельности
только после сравнения текущих значений. Его применение требует `daemon-reload`
и рестарта `ollama.service`; рестарт выгрузит runner, и первый запрос после
него может снова загрузить модель в VRAM.

Если drop-in отсутствует и оператор выбрал эти параметры, установите файл
отдельно. Существующий drop-in не заменяйте этим примером автоматически:

```bash
sudo bash -euc '
target=/etc/systemd/system/ollama.service.d/bezr.conf
test ! -e "$target" && test ! -L "$target" || {
  echo "STOP: target exists: $target" >&2
  exit 1
}
install -D -o root -g root -m 0644 /opt/bezr/ops/examples/gpu-server/ollama.service.d.conf.example "$target"
systemctl daemon-reload
systemctl restart ollama.service
'
systemctl is-active ollama.service
ollama ps
```

При другой GPU/модели можно уменьшить `OLLAMA_NUM_PARALLEL` или изменить
`OLLAMA_KEEP_ALIVE`; это не меняет BEZR pool/контекст и не гарантирует, что
модель поместится в VRAM. На этом сервере проверены два параллельных запроса и
одна загруженная модель. Переключение модели заменяет общий runner для всех
пользователей.

После настройки проверяйте и реальный агентский маршрут, а не только HTTP 200:

```bash
ip -4 addr show dev lo
sudo nft list table inet bezr_ollama_guard
curl -fsS http://172.24.3.1:11434/api/tags >/dev/null
```

## 4. WebUI, DNS, TLS и Nginx

Для нового стенда сгенерируйте `.env` штатным `python3 scripts/init_env.py`;
он не должен заменять уже существующий файл. Публичные параметры приведены в
[`web.env.example`](../ops/examples/gpu-server/web.env.example); секретный
`WEBUI_SECRET_KEY` генерируется отдельно и никогда не коммитится. Убедитесь,
что `FORWARDED_ALLOW_IPS` содержит **точный** IP доверенного reverse proxy,
который видит контейнер, а не `*` и не всю подсеть.

На новом хосте скрипт создаёт localhost-заготовку. После проверки, что `.env`
ещё нет, сгенерируйте её из корня проекта и измените несекретные поля на значения
GPU-примера. Для `FORWARDED_ALLOW_IPS` найдите gateway фактической Docker-сети
WebUI через `docker network inspect`; не угадывайте его по номеру подсети.

```bash
cd /opt/bezr
python3 scripts/init_env.py
sudoedit /opt/bezr/.env
```

Установите в `.env` значения из `ops/examples/gpu-server/web.env.example`, но
сохраните свежий `WEBUI_SECRET_KEY`, созданный скриптом. На GPU-примере это
`WEB_PORT=3000`, `AGENT_PLATFORM_PUBLIC_ORIGIN=https://bezr.space`,
`AGENT_CONTROL_UI_DOMAIN=agents.bezr.space`,
`FORWARDED_ALLOW_IPS=172.18.0.1`, `WEB_MEMORY_LIMIT=2g`, `WEB_CPU_LIMIT=2.0`.

Примеры Nginx: [`nginx-web.conf.example`](../ops/examples/gpu-server/nginx-web.conf.example)
и [`nginx-websocket.conf.example`](../ops/examples/gpu-server/nginx-websocket.conf.example).
Сертификат должен покрывать и `bezr.space`, и `*.agents.bezr.space`; приватный
ключ не помещается в Git. Настройте DNS для обоих имён и соответствующий
сертификату доверенный TLS. На недоступность/ошибку сертификата не отвечайте
отключением проверки сертификатов. Проверьте `sudo nginx -t` до reload и не
перезаписывайте существующий vhost на работающем сервере без сравнения.
Перед включением посмотрите `sudo nginx -T`, содержимое `sites-enabled` и
владельца портов 80/443. На чистом стенде проверьте, не является ли
`default_server` сайт-заглушка; отключайте только ненужную ссылку из
`sites-enabled`, никогда не удаляйте конфигурации других сайтов. Если другие
виртуальные хосты должны остаться, интегрируйте BEZR server blocks и websocket
`map` с учётом существующего `http` context.
В примере включён HTTP/2 для HTTPS сайта BEZR: это позволяет браузеру
одновременно загружать больше модулей Control UI. Он требует сборку Nginx с
`http_v2_module`; WebSocket по-прежнему использует разрешённый upgrade.
Если проверяете Nginx с временным конфигом от root, обязательно указывайте
`user www-data` и отдельные `*_temp_path` внутри тестового каталога: иначе
Nginx может изменить владельца общих временных каталогов рабочего сервера.

Устанавливайте Ollama proxy vhost после появления `172.24.3.1` на `lo`:
Nginx не запустит listener на адресе, которого ещё нет. Для нового стенда
установите Nginx-примеры по путям из таблицы выше. Следующий
блок рассчитан только на новую конфигурацию: он остановится, если целевые файлы
уже существуют, чтобы не затереть текущий vhost или сертификат.

```bash
sudo bash -euc '
for target in \
  /etc/nginx/bezr-tls \
  /etc/nginx/sites-available/bezr.conf \
  /etc/nginx/conf.d/bezr-websocket.conf \
  /etc/nginx/conf.d/bezr-ollama.conf \
  /etc/nginx/sites-enabled/bezr.conf; do
  test ! -e "$target" && test ! -L "$target" || {
    echo "STOP: target exists: $target" >&2
    exit 1
  }
done

install -d -o root -g root -m 0700 /etc/nginx/bezr-tls
umask 077
openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 365 \
  -keyout /etc/nginx/bezr-tls/bezr.key \
  -out /etc/nginx/bezr-tls/bezr.crt \
  -subj "/CN=bezr.space" \
  -addext "subjectAltName=DNS:bezr.space,DNS:*.agents.bezr.space"
chmod 0600 /etc/nginx/bezr-tls/bezr.key
chmod 0644 /etc/nginx/bezr-tls/bezr.crt

install -o root -g root -m 0644 /opt/bezr/ops/examples/gpu-server/nginx-web.conf.example \
  /etc/nginx/sites-available/bezr.conf
install -o root -g root -m 0644 /opt/bezr/ops/examples/gpu-server/nginx-websocket.conf.example \
  /etc/nginx/conf.d/bezr-websocket.conf
install -o root -g root -m 0644 /opt/bezr/ops/examples/gpu-server/nginx-ollama.conf.example \
  /etc/nginx/conf.d/bezr-ollama.conf
ln -s /etc/nginx/sites-available/bezr.conf /etc/nginx/sites-enabled/bezr.conf
nginx -t
systemctl reload nginx
'
```

Если сертификат подписывает локальный CA, установите выданные сертификат и ключ
с теми же путями и правами вместо генерации. Проверьте оба host name через TLS,
не отключая проверку сертификата:

```bash
curl --cacert /etc/nginx/bezr-tls/bezr.crt \
  --resolve bezr.space:443:127.0.0.1 -I https://bezr.space/
curl --cacert /etc/nginx/bezr-tls/bezr.crt \
  --resolve test-instance.agents.bezr.space:443:127.0.0.1 \
  -I https://test-instance.agents.bezr.space/
```

WebUI работает с существующим volume и пользователями: перед пересозданием
контейнера проверьте актуальные Compose-файлы, volume, `.env` и резервные копии.
Сам Supervisor не разворачивает и не обновляет WebUI.

На текущем GPU-сервере исправление параллельных запросов Control UI внесено
также непосредственно в работающий контейнер WebUI; сам Docker-образ при этом
не пересобран. При пересоздании контейнера это изменение потеряется, если
сначала не собрать и не установить образ с актуальным кодом. Обновление образа
при существующих агентах выполняйте по
[`WEBUI_SIDECAR_UPGRADE.md`](WEBUI_SIDECAR_UPGRADE.md), сохраняя данные и
проверяя совместимость sidecar.

## 5. Изолированная приёмка сети

Приёмка использует отдельные временные systemd units, cgroup, сети и отдельный
Docker daemon; существующий Docker не должен использоваться как тестовый.
Для неё нужен локальный probe-образ, который **не является OpenClaw**:
[`images/acceptance/README.md`](../images/acceptance/README.md). Архив и ID
должны совпадать с описанными контрольными суммами. Исходный более крупный
probe переполнял tmpfs 2 ГиБ; не увеличивайте лимит без анализа ресурсов.

Копия [`gpu-acceptance.example.json`](../ops/examples/gpu-server/gpu-acceptance.example.json)
показывает профиль успешного стенда. Проверьте интерфейс, пулы, endpoint,
root-controlled путь к архиву и фактический блочный I/O device **включая
major/minor**: `/dev/sdd`, `8:48` на другом сервере могут обозначать другое
устройство. Архив должен находиться на том же явно ограниченном блочном
устройстве, а candidate directory должен быть новым и ещё не существовать.
Файл рабочей конфигурации сохраните как `supervisor/gpu-acceptance.local.json`
с root-контролируемыми предками; не перезаписывайте существующий профиль.

```bash
cd /opt/bezr
sudo python3 scripts/gpu_host_acceptance.py --config /opt/bezr/supervisor/gpu-acceptance.local.json --check-config
# Только после проверки всех путей, лимитов и состояния занятого хоста:
sudo python3 scripts/gpu_host_acceptance.py --config /opt/bezr/supervisor/gpu-acceptance.local.json --execute --approve-busy-host --allow-host-inspection
```

`--check-config` проверяет схему, а не сервер. Продолжайте только при
`status=complete`, четырёх прошедших проверках, подтверждённой очистке и
совпадающих before/after снимках. Результат создаётся как **candidate**, не
активирует политики и не запускает Supervisor. При отказе не создавайте
успешный receipt вручную; сохраняйте диагностику.

На текущем сервере ранее созданная подтверждённая копия кандидата находится в
`/mnt/sdd/bezr-acceptance-probe-20261114/candidate-evidence`. Результаты
привязаны к текущему хосту, пулам, endpoint, интерфейсу и версиям политик;
для другого хоста или изменившейся привязки нужна новая приёмка.

## 6. Runtime Supervisor и кандидатные receipts

[`runtime.reference.json`](../ops/examples/gpu-server/runtime.reference.json)
показывает проверенные значения текущего сервера, включая **80 ГиБ**, и служит
для сравнения. Не копируйте его поверх рабочего `runtime.json`: он содержит
машинно-зависимый image ID и пути. Для политики общего дискового бюджета
40 ГиБ аргумент `--capacity-disk-bytes` должен быть `42949672960`, если
оператор отдельно выбрал эту политику. Изменение уже действующего
runtime/базы требует отдельного плана и не выполняется этим примером.

До генерации runtime подготовьте новый root-owned каталог состояния вне XFS
данных агентов, не размещайте его на том же filesystem, и перенесите **оба**
candidate receipt после проверки marker `candidate-ready.json` и production
loaders `load_firewall_acceptance_receipt` и `load_ollama_route_receipt` с
точными текущими параметрами. Используйте эксклюзивное создание файлов, не
перезаписывайте существующие receipt; после переноса повторно проверьте оба
loader. Если перенесён только один, сохраните диагностику и остановитесь.

Пример переноса **для нового state-каталога** из реально завершённой приёмки.
Замените `candidate` на каталог результата именно этого запуска. Скрипт
специально откажет, если state уже существует; на действующем сервере не
используйте его для повторного развёртывания поверх данных.

```bash
cd /opt/bezr
sudo python3 - <<'PY'
import os, stat
from pathlib import Path
from scripts.gpu_host_acceptance import read_config
from scripts.ollama_route_acceptance import strict_json
from supervisor.firewall_acceptance import (
    load_firewall_acceptance_receipt, validate_acceptance_state_path,
)
from supervisor.ollama_firewall import load_ollama_route_receipt

config = read_config('/opt/bezr/supervisor/gpu-acceptance.local.json', secure=True)
site = config['site']
# Укажите каталог, созданный успешным запуском на этой машине.
candidate = Path(config['candidate_dir'])
state = Path('/var/lib/personal-agent-supervisor')
validate_acceptance_state_path(str(candidate))
validate_acceptance_state_path(str(state))
if not candidate.is_dir() or os.path.lexists(state):
    raise SystemExit('STOP: candidate отсутствует или state уже существует')
marker_fd = os.open(candidate / 'candidate-ready.json', os.O_RDONLY | os.O_NOFOLLOW)
with os.fdopen(marker_fd, 'rb') as source:
    info = os.fstat(source.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise SystemExit('STOP: небезопасный candidate marker')
    marker = source.read(4097)
if len(marker) > 4096 or strict_json(marker.decode('ascii')) != {
        'status': 'candidate_ready', 'activation': False}:
    raise SystemExit('STOP: candidate не завершён')
base = (site['agent_network_pool'], site['frontend_network_pool'])
route = (*base, site['ollama_network_pool'], site['ollama_endpoint_ip'], site['egress_interface'])
if not (load_firewall_acceptance_receipt(str(candidate), *base)
        and load_ollama_route_receipt(str(candidate), *route)):
    raise SystemExit('STOP: candidate не соответствует серверу и сети')
os.mkdir(state, 0o700)  # только новый каталог; существующий не изменяется
for name in ('firewall-acceptance.json', 'ollama-route-acceptance.json'):
    source_fd = os.open(candidate / name, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(source_fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise SystemExit('STOP: небезопасный receipt')
        content = source.read(65537)
    if not 0 < len(content) <= 65536:
        raise SystemExit('STOP: неверный размер receipt')
    target_fd = os.open(state / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(target_fd, 'wb') as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())
if not (load_firewall_acceptance_receipt(str(state), *base)
        and load_ollama_route_receipt(str(state), *route)):
    raise SystemExit('STOP: проверка скопированных receipts не прошла')
print('Оба receipt проверены; Supervisor не запускался')
PY
```

При любом отказе после создания state не запускайте Supervisor и не удаляйте
файлы автоматически: сохраните диагностику и разберите частичное состояние.

Далее на **новом** стенде создайте runtime с помощью
`scripts/configure_supervisor.py --prepare-host-config`. Он проверяет оба
receipt, профиль и локальный образ и не перезаписывает существующий runtime.
Ниже пример **после подготовки state/receipt**, значения здесь нужно сверить:

```bash
cd /opt/bezr
sudo /opt/bezr-python/cpython-3.12.16-linux-x86_64-gnu/bin/python3.12 scripts/configure_supervisor.py \
  --prepare-host-config --profile /opt/bezr/supervisor/deployment.local.json \
  --image openclaw-stage2:7c12438929e5 \
  --capacity-ram-bytes 38654705664 --capacity-cpu-millicores 18000 \
  --capacity-disk-bytes 85899345920 --disk-floor-bytes 10737418240 \
  --state-dir /var/lib/personal-agent-supervisor \
  --socket-path /run/personal-agent-supervisor/control.sock \
  --network-profile-default agent_proxy_v1 --control-ui-domain agents.bezr.space \
  --agent-network-pool 172.24.0.0/24 --frontend-network-pool 172.24.1.0/24 \
  --ollama-api-url http://172.24.3.1:11434 --ollama-default-model-id qwen3.5:9b \
  --ollama-context-tokens 65536 --ollama-max-tokens 2048 --no-ollama-think \
  --ollama-network-pool 172.24.2.0/24 --ollama-egress-interface ens1f0
```

Для Qwen3.5 9B на этом сервере контекст 8192 оказался недостаточным для
системных инструкций OpenClaw, инструментов и рабочего контекста. На Tesla P100
12 GiB два одновременно выполнявшихся синтетических API-запроса с контекстом
65536 завершили по 96 токенов: Qwen3.5 9B примерно за 8.4 секунды при 10.7 GiB
занятой VRAM; Qwen3.5 Defiant Q4_K_M примерно за 13.2 секунды при 11.4 GiB.
Холодная загрузка составила около 3.8 и 6.4 секунды соответственно. Проверка
подтверждает Ollama API и выделение двух слотов, но не заменяет тест двух
параллельных диалогов через OpenClaw Gateway.
Пример настроек удержания и параллельности Ollama находится в
[`ollama.service.d.conf.example`](../ops/examples/gpu-server/ollama.service.d.conf.example).
Пример предназначен для установки как
`/etc/systemd/system/ollama.service.d/bezr.conf`: он оставляет одну модель
загруженной, держит её до 24 часов и разрешает два параллельных запроса.
Drop-in уже установлен на GPU-сервере, служба перезапущена; `ollama ps`
подтвердил удержание модели на 24 часа. После изменения drop-in нужна
перезагрузка конфигурации systemd и перезапуск Ollama; проверяйте фактические
параметры и два перекрывающихся запроса.

Начальное значение контекста в текущем `runtime.json` — 16384. Текущий
административный выбор — **65536 токенов**; Supervisor хранит выбор модели и
контекста в root-owned SQLite отдельно от bootstrap-конфига. На новом стенде
после подготовки сервиса войдите в `/agent/` под администратором, выберите модель
и контекст в панели «Модель Ollama», затем подтвердите перезапуск. Supervisor
атомарно обновит настройки всех
существующих агентов, сохранит выбранные модель/контекст в SQLite и данные.
После выбора Supervisor заранее загружает модель пустым запросом `/api/chat` с
теми же `num_ctx`, `think` и `shift=false`, что использует OpenClaw. При создании,
запуске или восстановлении агента выполняется та же проверка загрузки до старта
контейнера. Это прогревает общий Ollama runner: у отдельных агентов нет своих
процессов Ollama. Несколько агентов используют один выбранный runner и
настроенные слоты параллельности; разные модели не фиксируются за отдельными
PID. При смене модели прежний runner заменяется один раз, а новая модель
загружается до возобновления агентов.

Удержание runner на 24 часа не предотвращает его замену, если новый запрос
запрашивает несовместимые параметры. BEZR проверяет ответ загрузки и в панели
администратора показывает, подтвердил ли Ollama готовность runner. Если проверка
загрузки недоступна, настройка модели сохраняется, но первый запрос может
выполнять холодную загрузку.

Эта операция не меняет systemd параметры Ollama. На GPU-сервере Qwen3.5 9B
проверен с короткими запросами; другую модель и длительную генерацию следует
отдельно измерить.

Создание и перенос receipts, state и runtime — не миграция существующих
пользователей. Не удаляйте SQLite, данные, токены, существующие контейнеры и
квоты для повторного прохождения этих шагов.

## 7. Служба и подключение к WebUI

Заполните [`bezr-supervisor.service.in`](../ops/systemd/bezr-supervisor.service.in)
путями доверенного проекта, Python, runtime и mountpoint. Проверьте полученный
unit через `systemd-analyze verify`, затем на новом стенде установите его и
запустите. Не заменяйте уже установленную службу вслепую. Проверяйте статус,
журнал, права на сокет и token, стабильность рестартов и сохранность контейнеров:

Пример подготовки нового unit из шаблона на указанном сервере. Пути Python и
проекта могут отличаться; убедитесь в их существовании. Если подготовленный
unit или установленная служба уже существуют, пример остановится.

```bash
cd /opt/bezr
sudo python3 - <<'PY'
import os, re
from pathlib import Path
source = Path('/opt/bezr/ops/systemd/bezr-supervisor.service.in')
target = Path('/var/lib/personal-agent-supervisor/bezr-supervisor.service')
values = {
    '@AGENT_DATA_MOUNTPOINT@': '/mnt/xfs_data',
    '@RUNTIME_CONFIG_PATH@': '/var/lib/personal-agent-supervisor/runtime.json',
    '@PROJECT_ROOT@': '/opt/bezr',
    '@PYTHON_EXECUTABLE@': '/opt/bezr-python/cpython-3.12.16-linux-x86_64-gnu/bin/python3.12',
}
text = source.read_text(encoding='utf-8')
for key, value in values.items():
    if key not in text:
        raise SystemExit('STOP: в шаблоне отсутствует ожидаемый параметр')
    text = text.replace(key, value)
if re.search(r'@[A-Z][A-Z0-9_]*@', text):
    raise SystemExit('STOP: остались незаполненные переменные')
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w', encoding='utf-8') as stream:
    stream.write(text)
    stream.flush()
    os.fsync(stream.fileno())
PY
sudo systemd-analyze verify /var/lib/personal-agent-supervisor/bezr-supervisor.service
# Здесь проверьте содержимое unit и все пути до установки.
```

После проверки файла установка следующими командами создаёт **новую** службу;
второй блок меняет конфигурацию systemd и запускает процесс от root:

```bash
sudo python3 - <<'PY'
import os
from pathlib import Path
source = Path('/var/lib/personal-agent-supervisor/bezr-supervisor.service')
target = Path('/etc/systemd/system/bezr-supervisor.service')
data = source.read_bytes()
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
with os.fdopen(fd, 'wb') as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
PY
sudo systemctl daemon-reload
sudo systemctl enable --now bezr-supervisor.service
```

Если процесс не прошёл проверки или уже существовала служба с тем же именем,
остановитесь и разберите состояние отдельно. Команда `enable --now` не должна
применяться к неизвестной или непроверенной установленной конфигурации.

```bash
systemctl status bezr-supervisor.service --no-pager
journalctl -u bezr-supervisor.service -n 100 --no-pager
```

Веб-приложению нужен opt-in overlay
[`compose.supervisor.yaml`](../compose.supervisor.yaml), который монтирует
только каталог сокета и token, а не Docker socket. Задайте `SUPERVISOR_SOCKET_DIR`
и `SUPERVISOR_TOKEN_FILE` путями созданной службы и проверьте конфигурацию
с `docker compose -f compose.yaml -f compose.supervisor.yaml config --quiet`.
Для подключения действующего WebUI потребуется аккуратное обновление его
контейнера с сохранением существующих данных и секретов.

**При каждом создании или пересоздании WebUI обязательно передавайте оба
Compose-файла.** Запуск только с `compose.yaml` удаляет из контейнера mount
Supervisor socket и credential; сам WebUI остаётся healthy, но управление
агентами и моделью перестаёт работать.

```bash
cd /opt/bezr
export SUPERVISOR_SOCKET_DIR=/run/personal-agent-supervisor
export SUPERVISOR_TOKEN_FILE=/var/lib/personal-agent-supervisor/service.token
docker compose -f compose.yaml -f compose.supervisor.yaml config --quiet
# Только после проверки образа, volume, .env и наличия резервной копии:
sudo env SUPERVISOR_SOCKET_DIR=/run/personal-agent-supervisor \
  SUPERVISOR_TOKEN_FILE=/var/lib/personal-agent-supervisor/service.token \
  docker compose --project-directory /opt/bezr --env-file /opt/bezr/.env \
  -f /opt/bezr/compose.yaml -f /opt/bezr/compose.supervisor.yaml \
  up -d --no-build --force-recreate --no-deps web

# Прочитать ограниченный статус модели через реальное соединение с Supervisor:
sudo docker exec --user 1000:0 personal-agent-platform-web-1 python -c \
  'from control_plane.runtime import configured_client; print(configured_client().ollama_model_status())'
```

Для **первой установки на пустом хосте**, когда Supervisor уже запущен,
runtime/token/socket готовы и WebUI volume ещё не содержит пользовательских
данных, выполните build и start теми же двумя Compose-файлами:

```bash
cd /opt/bezr
sudo env SUPERVISOR_SOCKET_DIR=/run/personal-agent-supervisor \
  SUPERVISOR_TOKEN_FILE=/var/lib/personal-agent-supervisor/service.token \
  docker compose --project-directory /opt/bezr --env-file /opt/bezr/.env \
  -f /opt/bezr/compose.yaml -f /opt/bezr/compose.supervisor.yaml build web
sudo env SUPERVISOR_SOCKET_DIR=/run/personal-agent-supervisor \
  SUPERVISOR_TOKEN_FILE=/var/lib/personal-agent-supervisor/service.token \
  docker compose --project-directory /opt/bezr --env-file /opt/bezr/.env \
  -f /opt/bezr/compose.yaml -f /opt/bezr/compose.supervisor.yaml \
  up -d --no-deps web
```

Для существующей установки не используйте этот блок как обновление: сначала
резервная копия и процедура из `WEBUI_SIDECAR_UPGRADE.md`.

## 8. Приёмка первого агента и восстановление

1. Создайте один тестовый экземпляр штатным путём; проверьте его фактические
   ограничения RAM/CPU/PIDs и XFS project quota, а не только JSON профиля.
2. Проверьте отдельные сети и запрет доступа к чужим экземплярам, текущий
   firewall, доступ к выбранной Ollama только по разрешённому маршруту и
   реальный запрос к модели с ожидаемым ответом.
3. Проверьте Control UI владельца в браузере: доверенный wildcard TLS,
   загрузку JS/CSS, WebSocket, работу pairing и отказ чужому пользователю.
   Gateway Docker healthcheck сам по себе не доказывает эти свойства.
4. Проверьте штатную остановку и повторный запуск экземпляра, сохранность
   данных и квоты. Затем отдельно запланируйте reboot acceptance: восстановление
   endpoint, firewall, Supervisor и ожидаемого состояния агента.
5. Если этап не прошёл, сохраняйте данные и диагностику. Не ослабляйте
   изоляцию, не публикуйте токены и не удаляйте другие Docker-ресурсы.

## Диагностика частых проблем

| Симптом | Что проверить | Причина / действие |
| --- | --- | --- |
| WebUI healthy, но `/agent` не видит Supervisor | `systemctl is-active bezr-supervisor`; журнал unit; `SUPERVISOR_SOCKET_DIR` и `SUPERVISOR_TOKEN_FILE`; результат `docker compose ... config --quiet`; mounts запущенного WebUI | Обычно WebUI создан без `compose.supervisor.yaml`, путь сокета/токена не совпадает или Supervisor не запущен. Исправьте Compose-конфигурацию и применяйте её с резервной копией WebUI volume; не открывайте Docker socket в WebUI |
| Container не достигает Ollama по `127.0.0.1:11434` | Адрес `172.24.3.1/32` на `lo`, `bezr-ollama-endpoint.service`, Nginx listener, `nft list table inet bezr_ollama_guard` | В контейнере `127.0.0.1` указывает на сам контейнер. Используйте только проверенный внутренний endpoint `http://172.24.3.1:11434` и не публикуйте native Ollama порт |
| Control UI пишет `did not start`, CSS/JS возвращает 403/502/503 | DevTools Network: точный URL/status; `sudo nginx -t`; `journalctl -u nginx`; `namei -l` для обслуживаемого пути; доступность instance wildcard DNS/TLS | Отличайте отказ Nginx/доступа к файлу от ошибки Gateway/WebSocket. Не исправляйте это массовым `chmod -R`; найдите конкретный каталог/файл и сверяйте владельца с конфигурацией |
| Чат возвращает HTTP 500 или context overflow | Сохранённые admin settings ниже; `ollama ps`; `nvidia-smi`; журнал Supervisor и Ollama | Модель/контекст берутся из SQLite Supervisor, а не обязательно из runtime bootstrap. Поддерживаются контексты 8192/16384/32768/65536. На GPU 12 GiB расход зависит от модели, длины prompt и параллельных запросов; измеряйте реальный сценарий |
| Модель снова долго загружается | Был ли рестарт Ollama, смена модели, удаление runner из памяти; `ollama ps` и `nvidia-smi` | `OLLAMA_KEEP_ALIVE=24h` удерживает выбранную модель после использования, пока её не выгрузили или не заменили. Все агенты используют одну native Ollama службу и общую модель; у каждого агента не должно быть отдельного Ollama daemon |
| Приёмка `incomplete` или receipt не создаётся | `status`, `phase`, `checks`, диагностику по `check/stage/condition`, очистку временных unit/network/daemon | Не запускайте Supervisor без успешной host-bound приёмки и не создавайте receipt вручную. Сохраните отчёт, исправьте причину, выполните новую приёмку с новым `candidate_dir` |

Текущие административные настройки модели можно прочитать без показа токенов:

```bash
sudo python3 - <<'PY'
import sqlite3
path = 'file:/var/lib/personal-agent-supervisor/runtime.sqlite3?mode=ro'
with sqlite3.connect(path, uri=True) as db:
    print('model_id:', db.execute(
        "SELECT value FROM admin_settings WHERE key='ollama_default_model_id'"
    ).fetchone())
    print('context_tokens:', db.execute(
        'SELECT context_tokens FROM ollama_context_setting WHERE id=1'
    ).fetchone())
PY
```

Не изменяйте значения этим SQL: для смены модели или контекста используйте
администраторскую панель `/agent/`, которая проверяет модель, прогрев и
обновление активных экземпляров.

Дальнейшие подробности проверок и инвариантов: [SUPERVISOR_RUN.md](SUPERVISOR_RUN.md),
[OLLAMA_ROUTE_ACCEPTANCE.md](OLLAMA_ROUTE_ACCEPTANCE.md) и
[DEPLOYMENT_CONFIG.md](DEPLOYMENT_CONFIG.md). Эти документы могут содержать
исторический статус; актуальность каждого утверждения проверяйте на целевом хосте.
