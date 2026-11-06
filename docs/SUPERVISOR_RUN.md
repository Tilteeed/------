# Запуск кабинета с host-supervisor

## Что меняется

Кабинет передаёт проверенную Open WebUI identity через приватный Unix socket. Только host-supervisor обращается к Docker и XFS. Веб и агенты не получают Docker socket. Пользовательский отчёт для `2afe2b5` подтверждает отдельный реальный purge/XFS сценарий на disposable dataset. Restore и workspace browser реализованы локально, но не прошли VM/browser приёмку.

Локально реализованы BEZR-кнопка, one-time ticket/session handoff, HTTP/WS Access Proxy, relay, Open WebUI host middleware, per-instance agent/frontend-сети, Sidecar lifecycle, `trusted-proxy` config, Supervisor target/readiness, ограниченные HTTP/WebSocket scopes и owner-scoped ручной pairing в существующем `/agent`. Admin HTTP RPC list/approve доступен только внутреннему Sidecar handler; публичный Access Proxy блокирует оба служебных пути. Обычный create остаётся на legacy `NetworkMode=none`; исходный `NFTABLES_SEMANTICS_VALIDATED` остаётся `False`, а runtime firewall может быть разрешён только при валидном root-owned `firewall-acceptance.json`, созданном после Linux/nftables и Docker isolation acceptance и совпадающем с machine-id hash, policy version и обоими pools. Такой receipt в текущей среде не создан; Linux/Docker/browser acceptance не пройдена. `network_profile_default` по-прежнему `legacy_none`, пока оператор явно не задаст `agent_proxy_v1` после receipt. Sidecar query передаётся через `raw_path_qs`; Access Proxy требует HTTPS/WSS ASGI scope и сверяет канонический `X-Forwarded-For` с ASGI client и `X-Forwarded-Proto`. Фактический peer/scope за Docker TLS edge ещё не проверен. Лимиты Sidecar 128 MiB / 100m / 32 PIDs учитываются в локальном runtime accounting. Это не готовая production-функция; не развёртывать на ВМ до отдельной приёмки.

## Подготовка на Linux-ВМ

Доставьте код обычным Git-путём. Уже принятые настройки XFS и локальный deployment-профиль менять не нужно. Используется ранее собранный локальный образ OpenClaw; он фиксируется по image ID, автоматического pull нет. Новых Python-пакетов не требуется. Из утилит нужны уже используемые Docker и xfsprogs, включая xfs_io.

### Host-bound acceptance receipt for `agent_proxy_v1`

Для нового disposable Linux/Docker-хоста сначала после отдельного согласия оператора выполнить оркестратор (A и B ниже по runbook выполняются последовательно внутри него):

```bash
sudo python3 scripts/activate_agent_proxy.py --agent-pool <EXPLICIT_RFC1918_AGENT_TEST_POOL> --frontend-pool <EXPLICIT_RFC1918_FRONTEND_TEST_POOL> --probe-image sha256:<64_HEX_LOCAL_PYTHON3_IMAGE_ID> --state-dir /var/lib/personal-agent-supervisor --execute --confirm-disposable-host
```

Оркестратор требует Linux, root, уже установленный `ip`/`nft`/`unshare`/Docker и уже локальный immutable probe image; ничего не устанавливает и не скачивает. Если любой из двух проверочных этапов завершается ошибкой, новый receipt не записывается. После двух `PASS` он атомарно создаёт/обновляет `firewall-acceptance.json` с владельцем `root:root`, mode `0600`, внутри root-owned каталога `0700`. Receipt содержит только SHA256 от `/etc/machine-id` (не исходный ID), версию firewall policy, оба точных test pools и имена пройденных этапов. Копия на другой host, изменение pools или policy version закрывают gate. Это локальная root-admin attestation, а не подпись от недоверенного root.

Команда не запускает BEZR/Supervisor и не выбирает network profile. Затем конфигурирование `agent_proxy_v1` требует те же pools, Control UI domain и валидный receipt; `legacy_none` остаётся default:

```text
--network-profile-default agent_proxy_v1
--control-ui-domain <EXACT_TEST_DOMAIN_SUFFIX>
--agent-network-pool <SAME_AGENT_POOL>
--frontend-network-pool <SAME_FRONTEND_POOL>
```

Эти аргументы добавляются к обычному `configure_supervisor.py --prepare-host-config`. При старте Supervisor receipt проверяется снова; отсутствие/ошибка/несовпадение означает `semantics_validated=False` и fail-closed. При изменении семантики firewall увеличивать `FIREWALL_POLICY_VERSION` и проходить acceptance заново. В этой локальной Windows-среде orchestrator/live acceptance и запись receipt не выполнялись.

Оператор выбирает **общие** бюджеты RAM/CPU/disk для всех экземпляров, оставляя ресурсы ОС, вебу и будущей модели. Это не остаток после вычитания существующих экземпляров. Ёмкости, пути и UUID другой машины определяются заново. Значения в переносимом runtime.example.json намеренно не заполнены.

Пример настройки только для описанной лаборатории с примерно 8 GiB RAM, 8 CPU и 50 GiB XFS: общий бюджет 4 GiB RAM / 4 CPU / 40 GiB данных, свободный остаток XFS не менее 1 GiB. Это **предложение для первого запуска, не ранее согласованные значения и не универсальные defaults**; перед выполнением скорректируйте их под фактическую ВМ. Disk limit одного агента по-прежнему берётся из вашего deployment.local.json.

```bash
sudo python3 scripts/configure_supervisor.py --prepare-host-config \
  --profile supervisor/deployment.local.json \
  --image openclaw-stage2:7c12438929e5 \
  --capacity-ram-bytes 4294967296 \
  --capacity-cpu-millicores 4000 \
  --capacity-disk-bytes 42949672960 \
  --disk-floor-bytes 1073741824
```

При явном запуске оператором с флагом `--prepare-host-config` команда создаёт закрытый root-owned каталог /var/lib/personal-agent-supervisor и административные deployment.json/runtime.json. Исходный локальный профиль в проекте не меняется. Существующий runtime.json не перезаписывается; несовпадающий административный snapshot отклоняется. Служба не запускается, пакеты не устанавливаются, mount/квоты и данные агентов не меняются. Для другого пути к образу задайте свой --image; в runtime config попадёт неизменяемый ID реально существующего локального образа.

## Запуск

### SQLite migration gate for network-profile metadata

Старые runtime SQLite не изменяются автоматически. Если existing database ещё не содержит `instances.network_profile`, Supervisor завершится с `runtime_schema_migration_required` до изменения journal mode или данных. Для дальнейшего запуска требуется отдельное одобренное обслуживание: остановить Supervisor, проверить точный путь БД, выбрать новый защищённый backup path, затем выполнить из корня проекта:

```bash
sudo python3 scripts/migrate_runtime_network_profile.py \
  --database /var/lib/personal-agent-supervisor/runtime.sqlite3 \
  --backup /var/lib/personal-agent-supervisor/backups/runtime-before-network-profile.sqlite3 \
  --apply
```

Команда откажет без `--apply`, не перезапишет существующий backup, создаст консистентный SQLite backup через Backup API и только затем добавит столбец; старые строки получают `legacy_none`, что сохраняет старую Docker spec. Она **не** меняет контейнеры, XFS, файлы агентов или настройки OpenClaw. Команда выше — runbook-шаблон, не выполнялась и не является разрешением на VM/privileged изменение. Сначала нужна проверка recovery процедуры на синтетической копии и отдельное согласие оператора.

**Следующая команда уже запускает привилегированный компонент.** Он создаёт служебную SQLite, credential и Unix socket. После нажатия «Создать» будет назначать project ID/квоты и создавать контейнеры на подготовленной XFS. Это изменяющие ВМ операции; выполнять только после принятия этих действий оператором. Не запускать на основном Windows-хосте.

В отдельном терминале из корня проекта:

```bash
sudo python3 -m supervisor.service --config /var/lib/personal-agent-supervisor/runtime.json --enable-host-runtime
```

Дождитесь готовности CPU-окна: первые 60 секунд создание/запуск закрыты. Не выставляйте фиктивные метрики или quota flags. Закрытие процесса останавливает supervisor, а не автоматически контейнеры. Для первого запуска оставьте терминал открытым; оформление службы автозапуска не выполняется скрытно.

Во втором терминале, для стандартных путей из runtime config:

```bash
export SUPERVISOR_SOCKET_DIR=/run/personal-agent-supervisor
export SUPERVISOR_TOKEN_FILE=/var/lib/personal-agent-supervisor/service.token

sudo test -S "$SUPERVISOR_SOCKET_DIR/control.sock" && \
sudo test -f "$SUPERVISOR_TOKEN_FILE" && \
docker compose -f compose.yaml -f compose.supervisor.yaml up -d --build
```

Если изменены служебные пути, здесь укажите свои. Дополнительный Compose-файл подключает только socket directory и отдельный credential read-only. Отсутствующие bind sources не создаются автоматически. Секрет не копировать в браузер, .env, Git или вывод команд. Базовый compose.yaml без override сохраняет прежний режим web-only.

Код запускаемого от root компонента и его конфигурация должны находиться под административным контролем, вне путей, доступных вебу/агентам на запись. Supervisor не является защитой от компрометации администратора хоста или доверенного веб-backend.

## Короткая приёмка

Пункты ниже описывают прежнюю принятую lifecycle-серию; Stage 3 повторно не запускать. Новая приёмка понадобится только после отдельного разрешения доставки и готового Control UI/model slices.

1. Ранее пользователь сообщал о lifecycle-проверках create/start/stop/restart/remove-retain на своей ВМ; см. `docs/verification.md`.
2. Контроль владельца, retained restore и workspace browser для более новых функций требуют отдельной приёмки; локальные fake-тесты не подтверждают их на ВМ.
3. `agent_internal_v1` не делает Control UI доступным. Launch/status требуют `agent_proxy_v1`, готового server-resolved sidecar target и смонтированного Access Proxy; Supervisor пока не обеспечивает sidecar target, поэтому production status остаётся unavailable.

**Не нажимайте «Удалить данные и квоту» в этой обычной приёмке.** Пользовательский отчёт для `2afe2b5` уже подтверждает один purge на отдельном disposable XFS dataset. Любой повторный purge/release test — отдельное необратимое действие: он требует отдельного согласия и нового disposable набора данных, не действующих пользовательских данных.

Не нужно запускать отдельные unit-наборы после каждого шага. Если операция не завершилась, обновите состояние: timeout не означает, что контейнер не создан. Незавершённый intent/резерв сохраняется для восстановления; не удаляйте SQLite и каталоги вручную ради повторного создания.

## Границы

Жизненный цикл не означает готовность модели или чата. Изменения инструкций после первоначального создания пока остаются черновиком. `remove` сохраняет данные; пользовательский отчёт для `2afe2b5` подтверждает один реальный `purge` disposable XFS dataset. Локально доступны restore того же retained instance и workspace-only list/preview/download; новые функции не проверены на ВМ/browser E2E, и доступ не распространяется на secrets/credentials/internal state. Не использовать purge для сброса binding/SQLite или проверки на действующих данных; стандартная приёмка выше не включает purge/restore.

Фактическую готовность на XFS/Docker подтверждает приёмка на ВМ; локальный прогон с имитированными backend-ами не заменяет её.

По отчёту пользователя для commit `2afe2b5` после предыдущей 4494-приёмки дополнительно проверены два персональных контейнера, XFS write, remove-retain и purge временного test set с quota release. Это пользовательская VM-приёмка; точные ограничения, неисполненные тесты и дальнейший следующий шаг — в `docs/verification.md`.

## Архивный план контролируемой проверки restart/reconcile Supervisor

Этот план был составлен по более раннему отчёту о непроверенном restart. Пользователь позднее подтвердил, что текущая серия Stage 3 функциональных проверок завершена; **не повторять её сейчас**. Сохранять шаги как reference на случай новой конкретной проверки/регрессии. План не является разрешением на VM-доступ, публикацию, изменение системы или запуск.

**Если появится новая необходимость, перед запуском потребуется отдельное согласие пользователя.** Не использовать незакоммиченный локальный код без отдельного согласования доставки и rollout. Не запускать одновременно create/start/stop/restart/remove/purge/restore и не очищать/редактировать SQLite.

1. Оператор на ВМ фиксирует время, commit/версию supervisor, способ запуска, активные Docker container IDs/names/status/health, SQLite instance IDs/state/active/container bindings и totals reservations, а также read-only XFS project/quota assignment. Не выводить settings, gateway tokens, инструкции, operation payloads или иные секреты. Резервную копию делать только по уже утверждённой процедуре и в согласованное защищённое место.
2. Остановить только Supervisor существующим для этой ВМ способом; Docker daemon и agent containers не трогать. Во время остановки убедиться, что container IDs и health не изменились.
3. Запустить тот же Supervisor с прежними `runtime.json`, SQLite и environment. Не менять настройки безопасности или storage profile в рамках этого теста.
4. После запуска проверить `/health`, доступ `/agent`, прежние instance/container IDs и состояния, неизменность totals reservations и XFS project/quota. Убедиться, что reconcile не создал/не запустил контейнеры повторно и SQLite не получила дубликаты.
5. При ошибке старта/reconcile не очищать DB, не удалять containers/data и не нажимать purge/restore. Оставить Docker workloads как есть, сохранить только redacted diagnostics и остановиться для разбора.

**Критерии для такой будущей проверки:** Supervisor healthy; те же контейнеры работают с прежними IDs; данные и quota не изменились; SQLite сохраняет те же активные bindings и resource totals без дублей; `/agent` показывает соответствующие состояния. Пользователь говорит, что текущая серия функциональных проверок уже завершена, но точные результаты этой последовательности в документе не приведены. Новые локальные file-browser изменения требуют отдельной приёмки после согласованной доставки.

**Seccomp upgrade boundary:** пользователь подтвердил конкретную последовательность лабораторного rollout: старый supervisor `336aedde` сначала удалил неисправный контейнер через UI с сохранением данных; проверены его отсутствие в `docker ps -a` и SQLite `(0, 'removed')`; затем старый процесс остановили, новый supervisor `4494d757` запустили с сохранёнными runtime.json/SQLite, после чего создали новый контейнер. Это работает, потому что на startup reconcile не было старого активного Docker binding.


Не переносите этот вывод на активный контейнер, созданный со старым seccomp. DockerEngine exact-check включает `SecurityOpt`, а startup reconciliation выполняется до открытия socket; такой экземпляр может заблокировать запуск. Не очищайте SQLite и данные, чтобы обойти проверку. Если старый экземпляр ещё active, сначала нужен отдельный безопасный план его обработки.
