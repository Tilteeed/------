# Проверенный уровень первой веб-части

## Reboot recovery — текущая локальная доработка (2026-11-13)

Подключены durable Linux boot-ID claim, одноразовый набор CPU-warmup кандидатов, строгий парный identity-bound Docker start/containment и server-loop tick без общего reconcile retry. Первый boot ID только устанавливает baseline; restart Supervisor в том же boot не разрешает запуск упавших контейнеров. Подробности и целевая Linux-приёмка — `docs/REBOOT_RECOVERY.md`.

Независимое source review service/store не выявило блокеров при условии engine contract. Следующий engine/integration review обнаружил два транзитивных побочных эффекта обычного inspect; они исправлены. Повторное focused review (`deleg_e8daa8c6`) оставшихся блокеров в read-only observation/start/containment junction не нашло: boot-наблюдения не выполняют network repair/by-name stop, expected IDs передаются до и после bound start, false containment явно регистрируется. Это ограниченное source review соответствующего junction, не одобрение всей программы или настоящей Linux/Docker-приёмки.

Локально прошли 128 целевых тестов (`test_boot_recovery`, `test_boot_epoch`, `test_identity_bound_start`, `test_runtime_service`, `test_docker_engine_network`) и 100 основных тестов; `compileall` и `git diff --check` — exit 0. Включён связанный service → настоящий DockerEngine код поверх **синтетического** Docker transport, а не только раздельные helper-тесты. Epoch проверяется с реальной временной SQLite и reopen. Два воспроизведённых интеграционных дефекта исправлены RED→GREEN: boot-inspect больше не repair-ит отсутствующий WebUI endpoint до admission и не вызывает by-name stop для replacement после bound start. Это не реальный reboot, XFS, Docker или packet acceptance. Полный Supervisor suite пока не принят: последний прогон route acceptance выявил один отказ соответствия Sidecar agent-подсети; после завершения исправления нужен финальный полный прогон.

По явному напоминанию повторён `hermes verify --json`: `ok:false`, build `docker compose build` exit 1 — Docker CLI не найден. Test/boot/readiness-фазы рецепта не выполнялись. Повторять неизменённый recipe без новых предпосылок не нужно; Docker не устанавливался. Реальные Linux/network/firewall/GPU испытания и выдача route receipt не выполнялись.

## Локальная проверка текущих изменений

- `python -m unittest discover -s tests -v`: **75 тестов, OK**. Pairing, owner-scoping, HTTPS-проверки и запреты прямых маршрутов проверялись тестовыми клиентами/fake Gateway RPC; это не live-проверка OpenClaw.
- `python -m unittest discover -s supervisor/tests -v`: **193 теста, OK**. Включает explicit false/true FirewallManager semantics, receipt workflow, exact pool propagation to both acceptance checks, fail-closed production wiring и retained `/29` regressions.
- `python -m compileall -q supervisor control_plane scripts tests` и `git diff --check`: OK в текущем increment. UI JS не менялся; `node --check` и `node --test` повторно не запускались, ранее записан результат 6 тестов OK; это не browser E2E.
- `python scripts/activate_agent_proxy.py --help`, `python scripts/configure_supervisor.py --help`, `python scripts/linux_docker_proxy_acceptance.py --help` и `python scripts/control_ui_two_user_acceptance.py --help`: CLI разбирают параметры; запускался только help, не live-приёмка.
- Нынешний `scripts/linux_proxy_isolated_check.py` требует явные agent/frontend pools; на Linux его не запускали. Ранее, до появления CLI-параметров pools, вызов на Windows останавливался на platform guard (`This acceptance check requires Linux`) до сетевых действий. Namespace/nft/Docker-проверки не было.
- Linux/Docker/реальный OpenClaw Gateway, TLS/WSS/browser pairing и live two-user приёмка не выполнялись. Исходный `NFTABLES_SEMANTICS_VALIDATED` остаётся `False`; runtime firewall разрешается только с host-bound root-owned receipt (machine-id hash, policy version, exact pools), которого в текущей среде нет. `agent_proxy_v1` поэтому остаётся fail-closed и не является default. Подготовленный orchestrator/receipt workflow на Linux не запускался.

## Успешные локальные проверки (исторический базис первой части)

- `python -X utf8 -m unittest discover -s tests -v`: 18 тестов, OK.
- `node --check web/agent/app.js`: код завершения 0.
- `node --test tests/ui-state.test.mjs`: 4 теста, 4 passed, 0 failed.
- `python -X utf8 -m compileall -q control_plane scripts`: код завершения 0.
- Патчер интеграции дважды применён к отдельной копии настоящего исследованного `main.py`: проверка SHA256, компиляция и идемпотентность прошли. Исходный исследовательский файл не изменялся.
- `git diff --check`: код завершения 0.
- Статический поиск по добавленным строкам полного diff не обнаружил совпадений для hardcoded credential assignments, shell=True/os.system, eval/exec, pickle.loads и форматирования SQL через execute(f...). Это ограниченный поиск шаблонов, не доказательство отсутствия уязвимостей.

HTTP-тесты используют тестовую dependency личности и не запускают реальную аутентификацию Open WebUI. JS-тесты проверяют чистые преобразования состояний и входных данных; они не являются браузерным end-to-end тестом.

## Историческая проверка через Hermes Verify на основном хосте

`hermes verify --detect-only --json` определил рецепт `docker-compose project` по `compose.yaml`: build — `docker compose build`, start — `docker compose up`.

Реальный `hermes verify --json` завершился с кодом 1 и `ok: false`. Этап build не выполнился, поскольку команда `docker` недоступна на основном хосте. До запуска и readiness выполнение не дошло. Ничего не устанавливалось; отсутствие Docker не обходилось подменой контейнерного запуска локальной имитацией.

## Независимая проверка кода

Проверяющий прочитал `scan.json` и патчи `000.patch`–`020.patch` из полного набора 33 файлов. Подтверждённых существенных проблем в прочитанной части не найдено, но **одобрение не выдано** (`passed: false`): чтение оставшихся `021.patch`–`032.patch`, включающих тесты и frontend, остановлено из-за отозванного разрешения инструмента. Повторное чтение другим способом или повторная делегация для обхода отказа не выполнялись.

Эта проверка остаётся незавершённой. Её нельзя считать успешным независимым review всего проекта; для продолжения требуется новое разрешение.

## Последующая ручная приёмка на ВМ — этапы 1 и 2 выполнены

Пользователь запустил проект на ВМ и явно подтвердил весь ранее перечисленный набор проверок веб-базиса: самостоятельная регистрация обычного пользователя, вход/выход, сохранение настроек после перезапуска, разделение двух аккаунтов и отказ защищённого API без токена. В предоставленном `docker ps` веб имеет состояние healthy. Исторический отказ локального Hermes Verify из-за отсутствия Docker на Windows не опровергает состоявшийся запуск на ВМ и не требует повторения тех же проверок.

Для лабораторного OpenClaw предоставлены успешные результаты health/readiness, разрешённого CLI, отказа с неверным токеном именно по token mismatch, pairing Control UI, restart и пересоздания контейнера с сохранением маркеров в трёх volumes. После пересоздания CLI снова получил Gateway Health OK. На скриншоте Control UI модель отсутствует, что соответствует объёму этапа без LLM. Фактический Compose успешно проверен командой `python3 validate_compose.py`.

- Commit проекта на ВМ: `383b27b7aff0bbb3527c0e867c18d199955979f4`.
- OpenClaw: `2026.9.7 (7c12438)`, тег `openclaw-stage2:7c12438929e5`.
- Image ID из inspect: `sha256:5a07114bd0b6a9c578e470ec69747c78d79e5083189891d2c5ae1e136a3073dc`.
- Показанные ограничения: Privileged=false, ReadonlyRootfs=false, Memory=2147483648, PidsLimit=256; порт Gateway опубликован на 127.0.0.1:18789.

Это предоставленные пользователем свидетельства, не собственное выполнение помощником команд на ВМ. Отдельного автоматизированного отчёта Hermes Verify для ВМ и завершённого независимого аудита всего проекта не заявляется. Результаты не доказывают побайтовую воспроизводимость образа, полную изоляцию или отсутствие обходов.

Историческая заметка для приёмки только этапов 1–2: в тот момент OpenClaw работал отдельно, provisioning из кабинета, resource admission и интеграция с Gateway ещё не были подключены. Эти утверждения больше не описывают текущую версию; состояние этапов 3–4 зафиксировано ниже и в `docs/ROADMAP.md`.

## Этапы 3–4: функциональная приёмка host-runtime на ВМ

**Исторический источник:** отчёт пользователя о commit `4494d7575b0c7534076684e6d8547477b527a42f` на Linux-ВМ с Docker/XFS; на момент того отчёта локальный `main` совпадал с тестируемой версией. Более поздний commit `2afe2b5b4da9d5ea1dde1acdac8da015fe591eb7` имеет отдельный пользовательский отчёт с purge/XFS проверками. Restore/UI функции добавлены позднее в `0940fc1` и этим отчётом не проверялись. Это свидетельства пользователя; помощник не подключался к ВМ и не повторял проверки.

В отчёте указано:

- Seccomp-поправка для точного `ioctl(TIOCSPGRP)` устранила сбой tini; отдельный тест tini завершился Exit Code 0.
- Из кабинета создан настоящий OpenClaw-контейнер: Docker `running`, health `healthy`, Exit Code 0, OOMKilled=false.
- Через кабинет выполнены stop → start → restart на том же контейнере; после операций состояние `running / healthy`.
- Проверены персональные файлы и сохранение XFS project ID / inheritance после lifecycle.
- По `docker inspect` проверены `NetworkMode=none`, `ReadonlyRootfs=true`, `Privileged=false`, RAM 2 GiB, CPU 1 vCPU, PIDs 256, `CapDrop=[ALL]`.
- Пользователь под второй учётной записью не видел экземпляр первого в UI.
- Remove через кабинет удалил неисправный контейнер, но оставил данные, project ID и дисковый резерв; после этого удалось создать новый экземпляр с новым Project ID.
- На Linux прошли 73 supervisor-теста.

Это закрывает основную **функциональную** приёмку создания и lifecycle в границах описанного сценария. Это не полный аудит безопасности и не доказательство общей невозможности обхода ограничений.

### Оставшиеся непроверенные/нереализованные пункты

- EDQUOT при достижении hard limit настоящим экземпляром не проверен. Отчёт `2afe2b5` подтверждает quota assignment/readback и запись marker на XFS, но не испытание отказа записи.
- Отчёт `4494d757` проверял второго владельца только на отображение в UI; новый report `2afe2b5` дополнительно зафиксировал один отказ cross-owner purge до изменения чужого контейнера/quota. Это не полный authorization audit всех операций и endpoints.
- Не проверены одновременное создание несколькими владельцами, конкурентные lifecycle-запросы и восстановление supervisor при уже работающем управляемом экземпляре.
- Автозапуск supervisor после reboot не настроен.
- Текущий локальный purge owner-scoped и journaled. Storage DB открывается на запись только явным `mode=rw` без создания, обход дерева привязан к directory FDs и проверяет inode/device/mount ID, instance snapshot/token и payload всех операций scrub-ятся, а disk reservation остаётся до успешного WAL checkpoint; retry после scrub использует минимальные purge metadata.
- Это подтверждено локальными temp-SQLite и syscall-mock тестами; пользовательский отчёт для `2afe2b5` дополнительно подтверждает один реальный purge/quota reset на Linux/XFS. Report не проверяет adversarial mount/symlink race и EDQUOT; secure forensic erase от SSD не гарантируется.
- Restore retained storage — отдельная операция, локально реализована для прежних instance ID/path/quota; новые тесты не проверяют реальный Docker/XFS. Workspace browser теперь существует в локальном коде и ограничен `state/workspace`: owner-scoped, no-follow, без dotfiles/credentials/secrets, preview до 256 KiB и download до 16 MiB с пагинацией. Его browser/Linux VM acceptance ещё не проводилась. Cleanup после failed create с отсутствующим/неполным XFS journal отдельно не проверен.
- Gateway в кабинет, применение обновлённых настроек, LLM/chat и Telegram не подключены.

### Локальный этап Ollama/Supervisor (2026-11-12; HEAD `ca3c84b559f1e915cb2747d92d98bd1a1284e277`, незакоммиченные изменения на `main`)

В рабочей копии добавлены: root-controlled Ollama policy с точным allowlist, persisted admin model selection в SQLite, root-only AF_UNIX status/change RPC и CLI, атомарная замена защищённого `openclaw.json` для уже созданных экземпляров, новый `contextTokens` вместе с `contextWindow`/Ollama `params.num_ctx`, static model catalog (`models.mode=replace`, только выбранный ID, Ollama discovery/node-inference выключены), config policy v1 (root:1000, mode 0440, `FS_IMMUTABLE_FL` при Ollama, read-only file bind и `OPENCLAW_CONFIG_READONLY=1`), persisted `desired_state`, firewall-first `reconcile()` и только шаблон systemd-unit. При `ollama:null` прежний no-model startup сохраняется. Миграция SQLite — только явной backup-based командой; на пользовательской БД не запускалась.

По закреплённому OpenClaw `7c12438929e5d198616fe8f602d896e011647d39` локально прочитаны `docs/concepts/models.md`, `docs/cli/config.md`, `docs/gateway/configuration/config-rpc.md`, `src/gateway/methods/core-descriptors.ts` и `extensions/ollama/index.ts`. Документированные config-write RPC требуют `operator.admin`; trusted-proxy owner scope этого права не получает; built-in `gateway` tool ограничен чтением конфигурации. Это source review, не live RPC test. Read-only environment и file/mount protections не проверялись на реальном pinned Docker image/Linux.

Контролируемая смена модели сохраняет instance ID, data path и несвязанные Gateway/plugin-настройки; неизвестный model/agent config drift приводит к отказу. Это проверено только unit/synthetic adapters. Для прямого egress локально добавлены отдельная per-instance `/29` bridge/IPAM-планировка, точная проверка Docker network identity/membership и host-route ownership (connected/local/broadcast routes должны совпадать с bridge/IPAM и preferred source), отдельная allowlist nft table и независимый host-bound route receipt. `configure_supervisor.py` требует этот receipt вместе с базовым proxy receipt; DockerEngine не создаёт/не подключает route network и не стартует Gateway без совпадающего route gate/read-back, а reboot reconciliation проверяет маршрут до запуска. Это лишь source/fake-adapter evidence: production endpoint/pool/interface и receipt не заданы, Linux nftables/Docker packet path не принимались; firewall host не инспектировался и не менялся. Поэтому direct route не активирован, `chat` остаётся выключенным. L3/L4 route сам по себе не ограничит HTTP path или `model` в JSON body; до Broker/upstream enforcement сырой API остаётся ограничением, SEC-09 нельзя объявлять полностью закрытым. Реальный `/api/chat`, полный OpenClaw tools cycle, GPU/VRAM, pinned Docker image, Linux immutable flag и reboot не проверялись.

После route-изменений: `python -m unittest discover -s supervisor/tests -q` — 301 тест OK, 8 skipped; `python -m unittest discover -s tests -q` — 99 OK; `compileall` и `git diff --check` — OK. `hermes verify --json` ранее остановился на `docker compose build`, потому что Docker отсутствует; subsequent test/start/readiness phases не выполнялись, и неизменённый verifier не повторялся. Ничего не устанавливалось, сервер/firewall/XFS/VM, GitHub и пользовательские данные не менялись. Все изменения локальные и незакоммиченные.

Не запускать очистку существующего Project ID/каталога или сброс SQLite для проверки. Для реального EDQUOT и purge нужен отдельный изолированный набор данных/проект и согласованный сценарий.

### Подтверждённая последовательность обновления supervisor

Пользователь уточнил по переписке и выводам команд последовательность проверки на ВМ:

1. Запустили старый supervisor `336aedde`.
2. Через `/agent` удалили неисправный контейнер с сохранением данных.
3. Проверили, что старый контейнер отсутствует в `docker ps -a`, а SQLite показывает `Instance: (0, 'removed')`.
4. Остановили старый supervisor.
5. Запустили новый supervisor `4494d757` с существующими `runtime.json` и SQLite; он открыл private Unix socket и прогрел CPU-окно.
6. Затем создали новый контейнер, который прошёл healthcheck.

Следовательно, reconciliation не должен был принимать старый seccomp-профиль: на старте новой службы старый контейнер уже отсутствовал, а запись была неактивной. Операции retain сохранили старые данные и диск-резерв; новый экземпляр получил отдельный Project ID.

Это подтверждает именно такой порядок обновления на этой ВМ. Оно **не** доказывает, что новую версию можно запустить поверх активного контейнера, созданного со старым seccomp: current DockerEngine exact-check/reconcile по-прежнему может блокировать такой запуск. Не очищать SQLite или retained data ради обхода; активный старый экземпляр требует отдельного безопасного плана.

## Новый пользовательский отчёт для commit `2afe2b5`

**Источник:** приложенный пользователем отчёт от 1 ноября 2026 года о Linux-ВМ. Коммит совпадает с локальным базовым HEAD `2afe2b5b4da9d5ea1dde1acdac8da015fe591eb7`; последующий commit `0940fc1`, включая restore retained storage, в отчёте не проверялся. Это свидетельство пользователя, не собственный запуск помощника.

Отчёт подтверждает для испытанной версии:

- Open WebUI, supervisor и два персональных контейнера были `healthy`; отдельные owner/project/quota/reservations зафиксированы.
- Для временного `Purge Smoke Test` выполнена запись через container bind mount и обнаружен marker на host XFS; реальный `EDQUOT` не проверяли.
- `remove` сохранил каталог/marker и 10 GiB quota, перевёл запись в `removed/inactive` и освободил RAM/CPU; затем `purge` удалил тестовый каталог, сбросил quota, очистил instance snapshot/token/operation payloads и storage DB rows, не затронув два других агента.
- Проверены чужой purge (включая админский аккаунт), API input/Origin validation, replay/conflict idempotency и восемь параллельных повторов уже завершённого create.
- Resource admission отказал четырём create запросам при низком `MemAvailable`; внутренняя причина отдельно не извлекалась. Эти запросы не проверяли конкурентное первоначальное создание без существующего экземпляра.
- Supervisor autostart, restart/reconcile с работающими контейнерами, recovery после прерванной операции, EDQUOT и конкурентный первоначальный create остались непроверенными.

Отчёт фиксирует очистку временного Purge Smoke Test и старых тестовых Project ID; не считать тот тестовый dataset доступным для будущего restore. Вывод отчёта — успешная функциональная приёмка перечисленных Stage 3 сценариев на `2afe2b5`, но не полная security/operations acceptance. Локальный тест `SupervisorRestartRecoveryTests.test_reconcile_after_store_reopen_preserves_running_instance_and_reservations` прошёл с fake adapters; это не реальный Supervisor/Docker/XFS restart.

**Позднее уточнение пользователя:** текущая серия Stage 3 функциональных проверок уже выполнена; переходим к разработке и не повторяем эти проверки как следующий шаг. Подробные новые результаты после приложенного отчёта не предоставлены, поэтому их точные сценарии/выводы здесь не дополняются. Новые локальные изменения restore/workspace browser требуют собственной целевой browser/VM приёмки после согласованной доставки.
