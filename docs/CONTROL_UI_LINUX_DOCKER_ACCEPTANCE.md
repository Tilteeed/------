# Control UI: изолированная Linux/Docker-приёмка

## Статус и границы

Runbook и скрипты подготовлены локально. Они **не запускались** на Linux, Docker, nftables или ВМ; текущая среда — Windows. ВМ не создавалась, подключений не было. Исходный `NFTABLES_SEMANTICS_VALIDATED` остаётся `False`; runtime gate может открыться только по валидному root-owned receipt после A+B. Receipt в текущей среде отсутствует, поэтому `agent_proxy_v1` здесь остаётся fail-closed. Обычный `create` остаётся на `legacy_none`.

Скрипты предназначены только для новой disposable Linux/Docker-ВМ с синтетическими пользователями и данными. Не запускать их на действующей ВМ: они меняют firewall-таблицы и временно создают Docker networks/containers. Они не запускают `docker pull`, не создают volumes и не обращаются к проектной SQLite/XFS. До отдельного согласования тестового target и доступа ничего здесь не исполнять.

В runtime Docker lifecycle разделён: `created` проверяется по точному набору сетей и `IPAMConfig.IPv4Address`; пустые `NetworkID`/`IPAddress` допустимы только на этом этапе и не означают готовность. Для `running` обязательны фактические IDs/IP и membership. `paused`/`restarting` не принимаются как config-only состояния и требуют фактических endpoint-параметров; они не считаются готовыми. Перед стартом проверяется nftables policy, после запуска Gateway и Sidecar live-проверки выполняются повторно; Control UI не открывается без успешных проверок и здоровых контейнеров. Регрессионные тесты содержат shape ответа Docker 29.5.3, сообщённый для стадии `created`; это не заменяет проверку на реальном Docker Engine.

## Скрипты

1. `scripts/linux_proxy_isolated_check.py` — независимая proxy-only packet lab в private net/mount/PID namespaces, без synthetic Docker API. Реальные `ip`/`nft`, HTTP controls до/после enforcement, cold neighbour caches и строгий JSON readback; 36 потоков. Это не Docker data-plane доказательство и не прежний retained-route scaffold.
2. `scripts/linux_docker_proxy_acceptance.py` — та же независимая матрица на настоящих контейнерах отдельного nested daemon, не caller Docker. Нужны явный image archive и immutable `sha256:` image ID с Python 3; pull запрещён. Проверяются canonical IPAM/options/labels и live membership, свои разрешённые пары и cross-owner/host/external отказы; baseline Ollama table не используется для получения base PASS. Это не испытание настоящего OpenClaw/WebUI. Проверки retained-route ownership остаются отдельными регрессиями, не заявляются результатом этой новой матрицы.
3. `scripts/control_ui_two_user_acceptance.py` — live HTTPS API/handoff проверки двумя синтетическими BEZR-пользователями: разные owner origins, pairing list, cookie handoff, отказ чужой host-сессии и запрет браузерного доступа к Admin RPC/private pairing route. Создаёт краткоживущие BEZR Control UI sessions; запускать только на свежей тестовой БД. Токены берутся из environment, не печатаются и не записываются.

### Контракт pairing API

Gateway-интеграция закреплена на OpenClaw commit `7c12438929e5d198616fe8f602d896e011647d39`. Sidecar использует Admin HTTP RPC `POST /api/v1/admin/rpc` с envelope этой версии (`ok` и `payload`) только для методов `device.pair.list` и `device.pair.approve`. Browser relay запрещает Gateway RPC path и private Sidecar pairing path; BEZR API получает owner/instance только из проверенной сессии и текущего runtime, а не из переданных браузером target fields. Перед approve перечитывается текущее pending request, затем сравниваются request/device/role/scopes с тем, что увидел владелец; допускаются только штатный Control UI, точный instance origin и allowlisted non-admin scopes. После approve повторно читается список устройств. Это локально проверенный контракт, но не доказательство того, что закреплённый Gateway уже принял его в runtime.

Ни один из этих тестов не заменяет ручную проверку штатного Control UI в двух отдельных браузерных профилях и его реального WSS handshake/reconnect.

`scripts/activate_agent_proxy.py` — receipt-producing orchestrator: повторно запускает A и B на одном disposable host и только после обоих `PASS` пишет root-owned receipt в `state_dir/firewall-acceptance.json`. Запуск одного A/B отдельно receipt не создаёт. Receipt открывает только host-scoped firewall semantics gate; он не подтверждает HTTPS/WSS, pairing или готовность production UI.

## Условия до запуска

- Согласовать отдельную disposable Linux-ВМ и способ доступа; не подключаться к существующей лабораторной ВМ без отдельного подтверждения.
- На target должны быть уже доступны Linux, Docker Engine, `nft`, `ip`, `unshare`, Python и нужный локальный probe image. Скрипты ничего не устанавливают и не загружают. Этап B запускать только на чистой выделенной VM до установки/запуска BEZR Supervisor/WebUI: временные production-style `pa-agent-*`/`pa-front-*` network names не должны быть обнаружены активным Supervisor.
- Использовать свежую тестовую установку BEZR со свежей SQLite и двумя синтетическими аккаунтами. Не переносить рабочую БД, контейнеры, credentials, пользовательские файлы или XFS-наборы.
- Настроить только тестовые hostname: `AGENT_PLATFORM_PUBLIC_ORIGIN` — bare HTTPS origin BEZR, `AGENT_CONTROL_UI_DOMAIN` — отдельный wildcard test suffix. TLS-сертификат должен покрывать BEZR host и `*.AGENT_CONTROL_UI_DOMAIN`.
- TLS edge должен перезаписывать, а не дополнять `X-Forwarded-For`, задавать `X-Forwarded-Proto=https` и подключаться к loopback-only BEZR listener. Uvicorn доверяет только фактическому адресу edge. На target подтвердить, что ASGI `scope.client` совпадает с одним canonical forwarded client IP; не задавать wildcard trusted proxy.
- Выбрать непересекающиеся RFC1918 test pools после read-only проверки всех host routes и Docker IPAM. Значения из примеров/тестов не переносить в конфигурацию ВМ.

## Последовательность

### A. Linux route и nftables JSON precheck

В disposable VM, с правами, необходимыми для `unshare`:

```bash
sudo python3 scripts/linux_proxy_isolated_check.py --agent-pool <EXPLICIT_RFC1918_AGENT_TEST_POOL> --frontend-pool <EXPLICIT_RFC1918_FRONTEND_TEST_POOL> --execute --confirm-disposable-host
```

Ожидать exit 0 и полный structured JSON report с controls/readback/cold-neighbour/cleanup evidence; отдельный запуск receipt не создаёт. Это настоящая namespace packet lab без Docker daemon, а не synthetic Docker API. При несовпадении сохранить ограниченный приватный вывод и фактический `nft -a -j` результат. Не ослаблять сравнение ради PASS.

### B. Настоящие Docker networks, nftables и packet isolation

Сначала проверить, что probe image уже локальный и имеет immutable image ID с Python 3. Не подставлять тег и не разрешать pull. Пулы задаются явно:

```bash
sudo python3 scripts/linux_docker_proxy_acceptance.py \
  --agent-pool <EXPLICIT_RFC1918_AGENT_TEST_POOL> \
  --frontend-pool <EXPLICIT_RFC1918_FRONTEND_TEST_POOL> \
  --probe-image sha256:<64_HEX_LOCAL_IMAGE_ID> \
  --image-archive <ABSOLUTE_OPERATOR_PROVIDED_IMAGE_ARCHIVE> \
  --execute --confirm-disposable-host
```

Скрипт требует root и проверяет, что dedicated `inet`/`bridge` `agent_proxy_v1` tables отсутствуют. Временная политика содержит только два synthetic instance endpoint pairs; её readback сверяется полностью. Проверяются WebUI-probe → оба Sidecar-probe, каждый Sidecar-probe → свой Gateway-probe, отрицательные cross-owner/host/routed probes и host-to-container/ container-to-host probes. После завершения удаляются только созданные им container/network IDs и его dedicated tables. Нет `docker system prune`, удаления volumes, SQLite или каталогов данных.

Отдельный запуск A и B — диагностика и не записывает activation receipt. Для него выполнить оркестратор, который повторяет оба теста на том же disposable host и создаёт receipt только при двух `PASS`:

```bash
sudo python3 scripts/activate_agent_proxy.py --agent-pool <SAME_AGENT_POOL> --frontend-pool <SAME_FRONTEND_POOL> --probe-image sha256:<64_HEX_LOCAL_IMAGE_ID> --image-archive <ABSOLUTE_OPERATOR_PROVIDED_IMAGE_ARCHIVE> --state-dir /var/lib/personal-agent-supervisor --execute --confirm-disposable-host
```

Если любой этап завершается ошибкой, новая запись не создаётся. Receipt привязан к SHA256 machine-id, policy version и точным pools; после него `configure_supervisor.py` может принять `--network-profile-default agent_proxy_v1`, но только с теми же pools и явным Control UI domain. Это открывает только firewall semantics gate, не завершает C/D и не подтверждает production UI.

Если скрипт прерван аварийно или сообщает `CLEANUP INCOMPLETE`, не запускать его повторно и не применять global flush/prune. Остановиться, зафиксировать точный run ID и выполнить только согласованное read-only расследование состояния выделенной ВМ.

### C. Два пользователя, hostname routing и cookie handoff

Передавать тестовые токены только через скрытый prompt/environment manager ВМ; не писать их в командную строку, Git, отчёт или чат. Пример запуска после безопасной установки environment без отображения значений:

```bash
python3 scripts/control_ui_two_user_acceptance.py \
  --app-origin https://<BEZR_TEST_HOST> \
  --control-ui-domain <WILDCARD_TEST_SUFFIX> \
  --cafile <TEST_CA_PEM> \
  --execute --confirm-disposable-test-users
```

`--cafile` необязателен при установленном доверенном test CA. Проверка использует обычную TLS-валидацию; insecure TLS отключать нельзя. Скрипт получает status и pairing list для Alice/Bob, выполняет их раздельный launch-ticket handoff и проверяет отказ Bob на Alice host. Он проверяет только HTTP/API-контракт; это не browser/WSS acceptance.

### D. Ручной browser pairing и штатный Control UI

1. В двух отдельных browser profiles войти как Alice и Bob. Запустить тестовые Gateway-экземпляры только в изолированной тестовой конфигурации.
2. Из кабинета Alice нажать «Открыть агента». Штатный OpenClaw Control UI должен открыться на Alice instance hostname; другая страница чата не создаётся.
3. Если Gateway показывает pending device request, вернуться в кабинет Alice и нажать «Проверить запросы». Проверить display name, browser origin, роль `operator` и каждый scope. Только вручную нажать «Одобрить» для ожидаемого браузера. Запросы с `operator.admin`, другой ролью, другим origin, silent-флагом или неизвестными scopes должны оставаться неразрешимыми. При изменении request ID/scopes список должен перечитываться, а approve — отказать до повторного явного действия.
4. Вернуться к первому Control UI: он должен переподключиться либо после ручной перезагрузки. В DevTools проверить WSS handshake `101`, Origin/hostname и штатное сообщение Gateway. Зафиксировать отдельное отсутствие модели, если model provider в тесте не выбран.
5. Повторить для Bob. Убедиться, что Bob видит только свой экземпляр; прямой запрос к Alice hostname с Bob session получает отказ; из web/network probe запрещено прямое соединение к Gateway; Sidecar A не достигает Gateway B. Не использовать Gateway IP/URL из пользовательского запроса как target.
6. Проверить остановленный Gateway и отозванную BEZR-сессию: новые HTTP-запросы и уже открытый WebSocket должны закрываться.

## Критерий результата

Закрывать приёмку только при совокупном свидетельстве: реальные nft JSON/handles/readback совпадают без нормализации «на глаз»; Docker IPAM/routes/membership соответствуют плану; все разрешённые и отрицательные packet probes дали ожидаемый результат; два браузера открыли штатный Control UI через HTTPS/WSS и ручное pairing; Bob не получил Alice endpoint, сессию или Gateway; cleanup подтверждён по точным созданным IDs. `agent_proxy_v1` в production не включать до отдельного согласования после этого отчёта. Локальные fake-adapter тесты и успешный namespace precheck по отдельности недостаточны.
