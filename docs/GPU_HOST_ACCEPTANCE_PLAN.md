# Проект безопасной приёмки на используемом GPU-сервере

**Статус: код busy-host цепочки подключён локально; настоящая Linux/Docker приёмка НЕ выполнена. Документ остаётся проектом для согласования, не разрешением на запуск на занятом сервере.**

Исходная версия плана опиралась на `main`, HEAD `819d0d1aea7599879abbab7d3a9e90262687d83b`; описание текущей локальной доработки обновлено ниже. Конфигурация GPU-сервера повторно не обследовалась; SSH, firewall inspection, запуск Docker/nftables, обращение к Ollama и системные изменения не выполнялись.

Цель: сначала подтвердить сетевую семантику на отдельном одноразовом Linux-стенде, затем разработать и отдельно согласовать ограниченный режим приёмки на фактическом GPU-хосте. Проверка не должна изменять рабочие Docker-объекты, Ollama, действующие правила/маршруты/интерфейсы, DB, пользовательские каталоги и квоты.

## 1. Что уже есть и почему это пока нельзя запускать на занятом хосте

| Механизм | Что делает текущий код | Решение для используемого GPU-сервера |
|---|---|---|
| `activate_agent_proxy.py` → `linux_proxy_isolated_check.py` + `linux_docker_proxy_acceptance.py` | Оба checks переведены на независимую proxy-only private lab; Docker check использует отдельный daemon/socket и явный image archive; disposable оркестратор валидирует JSON evidence | Disposable opt-in не разрешает запуск на занятом хосте; для него предназначен отдельный resource-bounded entrypoint после его реальной приёмки |
| `activate_ollama_route.py` → два route checks | Уже предусмотрены private net/mount/PID namespaces, отдельный nested daemon, socket/data-root/exec-root, локальный HTTP target и cleanup | Это не готовый busy-host режим: совокупные resource/cgroup/storage границы всего запуска и отсутствие влияния на занятый хост ещё не приняты |
| `firewall-acceptance.json` | Независимая приёмка `agent_proxy_v1`, привязанная к fingerprint хоста и двум пулам | Не заменяется route receipt |
| `ollama-route-acceptance.json` | Отдельная приёмка `agent_ollama_v1`, привязанная также к Ollama endpoint, интерфейсу и Ollama pool | Не заменяет base receipt |

**Нельзя передавать `--confirm-disposable-host` на используемом сервере, переименовывать этот флаг ради обхода ограничения или считать отдельный Docker socket достаточным доказательством безопасности.** Новый `scripts/gpu_host_acceptance.py` имеет read-only `--check-config` и отдельно закрытый `--execute --approve-busy-host --allow-host-inspection`. Он связывает четыре fixed checks с transient units, strict resource proof, private packet labs и двумя candidate receipts. `supervisor/gpu-acceptance.example.json` намеренно незаполнен и отклоняется до согласования всех полей. Наличие кода не означает Linux PASS или разрешение выполнить его здесь. Конкретный приватный runbook хранится локально в игнорируемом `docs/GPU_DEPLOYMENT_PRIVATE.md`.

## 2. Этап A — воспроизведение ARP и полная packet-приёмка на отдельном стенде

1. Отдельно согласовать disposable Linux VM и её ресурсы. Создание VM на занятом GPU-сервере само по себе требует согласия; предпочтительный первый стенд — вне этого сервера. GPU passthrough и реальные модели не нужны.
2. Выполнить обе независимые приёмки с действительными Linux namespaces, Docker и nftables. Portable/fake тесты их не заменяют.
3. Для каждого разрешённого потока очистить neighbour caches после установки политики и проверить реальный полный HTTP/TCP обмен. Для каждого запрещённого потока требовать успешный контроль до и после BEZR enforcement, точный readback политики и ожидаемый отказ только при enforcement.
4. Если холодный разрешённый поток не проходит, зафиксировать причину в изолированной лаборатории. В текущем renderer добавлены узкие ARP request/reply Gateway↔router и route policy version 2; старые receipts закрыты. Это исправление проверено synthetic regressions, но реальный cold-path результат ещё не получен.
5. Если подтверждена ошибка политики, исправлять production renderer, а не тест: определить минимально необходимые ARP request/reply для точной пары Gateway↔bridge gateway; сохранить интерфейсные, адресные и межэкземплярные границы. Добавить отрицательные проверки посторонних адресов/направлений. Не добавлять безусловное разрешение всего ARP, static neighbours или прогрев для получения PASS.
6. После изменения политики проверить renderer/normalizer/readback, отрицательные regression tests и необходимость изменения policy version; старое доказательство не должно автоматически удостоверять изменённые правила. Повторить полную реальную приёмку обоих профилей.

**Receipt этой VM действителен только для неё.** Нельзя переносить его на GPU-хост, переписывать `host_id_sha256`, копировать `/etc/machine-id` GPU-хоста в VM либо выдавать GPU receipt по VM-отчёту. Успешная VM-проверка снимает вопрос семантики исследованной политики, но не является host-bound приёмкой GPU-сервера. В текущем коде host binding — SHA-256 локального `/etc/machine-id`, а не аппаратная/TPM-аттестация; доверенная граница включает администратора root и сохранение корректной уникальной идентичности хоста.

## 3. Что нужно реализовать до этапа B на GPU-хосте

Все пункты ниже — критерии допуска и реальной приёмки режима. Локально подключённый код не считается доказательством их выполнения на Linux.

- Отдельный явно разрешаемый режим для занятого хоста. Существующий disposable gate остаётся без ослабления. Нет автоматического fallback к прежним скриптам.
- Оба независимых набора проверок должны запускаться в проверяемой private лаборатории. Base Docker check адаптирован локально: обычные вызовы default Docker/context и caller `NftablesAdapter()` не допускаются.
- Отдельные net/mount/PID namespaces с FD-bound проверкой типов/идентичностей до каждой мутации, private procfs и nonshared mount propagation. Не переносить физические NIC, не подключать lab veth к host namespace, не использовать host network и не публиковать host ports. Имена интерфейсов и адреса endpoint моделируются только внутри lab.
- Все Docker CLI получают единственный явный private socket. Не наследовать рабочие `DOCKER_HOST`, context, CLI/daemon config, proxy settings, containerd socket, plugins и runtime/CDI configuration. Не монтировать production Docker socket, `/var/lib/docker` или рабочие каталоги.
- Ограничить **весь запуск**, включая wrapper, dockerd, containerd, контейнеры, HTTP-серверы и потомков: CPU, RAM, swap, PIDs, I/O, диск/inodes и общее время. Проверять принадлежность всех процессов разрешённому subtree; контейнерных `--memory/--pids-limit` недостаточно для этого проектного требования. Если нужная делегация/контроллеры недоступны — BLOCKED, без перестройки host cgroups или перезапуска сервисов.
- Разрешены только заранее согласованные test workspace и cgroup subtree. Никакого переназначения существующих XFS project IDs, изменения mount/fstab, сброса квот или уборки старых данных. Если storage bound нельзя обеспечить без отдельной настройки, запуск блокируется.
- Никаких запросов к настоящему Ollama и GPU: только nonce-bound HTTP listener в lab, без inference, загрузки моделей, `/dev/nvidia*`, GPU passthrough и GPU runtime. Нужен проверяемый запрет доступа к GPU devices, а не только отсутствие `--gpus` в argv.
- Только заранее предоставленный проверенный image archive и immutable image ID. Никаких pulls, установок, daemon restart, глобальных sysctl, загрузки/выгрузки kernel modules, изменения host forwarding/firewall backend или AppArmor/SELinux профилей. Недостающая предпосылка означает BLOCKED.
- Ограниченные stdin/stdout и общий deadline; scoped process cleanup, проверенные SIGTERM/timeout/cancellation пути. SIGKILL внешнего владельца может оставить workspace: это FAIL/no receipt, а не обещание полного автоматического удаления.
- Cleanup работает только с захваченными exact IDs, inode/namespace identities и собственными путями. Не использовать name-based удаление, `prune`, `compose down -v` или глобальный ruleset flush.

### Отдельное условие: host-local или routed Ollama

Для deployment определить фактическую топологию: Ollama IP принадлежит самому Docker-хосту или это routed destination. Route lab теперь последовательно проверяет оба варианта: veth-routed endpoint и тот же exact endpoint на loopback router namespace с readback фактического local route. В production renderer существуют отдельные host-local `inet input/output` allowances. Настоящий host-local packet PASS ещё не получен; нельзя считать synthetic evidence или routed-only результат его заменой.

Матрица и отчёт должны явно подтверждать выбранный вариант, включая cold-neighbour и отрицательные проверки. Если нужный вариант не покрыт — BLOCKED. Если для фиксации режима нужны новые поля отчёта/receipt, версии и строгие loaders меняются явно с негативными тестами, а не обходом текущей схемы.

## 4. Отдельно согласуемая последовательность этапа B

### G0 — разрешение и готовность кода

- Указаны commit, согласованный scope, точные пути, ресурсы, тестовый image, endpoint/interface/pools и выбранная топология.
- Завершены source review и реальные испытания будущего режима на disposable clone, включая timeout/cancellation/неполный cleanup. Это не заменяет последующий GPU-host run.
- Владелец подтверждает допустимый остаточный риск общего ядра и ресурсной нагрузки. Гарантия «нулевого влияния на latency и нулевого риска» не даётся. Если требуется именно такая гарантия, совместный запуск не разрешается; остаётся отдельный стенд без GPU-host receipt.
- Разрешение на разработку/документирование не считается разрешением на серверные действия. Текущий запрет firewall inspection сохраняется.

### G1 — отдельно разрешённый read-only preflight

- Получить только согласованный allowlist сведений: host fingerprint, версии/возможности runtime и kernel, namespaces/mounts, доступные resource controllers, site binding и разрешённый storage.
- Для подтверждения неизменности production отдельно согласовать минимальный baseline Docker-идентичностей/сетей, PID/start-time сервисов и структуры host firewall/routes. Firewall inspection не выполнять без нового явного разрешения. Если проверку условия «не изменили host rules» нельзя обеспечить разрешённым способом, это BLOCKED, не доказательство по умолчанию.
- Не собирать полные Docker inspect/ENV, secrets, содержимое DB или моделей. Не обращаться к Ollama API. Использовать согласованный allowlist либо сведения, предоставленные владельцем; неподтверждённые условия отмечать неизвестными.
- Запретить изменения production network/firewall конфигурации другими администраторами на согласованное окно, не останавливая работающие сервисы. Если обеспечить стабильность нельзя, receipt не выдаётся.
- Сравнивать структуру firewall, а не слепой hash счётчиков: обычный рост packet/byte counters не равен изменению правил. Нормализация не должна скрывать изменение match/action, порядка, hooks, priorities, policies и состава объектов.

### G2 — создание ограниченной lab и проверки

- Создать только разрешённые новые workspace/cgroup и private namespace объекты; журналировать точные identities до запуска daemon.
- До любых сетевых мутаций подтвердить границы из раздела 3. Ни один private daemon не стартует до ресурсного containment.
- Запустить обе независимые матрицы с production renderer/readback, реальными controls и выбранной топологией. Исключение/тайм-аут/несовпадение/неполный report означает FAIL. Запретить fake/supplied reports, skip flags и повторное использование результатов предыдущего run.
- Сбой одной матрицы запрещает выдачу обоих новых candidate receipts этого запуска. Маршрут и production profile не активировать.

### G3 — teardown и подтверждение неизменности

- Удалить только принадлежащие run объекты; доказать завершение daemon, containerd, контейнеров и остальных потомков. Проверить отсутствие owned links/tables/networks, освобождение workspace и разрешённого cgroup subtree.
- Сверить разрешённые production baselines. Изменение идентичности/состояния рабочих объектов, неполные данные или cleanup error означают FAIL/no receipt.
- **Не восстанавливать весь host ruleset из snapshot автоматически:** это может затереть легитимные изменения. Не перезапускать рабочие сервисы ради возврата baseline. При неожиданном host drift — остановиться, сохранить минимальный отчёт и передать владельцу; отдельное исправление требует отдельного разрешения.
- При оставшемся workspace указать только точный захваченный путь и причину. Не выполнять blind cleanup.

### G4 — candidate receipts, без активации

- Только после G2+G3 PASS сформировать два отдельных candidate receipts в новом согласованном root-controlled каталоге, не перезаписывая рабочие receipt/state/DB.
- Host identity получает внешний процесс на фактическом GPU-хосте штатным `machine_id_sha256()` и перепроверяет после teardown. Не разрешать переданный пользователем host digest или remote-report-to-receipt conversion.
- Проверить каждый candidate своим строгим production loader и exact binding. Не выдавать base receipt на основании одного route report, даже если route lab дополнительно проверяла proxy rules.
- Сохранить рядом минимальный проверяемый отчёт: commit, режим/топология, фактические версии, image ID, policy binding, результаты обоих наборов, identities lab, cleanup и разрешённое сравнение baseline. Это отчёт о выполненном запуске, не фиктивный заполненный шаблон.
- Перенос candidate receipts в рабочий state-dir и активация — отдельный план и отдельное согласие. Частичный перенос не считается готовностью. Ничего не переключать в ходе этой процедуры.

## 5. Незаданные параметры согласования

| Параметр | Текущее состояние |
|---|---|
| Конкретный хост и отдельное окно запуска | Не заданы |
| Разрешение read-only preflight, включая/исключая firewall inspection | Не получено |
| Допустимость временного test cgroup/workspace и точные пути | Не согласована |
| CPU/RAM/swap/PIDs/I/O/disk/inodes/time limits и минимальный резерв хосту | Не заданы; не выбирать по умолчанию |
| Согласованный порядок действий при resource pressure и пороги остановки | Не задан |
| Agent/frontend/Ollama pools, endpoint, interface, host-local/routed | Не подтверждены для GPU-хоста |
| Image archive и immutable image ID | Не предоставлены для этой процедуры |
| Root-controlled candidate receipt directory | Не согласован |
| Ответственный за run/аварийную остановку и разрешённые baseline данные | Не заданы |
| Код и приёмка busy-host режима | Цепочка подключена локально; реальные Linux, systemd/resource и packet checks не выполнены |

До закрытия этих условий итог **BLOCKED**. Согласование проекта процедуры не означает разрешения «запустить всё»; разрешения на preflight, временные системные объекты, испытания и публикацию candidate receipts должны быть явными и ограниченными.

## 6. Границы результата

Даже успешная isolated packet-приёмка на фактическом хосте не подтверждает доступность настоящего Ollama из production namespace, прохождение реального production NIC/upstream firewall, enforcement JSON `model`/HTTP paths, GPU/VRAM, inference или полный OpenClaw tool execution cycle. Это отдельные проверки и разрешения; L3/L4 receipt не является доказательством L7-модельной политики.

Реальный Linux/systemd reboot, XFS/immutable/purge acceptance также не закрываются этим документом. Рабочие данные для purge не используются.

## Основание по коду проекта

- `scripts/activate_agent_proxy.py`: `main()`, `_run_check()` — два base checks и запись host-bound receipt.
- `scripts/linux_docker_proxy_acceptance.py`: публичный disposable wrapper независимой private proxy lab; прежние caller-Docker helpers удалены. Busy-host вход — `scripts/gpu_host_acceptance.py`, transport — `scripts/gpu_acceptance_job.py`, containment — `scripts/acceptance_busy_host.py`.
- `scripts/ollama_route_linux.py`: `validate_lab_boundary()`, `daemon_argv()`, `Lab.guard()`, `Lab.exercise()` — существующие private-lab механизмы, но не доказанный busy-host режим.
- `scripts/activate_ollama_route.py` — независимая route orchestration.
- `supervisor/firewall_acceptance.py` и `supervisor/ollama_firewall.py` — строгие host/config bindings и отдельные loaders; `expected_ollama_ruleset()` содержит routed и host-local ветки, а также текущие bridge drops.
- `docs/OLLAMA_ROUTE_ACCEPTANCE.md` — disposable-only инструкции и непройденная реальная cold-path приёмка.

Это проектные условия безопасности и приёмки, не внешние нормативные требования и не протокол уже выполненных испытаний.
