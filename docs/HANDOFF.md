# Передача проекта в новую сессию

## 1. Главная задача и статус

Базовый сценарий host-runtime из кабинета **пройден на лабораторной Linux-ВМ по отчёту пользователя** для commit `4494d7575b0c7534076684e6d8547477b527a42f`: настоящий OpenClaw → running/healthy → stop/start/restart → remove-retain → новое создание. Текущая локальная ветка содержит последующие изменения; они не развёрнуты и не приняты на ВМ, поэтому текущую стадию 3 не считать закрытой.

Базовый сценарий из пользовательского отчёта принят для той версии. Не объявлять доказанными EDQUOT, прямую owner isolation на ВМ, конкуренцию, recovery supervisor или общую невозможность обхода ограничений. Текущая локальная версия требует отдельной приёмки; актуальные границы и следующий шаг — `docs/ROADMAP.md` и `docs/verification.md`.

## 2. Где находится проект

- Локальный корень: `C:/Users/SystemX/Downloads/Диплом/Практика/Вебчик`.
- Текущая локальная ветка `main`, HEAD **`e3533e99b36ac9265426c36f1ee2b3c9f14303cf`**, с незакоммиченными исправлениями purge. Локальный ref `origin/main` не проверялся заново; сеть не опрашивалась. Пользовательский VM-отчёт относится к более раннему `4494d7575b0c7534076684e6d8547477b527a42f`.
- Пользовательский отчёт заявляет проверку этого commit на ВМ. Сопоставить отчёт и локальный код; не переносить лабораторные параметры на другой стенд.
- После получения отчёта актуализируются документы приёмки/roadmap. Проверить текущий `git status/diff`; не публиковать без отдельного разрешения.
- Доставка согласована: локальный проект → GitHub после разрешения → clone/build на ВМ. На основном Windows-хосте Docker отсутствует; развёртывание туда не переносить.

В начале новой сессии сверить текущий Git и изменения пользователя. Checkpoint здесь — справка, не требование откатить проект к старому состоянию.

## 3. Замысел и уже принятые решения

Тема диплома: «Разработка прототипа среды функционирования программного обеспечения, использующего технологии искусственного интеллекта, с учетом требований ИБ».

Практика: открытая регистрация Open WebUI, персональный OpenClaw на владельца, раздельные данные и управление через кабинет. Пользователь и агент не получают Docker API, управляющие credentials или возможность ослаблять обязательные ограничения. В дальнейшем — общая модель на сервере и собственный Telegram-бот пользователя.

Основные решения:

- Первый Open WebUI аккаунт — admin, последующие — user; регистрация без ручного одобрения.
- Один не удалённый экземпляр на владельца, включая остановленный.
- Порог RAM/средней CPU **50% — единое правило проекта**. В `final` отказ, в `lab` — `would_deny`. Не превращать его в произвольный пользовательский/host override и не распространять автоматически на диск.
- Метрики CPU: окно 60 секунд, свежесть 10 секунд; swap не добавляется в физическую RAM.
- Обычный `remove` сохраняет данные. Явный owner-scoped `purge` и повторяемая очистка реализованы в текущей локальной копии и прошли fake-backend проверки; на ВМ не проверялись. Автоматической очистки нет. Retained storage не подключается к новому экземпляру.
- Модели пока нет. Работа контейнера не означает работающий LLM-чат.
- Не объявлять проект соответствующим КИИ/ГИС/ИСПДН: нормативные идеи адаптируются, применимость отдельно обосновывается.

## 4. Что уже принято на ВМ

1. Веб-базис: регистрация, вход/выход, сохранение настроек, разделение двух аккаунтов, отказ API без токена.
2. Отдельный лабораторный OpenClaw без модели: реальный запуск, health/readiness, token auth/pairing, сохранение данных после пересоздания.
3. Предшествующие config/coordinator-срезы: пользователь предоставил Linux-результаты, в том числе 57 supervisor / 15 lab/storage OK и ожидаемый отказ синтетического create при неподтверждённой квоте.
4. Новый runtime по пользовательскому отчёту: настоящий create из `/agent`, running/healthy, stop/start/restart, проверенные Docker security settings, XFS project ID/quota assignment/readback и remove-retain с последующим новым create. Отчёт не подтверждает EDQUOT.
5. Подготовленный пользователем XFS-том с project Accounting/Enforcement ON. Старое root ext4 discovery завершено; возвращаться к подготовке ext4 не нужно.

Подробные свидетельства, точный commit и ограничения — `docs/verification.md`; лабораторные storage параметры — `docs/VM_STORAGE.md`.

## 5. Лабораторные параметры — НЕ defaults конечного стенда

Только для текущей ВМ:

- XFS `/dev/sdb1`, mountpoint `/srv/agent-data`, 50 GiB.
- UUID `f187448b-d3e6-4838-b7c1-893b34886010`.
- Project Accounting/Enforcement ON; fstab подготовлен пользователем.
- Локальный профиль `lab-v1`, `mode=lab`: RAM `2147483648`, CPU `1000` millicores, PIDs `256`, disk **`10737418240` bytes (10 GiB)**.
- Лабораторный образ: `openclaw-stage2:7c12438929e5`; helper должен получить ID реально имеющегося локального образа, а не считать tag неизменяемым.
- OpenClaw baseline commit `7c12438929e5d198616fe8f602d896e011647d39`; Open WebUI `v0.12.5`, точный base image закреплён в Dockerfile/lock.

Конечный стенд будет **на другой машине**. UUID, устройства, пути, ёмкости и бюджеты определяются заново. Исторический ресурсный снимок ВМ не является текущим измерением.

В `docs/SUPERVISOR_RUN.md` приведено предложение общих бюджетов 4 GiB RAM / 4 CPU / 40 GiB disk и floor 1 GiB. **Это не ранее согласованные значения и не применённая настройка.** Оператор должен учесть ОС, веб, оставшийся stage2 Gateway и будущую модель. Старый Gateway автоматически не остановлен и не мигрирован.

## 6. Текущая архитектура и карта кода

```text
Браузер /agent
  → Open WebUI: upstream human JWT + owner-scoped API
  → SupervisorClient: приватный AF_UNIX + отдельный service bearer
  → root Linux supervisor
      → RuntimeStore: intents, бюджеты, snapshot, replay
      → /proc + statvfs metrics
      → XfsVolumes: project ID, inheritance, block/inode hard limits
      → DockerEngine: create/start/stop/restart/remove + фактический inspect
```

| Файлы | Назначение |
| --- | --- |
| `control_plane/api.py`, `openwebui.py` | Проверенный upstream actor, draft/revision, lifecycle bridge. Клиент не задаёт actor/image/mounts. |
| `control_plane/runtime.py` | Ограниченный приватный клиент; credential только на backend, allowlist ответа. |
| `web/agent/app.js`, `ui-state.mjs`, `index.html` | Кнопки lifecycle, retained datasets, явный purge, состояние и восстановление pending operations. |
| `supervisor/service.py` | Root Linux service; `/v1/me`, `/v1/actions`, `/v1/replay`; явный запуск с `--enable-host-runtime`. |
| `supervisor/runtime_store.py` | Новый durable runtime-журнал: owner slot, бюджеты, неизменяемые snapshots, tombstones/retained disk. |
| `supervisor/metrics.py` | Фоновый сбор /proc/stat, MemTotal/MemAvailable, statvfs, прогрев CPU 60 секунд. |
| `supervisor/volumes.py` | XFS prepare/verify и явный retryable purge journaled tree; private state DB, project IDs, дерево/лимиты. Purge пока не принимался на ВМ. |
| `supervisor/docker_engine.py` | Stdlib Docker HTTP Unix socket, API v1.45, immutable local image, проверка фактического контейнера. |
| `supervisor/seccomp.json`, `SECCOMP_SOURCE.md`, `MOBY_LICENSE`, `MOBY_NOTICE` | Default-deny профиль на базе закреплённого Moby с ограничением ioctl и альтернативных quota setters. |
| `supervisor/config.py`, `policy.py`, `storage.py`, `probes.py` | Профиль, ресурсная политика, read-only backend preflight, bounded subprocess. |
| `supervisor/registry.py`, `coordinator.py` | Предшествующее библиотечное ядро. Новый сервис использует RuntimeStore, а не неявно мигрированные старые reservations. |
| `scripts/configure_supervisor.py` | Явная подготовка root-owned deployment/runtime JSON, фиксация локального image ID. Не запускает службу и не назначает квоты. |
| `compose.supervisor.yaml` | Opt-in bridge: socket directory + credential read-only. **Без Docker socket в вебе.** |
| `scripts/smoke_runtime.py` | Один локальный сквозной сценарий с настоящими HTTP/SQLite и fake Docker/XFS/metrics, включая retry/replay purge retained-набора. |

Базовый `compose.yaml` остаётся web-only. Без opt-in bridge API честно возвращает runtime_not_connected.

### Важные границы реализации

- Intent сначала атомарно резервирует слот/ресурсы и разрешает **только подготовку storage**. Для этого допускается отсутствие единственного признака `disk_quota_verified`; это не разрешение создавать/запускать контейнер.
- После реального назначения и readback персональной квоты выполняется полный свежий admission. Общие Accounting/Enforcement ON или валидный JSON не равны персональной квоте.
- RuntimeStore фиксирует полный профиль для своего журнала. Не удалять DB ради смены binding; автоматическая миграция профиля не реализована.
- Retained disk остаётся в бюджете после удаления. RAM/CPU освобождаются после подтверждённого remove.
- Контейнер: UID/GID 1000, readonly rootfs, cap_drop ALL, no-new-privileges, RAM/CPU/PIDs, bounded tmpfs, logging none, **network none**. Две bind-привязки state/secrets внутри одного XFS проекта.
- Disk limit должен делиться на 1024; inode hard limit — технический `max(1024, disk_bytes//4096)`, не пользовательская настройка.
- Одного cap_drop недостаточно для project inheritance: seccomp ограничивает filesystem ioctl/setattr и альтернативные пути. Точечный tini ioctl regression на ВМ пройден по пользовательскому отчёту; полный security audit не выполнен.
- `initialize_files` использует принятый lab bootstrap: gateway local/lan, token auth, loopback controlUi.allowedOrigins. Subsequent draft saves пока не применяются к уже созданному агенту.
- Root-owned административный snapshot нужен вне user-writable checkout. Служба проверяет владельца/предков; напрямую подставлять старый user-owned deployment.local.json в runtime config нельзя.

## 7. Что действительно проверено, а что нет

### Подтверждено

- Пользователь сообщил о ВМ-приёмке настоящего OpenClaw на commit `4494d7575b0c7534076684e6d8547477b527a42f`: create из кабинета, running/healthy, stop/start/restart, remove-retain, новая instance после remove; 73 supervisor tests OK. Ограничения отчёта — `docs/verification.md`.
- Локально после последних исправлений прошёл `scripts/smoke_runtime.py`: настоящий HTTP/SQLite, fake Docker/XFS/metrics; lifecycle, replay после смены draft, отказ новому stale request, pending-create recovery по исходному snapshot, owner split, paused/restarting, remove-retain, новое создание, owner-scoped purge, отказ чужому владельцу, retry после синтетического сбоя и exact replay.
- Локально прошли `supervisor.tests.test_runtime_service` (6 тестов), `tests.test_api` (8), `node --check web/agent/app.js`, 4 UI state tests, `compileall` и `git diff --check`. Для XFS purge database-mode теста использован реальный временный SQLite-файл; quota/xattrs и Linux dirfd syscalls имитированы. Браузерный end-to-end, настоящий AF_UNIX, Docker/OpenClaw или XFS не проверены.
- Временный HTTP server и SQLite из smoke удалены; пользовательские VM-данные не затрагивались.

### Последнее независимое ручное ревью и внесённые после него правки

Ревью не дало финального одобрения: найдены три ошибки. Затем код изменён:

1. Старый create-key после удаления: клиент отслеживает поколение экземпляра, сбрасывает старые ключи только при достоверной смене/удалении, не при unavailable. Есть memory fallback без sessionStorage и обработка instance_retired.
2. Replay при новом черновике: приватный `/v1/replay` загружает сохранённый **owner-scoped** request до проверки текущего draft. Новый неизвестный stale-запрос всё равно отклоняется. Браузеру не возвращается содержимое старого settings snapshot.
3. Восстановление из другой вкладки/после смены draft: service сообщает владельцу `pending_create_key` / `pending_create_revision`, кабинет предлагает «Продолжить создание» по исходному snapshot.
4. `paused` / `restarting` больше не подменяются `failed`; Docker adapter обрабатывает unpause внутри авторизованного lifecycle, reconciliation может проверять квоту этих состояний.

Эти исправления исполнены в локальном обновлённом smoke; их backend-путь прошёл fake-adapter HTTP/SQLite сценарий. Реальный браузерный JS-generation и настоящий Docker/XFS/AF_UNIX этим не подтверждены. Пользовательский ВМ-отчёт подтверждает реальный happy path для commit `4494d7575b0c7534076684e6d8547477b527a42f`, но не перечисленные ниже негативные проверки.

### Дополнительные исправления purge в локальном checkout

- `XfsVolumes.purge` теперь открывает существующую SQLite на запись через отдельный `mode=rw` без создания базы; обычный verify остаётся `mode=ro`. Тест использует настоящий временный SQLite-файл и проверяет, что отсутствующая БД не создаётся.
- Рекурсивное удаление на Linux использует directory descriptors, `O_NOFOLLOW`, inode/device и mount-ID checks; синтетический тест проверяет запрет обхода при подмене каталога. Реальные Linux dirfd/XFS syscall ещё не исполнены на этом Windows-хосте.
- Перед освобождением RuntimeStore disk reservation очищаются runtime settings, gateway token и payload всех операций экземпляра (create/start/stop/restart/remove/purge); остаётся только минимальная replay-запись. WAL checkpoint обязателен, иначе reservation сохраняется и retry восстанавливается по метаданным purge. Draft в пользовательском кабинете намеренно остаётся.
- Локальные unit/HTTP-smoke проходят с fake quota/xattrs; это не проверка настоящего XFS, физического forensic erase или VM rollout.

### Не выполнено / не подтверждено

- EDQUOT при достижении hard limit настоящим экземпляром; report confirms quota assignment/readback, not rejection of writes.
- Пользовательский ВМ-отчёт проверял второго владельца только в UI; локальный fake HTTP/SQLite smoke проверил отказ чужому purge до storage. Другие direct cross-owner операции на настоящей ВМ не проверялись.
- Конкурентный lifecycle/create и supervisor restart/recovery while managed instance exists; service autostart after reboot.
- Owner-scoped purge retained tree, SQLite write-mode regression, partial-tree retry, WAL-scrub checkpoint/replay и оставление резерва при сбое прошли локальные synthetic/temp-file checks. Реальный XFS/Docker, cleanup частично подготовленного failed-create storage и ВМ-приёмка не подтверждены; retained storage reattachment не реализовано.
- Реальный browser end-to-end для operation-key generation/recovery; локальные JS syntax/UI-state checks не заменяют его.
- Gateway/browser integration, application of changed draft, LLM/chat, Telegram.
- Перенос на другую машину и полный security audit.


## 8. Разрешения и известные блокировки

Пользователь предоставил отчёт о запуске настоящего OpenClaw на ВМ. Это разрешает учитывать эти результаты как пользовательские свидетельства, но не разрешает повторные изменения ВМ, установку, SSH, публикацию, назначение квот или изменение/удаление данных.

Локальный `hermes verify --json` запускался после seccomp change и остановился на `docker compose build`, поскольку Docker CLI недоступен на Windows. Не запускать повторно без изменения предпосылки. Локальный smoke и целевые проверки проходили отдельно и не заменяют Compose/VM.

Подтверждённый rollout sequence разрешил потенциальное противоречие: old supervisor удалил старый контейнер retain и SQLite зафиксировала `(0, 'removed')` до остановки старой службы и запуска `4494d757`; новый контейнер создавался уже после. Это не подтверждает обновление поверх активного контейнера со старым seccomp; не очищать DB/данные ради такого сценария.

Не устанавливать зависимости, не публиковать, не подключаться по SSH, не выполнять privileged setup/start, не менять fstab/mount/ФС/квоты и не удалять/мигрировать данные без конкретного отдельного согласия. Секреты и локальные credentials не читать/печатать без необходимости.


## 9. Следующие действия — короткий маршрут

1. Пользователь подтвердил sequence rollout: old container удалён retain, DB показала inactive/removed до остановки старого supervisor и запуска нового. Это не означает поддержку active old-seccomp adoption; сохранять эту границу.
2. Базовый VM-сценарий для `4494d757` принят пользователем; не менять его действующие данные. Текущие локальные изменения после этой версии на ВМ не проверены.
3. Локально исправлен owner-scoped `purge`: writable-no-create storage SQLite, descriptor-relative traversal, runtime snapshot/token и все instance operation payloads scrub-ятся до освобождения резерва. Retry после scrub-checkpoint failure сохраняет минимальный purge metadata/key. Targeted HTTP/SQLite smoke и runtime tests прошли; quota/xattrs и Linux FD syscalls остаются имитацией. Не запускать purge на ВМ или действующих данных.
4. Следующий шаг — короткая приёмка текущего кода на Linux-ВМ по `docs/SUPERVISOR_RUN.md`, только после отдельного согласия на публикацию/доставку и привилегированный запуск. Обычная приёмка ограничивается create/lifecycle/remove-retain; purge/EDQUOT — отдельная изолированная проверка с отдельным согласием.

Это рекомендуемый порядок, не разрешение на кодовую миграцию, публикацию, SSH, privileged setup, квоты, системные изменения или удаление данных. Работать в локальной копии, сохраняя пользовательские изменения.


## 10. Что читать дальше

- `docs/SUPERVISOR_RUN.md` — текущие команды и короткая приёмка.
- `docs/DEPLOYMENT_CONFIG.md` — разделение профиля машины, политики и runtime config.
- `docs/VM_STORAGE.md` — лабораторные свидетельства, не универсальные defaults.
- `docs/STAGE3_CONTRACT.md` — контракт, исходные библиотеки и новая runtime-связка.
- `docs/ROADMAP.md` — план и история; отдельные старые пункты описывают прежний library-only snapshot, при расхождении сверять код и новые разделы.
- Материалы диплома при необходимости: `C:/Users/SystemX/Мой диск/Диплом`. Их исходники в этой задаче не изменялись.
