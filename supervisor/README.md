# Ядро supervisor — отдельные модули стадии 3

## Сквозной runtime

Добавлены `service.py`, `runtime_store.py`, `metrics.py`, `volumes.py` и `docker_engine.py`: отдельная привилегированная Linux-служба с приватным AF_UNIX API, staged storage intents, персональными XFS quotas и реальным Docker lifecycle. Кабинет подключается через `control_plane/runtime.py` и `compose.supervisor.yaml`, без Docker socket в вебе. Модель/чат/Telegram пока не подключены; сеть runtime — none. Seccomp сохраняет default-deny и блокирует изменение project inheritance.

Запуск с явным согласием на изменения ВМ — `docs/SUPERVISOR_RUN.md`. Подтверждён локальный сквозной HTTP/SQLite сценарий с явно fake Docker/XFS/метриками (`scripts/smoke_runtime.py`); реальный новый runtime на ВМ ещё не принят. Это не объявление завершённой Docker/XFS-верификации.

## Предшествующее библиотечное ядро

Ниже описаны исходные policy/Registry/CreateCoordinator. Они сохранены как библиотечные компоненты, но работающий service использует отдельный RuntimeStore со стадиями подготовки и retained-data бюджетом. Новых Python-пакетов для host-service не требуется. Старый лабораторный Gateway не мигрируется и не усыновляется автоматически.

## Реально реализованные политики

Перенос на другую машину: см. `docs/DEPLOYMENT_CONFIG.md`. UUID, устройства и пути из `docs/VM_STORAGE.md` относятся только к лабораторной ВМ. Загрузчик `config.load_profile(path)` уже реализован: он читает явно заданный административный JSON-профиль версии 1 и возвращает неизменяемые settings без подстановки лабораторной идентичности. Шаблон — `supervisor/deployment.example.json`, локальная копия — игнорируемая `supervisor/deployment.local.json`. UUID, mountpoint и дисковый лимит в шаблоне не заполнены намеренно; без них профиль отклоняется.

Read-only проверка файла: `python -m supervisor.config --check supervisor/deployment.local.json`. Exit 0 означает корректность профиля, **не** mount/quota readiness; exit 2 — отказ. Проверены реальное чтение файла, строгие типы/границы, неизвестные поля, дубли JSON, лимит 65536 байт и CLI в отдельном Python-процессе. `disk_quota_verified`, actor, image и произвольный порог задавать в JSON нельзя. Профиль уже использует библиотечный `CreateCoordinator`, но не работающий веб/Docker. CPU candidate/capacity в этой связке заданы в millicores. Подробности и оставшиеся проверки — в руководстве конфигурации.

`policy.validate_create(payload)` принимает только:

```json
{"action":"create","idempotency_key":"client-request-01","settings_revision":0}
```

Это пример формы запроса, не ответ настоящего runtime. Результат — неизменяемый объект; неизвестные поля, user/owner/image/mounts/privileges/Gateway URL, некорректный key и revision отклоняются. Actor определяется будущим серверным auth-слоем, не этой функцией.

`policy.evaluate_admission(...)` — чистая функция оценки переданной сервером информации, не сборщик метрик и не транзакционное выделение ресурсов:

- `final`: занятость RAM или CPU от 50% запрещает допуск;
- `lab`: те же пороги возвращаются в `would_deny`, сами по себе не блокируют;
- в обоих режимах устаревшие/будущие метрики, неполное CPU-окно, физический недостаток RAM/диска и отсутствие проверенной hard quota не разрешают допуск;
- окно CPU 60 секунд и свежесть 10 секунд — стартовая реализация технического предложения контракта, не результат замеров оптимальных параметров на ВМ;
- malformed inputs, NaN/Infinity, bool вместо чисел и выход за диапазоны отклоняются.

Порог **50% — выбранное пользователем общее правило проекта**, а не переносимое из ВМ числовое измерение и не пользовательская настройка. При смене машины его не пересчитывают и не выносят в произвольный `.env` override. Действующее различие `lab`/`final` выше сохранено без изменения поведения. Окно 60 секунд и свежесть 10 секунд — технические параметры текущей политики, не характеристики оборудования; централизованную версионированную настройку этих технических параметров ещё предстоит добавить в coordinator, не переписывая сейчас алгоритм ради удаления констант.

Аргументы `now`/`sampled_at` должны использовать одну часовую шкалу, выбираемую доверенным сборщиком. `cpu_percent` — агрегированная средняя загрузка всей ВМ, не сумма процентов ядер. RAM передаётся как точные байты MemTotal/MemAvailable; swap не добавляется в физический бюджет.

`disk_quota_verified` может выставляться только будущим доверенным storage backend по реально подтверждённому ограничению нужного набора данных. Наличие feature project/quota в ext4 или Accounting/Enforcement ON у XFS не подтверждает назначение нужной квоты конкретному экземпляру. Браузер не задаёт этот флаг, измерения, профиль или бюджеты. Отдельный лабораторный тест малого проекта также не делает все будущие хранилища автоматически verified; нельзя включать флаг ради зелёного результата.

Функция требует свободного диска под кандидат и явно переданный свободный остаток; выбор disk floor не утверждён этим кодом. Это отдельный guard, а не создание/резерв места на ФС. Суммарные бюджеты платформы, модели и уже зарезервированных агентов должны обрабатываться транзакционно в доверенном coordinator/registry, не только этой функцией.

## Реестр операций — отдельная часть текущей реализации

`registry.Registry(path)` реализует атомарное резервирование одного слота на владельца и суммарных RAM/CPU/disk бюджетов через SQLite `BEGIN IMMEDIATE`. Повтор семантически того же запроса с тем же owner/key возвращает прежнюю операцию, изменённый запрос конфликтует. Getter проверяет принадлежность объекта. Проверены реальные временные SQLite, сохранение после повторного открытия, rollback и гонки потоков. Его состояние reserved/queued означает только запись намерения: контейнера и работающего агента ещё нет.

Метод `reserve_create` принимает actor, versioned profile и ресурсы кандидата. Старый интерфейс со статическими capacities сохранён; новый coordinator передаёт только trusted `admit` callback. Callback вызывается после BEGIN IMMEDIATE/replay/owner-slot checks и возвращает типизированные общие потолки `ReservationCapacity`; смешивать его со статическими capacities нельзя. Все резервы суммируются внутри той же транзакции. Путь БД задаётся сервером, родительский каталог должен уже существовать.

## Coordinator: конфигурация → допуск → атомарный резерв

`CreateCoordinator(registry, profile, observe, clock)` реализован в `supervisor/coordinator.py`. Метод `create(actor_id, payload, current_settings_revision=...)` валидирует закрытый create contract, использует только ресурсы серверного профиля и возвращает immutable `CreateResult`: operation/instance IDs, status queued, replay marker и Admission (либо None для точного повтора). Actor и текущая ревизия приходят от доверенной службы, не из JSON; служебная аутентификация ещё отсутствует.

Новый запрос проверяет ревизию и snapshot **внутри SQLite-транзакции после получения writer lock**. `observe` должен быстро читать доверенный cache, не собирать CPU 60 секунд или вызывать команды/сеть под блокировкой. Freshness/physical capacity/quota guards и порог 50% сохранены; общие budget ceilings не могут превышать reported physical totals. Нет автоматических VM/default capacities, provider фактического хоста ещё не реализован.

Версия профиля привязана в `deployment_profiles` к SHA256 полного валидированного профиля, включая PIDs, режим и storage identity. Новая таблица добавляется при открытии Registry без удаления прежних записей. Нельзя менять содержание под уже использованной версией или обходить binding вызовом без fingerprint. Старые reservations без истории не объявляются соответствующими новой конфигурации; для новой привязки нужна новая версия. Полные исторические профили для будущего executor пока не хранятся.

Повтор того же owner/key/payload/profile возвращает прежнюю операцию даже при изменившейся draft revision/недоступных текущих метриках; это чтение уже принятого намерения, не новое разрешение запуска. Сбой/отказ не оставляет частичный instance/operation/profile binding. Настоящий executor обязан повторно проверить admission и точные settings/profile перед эффектами: проверка перед резервом не блокирует отдельную DraftStore БД и не доказывает readiness runtime.

20 новых тестов проверяют реальный SQLite lock, отказы/rollback (включая trigger-induced INSERT failure), profile drift/legacy history, границу свежести 10 секунд и гонки 4 потоков. Метрики/quota evidence в этих тестах синтетические. Работающий XFS и успешный config check сами не дают `disk_quota_verified=True` настоящему агенту.

В предшествующем библиотечном Registry нет executor, изменения статусов, освобождения резервов или удаления: его записи продолжают занимать слот и бюджет. Новый host-service использует отдельный RuntimeStore; это не миграция старых reservations. Не использовать один библиотечный Registry как готовый управляющий сервис. Подключение этих операций требует отдельного recovery/reconciliation-контракта, а не удаления строк вручную.

Реестр/coordinator не являются сервисной аутентификацией. До подключения API необходимо завершить доверенный канал web → supervisor, авторизацию actor, реальные host/quota providers, recovery/reconciliation и проверяемый Docker executor. Не открывать библиотечные методы браузеру напрямую и не включать публичный provisioning по успеху unit-тестов.

## Read-only preflight XFS

`supervisor/storage.py` проверяет подготовленный backend по административному профилю: канонический путь, точный mountpoint, XFS/UUID/корень ФС, rw и project quota mount options, Accounting/Enforcement ON. После чтения quota state mount проверяется повторно; смена метаданных блокирует результат. Это снимок, не устранение всех TOCTOU-гонок будущего provisioning.

CLI на Linux-ВМ: `sudo python3 -m supervisor.storage --check supervisor/deployment.local.json`. JSON `status=backend_ready` и exit 0 означают только успешный backend preflight; `status=blocked` и exit 2 — отказ. **disk_quota_verified всегда false**, включая успешный preflight: персональные project ID/hard limits не назначаются и не проверяются. Не переносить backend_ready в admission как доказательство квоты экземпляра.

`supervisor/probes.py` запускает фиксированные команды вызывающего кода без shell, с LC_ALL=C, ограниченным чтением stdout и timeout; stderr не публикуется. Сам runner не является sandbox для произвольных argv. Нет форматирования, mount/remount, назначения квот, Docker или fallback. Подробности и конечный список VM-проверок — `docs/STORAGE_PREFLIGHT.md`.

## Проверки

Из корня проекта:

```bash
python -m unittest discover -s supervisor/tests -v
python -m unittest discover -s lab/storage/tests -v
```

Тестовые метрики, профили и JSON-фикстуры — синтетические входы unit-тестов, не сведения о ВМ и не результат исполнения Docker. Временные SQLite создаются только внутри тестов. Никакие `.env` или реальные credentials для тестов не нужны.

Свежий локальный прогон подтвердил **70 supervisor-тестов и 15 lab/storage-тестов, OK**, включая 20 coordination-тестов и 13 новых storage/probe/CLI-тестов. Это unit/contract-проверки с настоящими временными файлами/SQLite/Python subprocess, не испытание Docker или XFS. Предыдущий lab/openclaw-прогон: 18, OK с 2 skips; этот набор не менялся и заново в данном срезе не выполнялся.

Отдельно приняты результаты пользователя на Linux-ВМ для предшествующего config-среза: 37 supervisor/15 storage OK, `lab-v1` валиден, незаполненный example возвращает exit 2, mount UUID/тип XFS совпадают, project Accounting/Enforcement ON. Диск в локальном lab-профиле явно выбран 10737418240 bytes (10 GiB), это не universal default и не уже испытанная квота OpenClaw. Затем пользователь предоставил Linux-прогон coordinator-среза: 57 supervisor/15 lab/storage OK и сообщение об ожидаемом отказе синтетического create при неподтверждённой квоте. Новый XFS preflight пока проверен локально на фикстурах/процессах, не на реальной ФС ВМ.

Read-only диагностика ext4 в `lab/storage/` уже выполнена пользователем на Linux-ВМ: complete/errors=[], корневой `/dev/sda1`, project=false, quota=false, prjquota_visible=false, enforcement_verified=false. Она не включает квоты и не исследует новый XFS-том. Исторический Windows-результат incomplete/unsupported_platform не блокирует завершённое Linux-discovery. Новый XFS `/srv/agent-data` имеет отдельные предоставленные свидетельства Accounting/Enforcement ON; сведения о reboot и пробе 100 МиБ из последующего ревью отделены от первичных логов в `docs/VM_STORAGE.md`. Проверка quota backend настоящего экземпляра OpenClaw ещё не выполнена. Изменение ФС, монтирование и установка утилит требуют отдельного разрешения.
