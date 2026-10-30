# Read-only preflight подготовленного XFS

## Область действия

Это проверка backend, не provisioning и не проверка персональной квоты агента. Параметры берутся из явно заданного deployment-профиля целевой машины; лабораторные UUID/устройства/пути не зашиты в код. Schema v1 поддерживает здесь только xfs_project_quota.

Проверяются канонический существующий путь без перенаправления symlink, точный mountpoint, XFS, ожидаемый UUID, корень ФС, безопасный device source, rw и точные prjquota/pquota options без конфликтующих флагов. Затем проверяются Project Accounting/Enforcement ON и повторный снимок mount metadata. Отсутствие тома, неверная/неоднозначная информация, смена метаданных или ошибка команды дают отказ без fallback на корневую ФС.

Повторный снимок снижает риск смены mount, но не удерживает mount/каталог и не исключает ABA/TOCTOU. Будущий executor должен повторно проверять окружение и безопасно привязывать реальные операции к нужному хранилищу.

## Что запускается

Только следующие команды с argv без shell (TARGET — путь из проверенного административного профиля):

```text
findmnt --json --mountpoint TARGET --output TARGET,SOURCE,FSTYPE,UUID,OPTIONS,FSROOT
xfs_quota -x -c 'state -p' TARGET
findmnt --json --mountpoint TARGET --output TARGET,SOURCE,FSTYPE,UUID,OPTIONS,FSROOT
```

LC_ALL=C фиксирует язык quota state. stdout ограничен при чтении: 65536 байт полезного вывода, дополнительный байт используется для обнаружения превышения. Timeout по умолчанию ограничивает process.wait десятью секундами, не весь preflight и не запуск Popen. Cleanup может дополнительно ждать process.wait(timeout=1) и reader.join(timeout=1). Если потомок удерживает stdout, вызывающий поток получает output_timeout, но daemon-reader и pipe могут оставаться до закрытия stdout потомком: завершение дерева процессов и полная очистка ресурсов не гарантированы. stderr отбрасывается; наружу возвращаются фиксированные коды, не сырые диагностики. Нет mount/remount, форматирования, назначения project ID/лимитов, миграции, Docker или установки пакетов. Runner принимает доверенные argv от вызывающего кода и сам не является sandbox.

## Приёмка нового среза на Linux-ВМ

После обычной доставки кода из корня проекта, с уже заполненным локальным профилем:

```bash
python3 -m unittest discover -s supervisor/tests -v
sudo python3 -m supervisor.storage --check supervisor/deployment.local.json
printf 'storage preflight exit: %s\n' "$?"
```

Конечный список критериев этого среза:

1. 70 supervisor-тестов проходят. В них нет реальной настройки XFS: mount/quota fixtures синтетические, runner испытывается настоящими Python-процессами.
2. На подготовленном XFS CLI возвращает JSON с status=backend_ready, backend_ready=true, errors=[] и disk_quota_verified=false; exit 0. Это ожидаемый критерий, **не уже полученный вывод ВМ**.

При blocked / exit 2 сохранить JSON и код ошибки. Не менять автоматически профиль, mount или квоты ради успеха. Нестандартный формат вывода/недоступные утилиты/недостаток прав требуют разбора, а не отключения guard. Ранее принятые Linux 57/15 и config-срез не нужно повторять отдельно; старое root ext4 discovery тоже завершено.

## Что не разрешает успешный результат

StorageReport.disk_quota_verified неизменяемо false и не принимается параметром конструктора. Общие Accounting/Enforcement ON не доказывают project ID, hard block/inode limits, отказ записи или охват всех данных конкретного агента. Не преобразовывать backend_ready в quota evidence для coordinator. Вызов preflight не подключён к вебу, не создаёт registry operation и не разрешает runtime start.

Персональные квоты, writable layer/logs, retained data, lifecycle/recovery, host metrics collector, служебная авторизация и Docker executor остаются отдельными работами. Изменяющие ФС операции требуют отдельного согласования.

## Независимое ревью

Рецензент полностью прочитал storage.py, probes.py, test_storage.py, этот документ и config.py. При ручном разборе существенных security/logic ошибок не выявлено. Уточнения timeout и очистки pipe внесены в описание выше. Инструментальные SHA256 и автоматический scan у рецензента не выполнены: terminal-вызов заблокирован из-за отозванного согласования. Блокировка не обходилась. Поэтому итог независимого review — incomplete / passed=false, не полное одобрение snapshot. Ранее вычисленные основным исполнителем hashes не заменяют недостающую независимую проверку.

## Проверено локально

70 supervisor и 15 lab/storage тестов OK на Windows. Из новых — 13 тестов storage/probe/CLI с отрицательными случаями, ограничением вывода, timeout, UTF-8 и sanitised errors. Это не реальное исполнение findmnt/xfs_quota на Linux и не испытание hard quota настоящего OpenClaw.
