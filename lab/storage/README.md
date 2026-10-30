# Read-only discovery ext4 project quotas

Этот шаг только собирает метаданные. Он **не включает квоты**, не меняет корневой
раздел и не проверяет hard quota / отказ записи при превышении лимита.
Согласия на включение quotas или изменение root filesystem нет.

## Запуск пользователем на Linux ВМ

Из корня проекта, на той же Linux ВМ, где работает локальный Docker daemon:

```sh
sudo python3 lab/storage/inspect_ext4.py
```

Нужны **уже установленные** Python 3.10+ (только stdlib), Docker CLI с доступом к
уже работающему локальному daemon, `findmnt` с JSON output (util-linux),
`tune2fs` с возможностью чтения superblock (e2fsprogs). Ничего устанавливать или
запускать скрипт не пытается. `sudo` нужен для чтения устройства и доступа к
Docker; скрипт сам `sudo` не запускает. Используйте доверенные локальные утилиты
из PATH и локальный Docker context, не удалённый daemon / DOCKER_HOST.

Скрипт выполняет только:

1. `docker info --format` с JSON-шаблоном, выбирающим **только** `Driver` и
   `DockerRootDir`, а не весь Docker info.
2. `findmnt --json --target DockerRootDir --output SOURCE,FSTYPE,OPTIONS,TARGET`.
3. Только при `fstype=ext4` и безопасном обычном пути `/dev/...`:
   `tune2fs -l DEVICE` — исключительно чтение.

Команды передаются списками аргументов, без shell; для каждой установлен
`LC_ALL=C`, timeout 10 секунд, проверяются return code, тип и размер stdout
(не более 1 048 576 символов перед разбором), структура JSON и необходимые метаданные.
Это последовательный снимок метаданных, не атомарная проверка состояния.
Нет форматирования, mount/remount, quotaon, изменения tune2fs или файлов на ВМ;
нет CLI-флагов для изменения состояния, подстановки устройства или фикстур.

Пути проходят консервативную синтаксическую проверку: абсолютные, до 4096
символов, ASCII-буквы/цифры и `/_ . + -` **без пробелов**, без пустых компонентов,
`.`/`..`, управляющих символов, findmnt-суффиксов вида `[/subpath]` и shell
метасимволов. `/` допустим как mountpoint. `/dev/mapper/...` допустим.
Это не проверка symlink/block-device identity. Нестандартные, неоднозначные и
неподдерживаемые данные отвергаются как incomplete, а не «исправляются».
Mountpoint должен содержать DockerRootDir по границе компонента пути.

## JSON на stdout

Нормальный вызов печатает один объект с whitelist полей:

| Поле | Значение |
| --- | --- |
| `status` | `complete` — метаданные ext4 прочитаны и разобраны; `incomplete` — данные неполные / неподдерживаемые |
| `errors` | Короткие фиксированные коды причин, без вывода утилит |
| `driver`, `docker_root_dir` | Только проверенные Driver и DockerRootDir |
| `filesystem` | Проверенный тип ФС из findmnt |
| `device`, `mountpoint` | Проверенные пути или `null` |
| `features.project`, `features.quota` | Наличие точных feature-токенов в `Filesystem features:`; `true` / `false` / `null` |
| `prjquota_visible` | Наличие **точного** токена `prjquota` в видимых mount options; `true` / `false` / `null` |
| `enforcement_verified` | **Всегда `false`** |

`false` для feature означает: валидная непустая строка features прочитана,
но токена в ней нет. `null` означает неизвестно: строка отсутствует, пуста,
неоднозначна, повреждена либо команда не выполнена. Отсутствие `prjquota` означает
только отсутствие этого видимого токена; другие признаки не подменяются им.
Ни features, ни mount option не доказывают включённый enforcement. Даже
`status=complete` и все три признака `true` **не являются успешным тестом квоты**.
Отсутствующие features при успешно прочитанных метаданных могут дать complete:
это завершённое discovery, а не verdict о готовности квот.

Код выхода: `0` — discovery complete, `2` — incomplete. На Windows / другой
не-Linux платформе — `unsupported_platform` без запуска внешних команд.
Неизвестные CLI-аргументы — `invalid_arguments` без запуска discovery.

Причины incomplete: `unsupported_platform`, `unsupported_filesystem`,
`unsafe_device`, `docker_invalid_metadata`, `findmnt_invalid_metadata`,
`tune2fs_invalid_features`; ошибки команд кодируются как
`docker_…`, `findmnt_…`, `tune2fs_…` с суффиксом `unavailable`, `timeout`,
`failed` или `invalid_output`. Поток stderr, полные stdout утилит, raw mount
options и дополнительные Docker поля не выводятся. Скрипт не читает `.env`.
Ожидаемые отказы не печатают traceback / текст исключения; ошибки ограничены
фиксированным кодом. Отчёт всё же содержит разрешённые локальные пути — перед
публикацией проверьте, можно ли раскрывать именно эти пути.

## Проверка кода, не проверка ВМ

Из корня проекта, без внешних команд discovery, установок и сторонних пакетов:

```sh
python -B -m unittest discover -s lab/storage/tests -v
```

Все command fixtures в тестах **синтетические**, явно помечены в test module;
runner инъецируется только при unit-тестах. Platform mocks находятся только
в тестах. В рабочем CLI нет режима фикстур или принудительного Linux.
Тесты упражняют настоящий парсер и сборку отчёта: features present/missing/
unknown, точный токен options, unsupported FS, небезопасные пути, пропуски и
типы metadata, malformed/duplicate JSON, отсутствие утилит, return code,
timeout, отсутствие утечек и запрет команд вне Linux.

Известно **только со слов пользователя**: `overlay2`, `/var/lib/docker` на
корневом `ext4`, `/dev/sda1`, options `rw,relatime,errors=remount-ro`.
Это не результат запуска данного скрипта. Features пока неизвестны.
Из этих сведений нельзя объявить project quotas невозможными на ext4.
Для следующего решения нужен фактический JSON, полученный пользователем на ВМ.
Включение квот / изменение root filesystem требует отдельного согласования;
этот артефакт такого согласия не подразумевает и никаких изменений не выполняет.
