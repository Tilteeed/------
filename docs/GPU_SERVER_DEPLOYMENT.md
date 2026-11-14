# BEZR: развёртывание на GPU-сервере

Этот документ описывает последовательность подготовки **нового** сервера и
проверку уже работающего стенда. Примеры в [`ops/examples/gpu-server/`](../ops/examples/gpu-server/)
основаны на настройках `sbergigachat`, прочитанных 14 ноября 2026 года. Это
**не универсальные значения**: перед применением проверьте адреса, устройства,
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

На проверенном сервере один агент ограничен 4 ГиБ RAM, 2 CPU, 512 PIDs и
10 ГиБ диска. **Фактический runtime на сервере при проверке содержал общий
дисковый бюджет 80 ГиБ**, хотя ранее обсуждалось 40 ГиБ. Он также содержал
36 ГиБ RAM, 18 CPU и порог свободного диска 10 ГиБ. Не считать 40 ГиБ уже
настроенным ограничением: определите нужную политику отдельно. Даже при
бюджете 40 ГиБ и лимите 10 ГиБ на агента число работающих экземпляров может
быть меньше четырёх из-за других ресурсов и резерва свободного места.

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

Нужны Linux, cgroup v2, systemd, Docker/Compose, `ip`, `nft`, `unshare`,
`bpftool`, XFS tools, Python 3.12+, Nginx, доступный NVIDIA driver и уже
работающая Ollama. До установки или изменения системы проверьте существующие
службы, пространство, состояние контейнеров, портов и томов:

```bash
git -C /opt/bezr status --short --branch
systemctl is-active docker nginx ollama
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

## 2. Профиль хранилища и агентов

Возьмите [`deployment.example.json`](../ops/examples/gpu-server/deployment.example.json),
замените нулевой `expected_uuid` на UUID фактически проверенной XFS и при
необходимости скорректируйте mountpoint/лимиты. `prjquota` должен быть
включён и для accounting, и для enforcement; не подставляйте UUID из другой
машины. Сохраните копию как `supervisor/deployment.local.json`: этот путь
исключён из Git. Существующий файл не перезаписывайте без проверки.

```bash
cd /opt/bezr
python3 -m supervisor.config --check supervisor/deployment.local.json
sudo python3 -m supervisor.storage --check supervisor/deployment.local.json
```

`backend_ready` означает проверку backend, а не испытание реальной квоты.
Файловая система с `prjquota` должна корректно монтироваться после reboot;
редактирование `fstab`, создание ФС и миграция данных — отдельные операции.

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

Примеры Nginx: [`nginx-web.conf.example`](../ops/examples/gpu-server/nginx-web.conf.example)
и [`nginx-websocket.conf.example`](../ops/examples/gpu-server/nginx-websocket.conf.example).
Сертификат должен покрывать и `bezr.space`, и `*.agents.bezr.space`; приватный
ключ не помещается в Git. Настройте DNS для обоих имён и соответствующий
сертификату доверенный TLS. На недоступность/ошибку сертификата не отвечайте
отключением проверки сертификатов. Проверьте `sudo nginx -t` до reload и не
перезаписывайте существующий vhost на работающем сервере без сравнения.
В примере включён HTTP/2 для HTTPS сайта BEZR: это позволяет браузеру
одновременно загружать больше модулей Control UI. Он требует сборку Nginx с
`http_v2_module`; WebSocket по-прежнему использует разрешённый upgrade.
Если проверяете Nginx с временным конфигом от root, обязательно указывайте
`user www-data` и отдельные `*_temp_path` внутри тестового каталога: иначе
Nginx может изменить владельца общих временных каталогов рабочего сервера.

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
оператор подтвердил эту политику и ресурсы. Изменение уже действующего
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
  --capacity-disk-bytes 42949672960 --disk-floor-bytes 10737418240 \
  --state-dir /var/lib/personal-agent-supervisor \
  --socket-path /run/personal-agent-supervisor/control.sock \
  --network-profile-default agent_proxy_v1 --control-ui-domain agents.bezr.space \
  --agent-network-pool 172.24.0.0/24 --frontend-network-pool 172.24.1.0/24 \
  --ollama-api-url http://172.24.3.1:11434 --ollama-default-model-id qwen3.5:9b \
  --ollama-context-tokens 16384 --ollama-max-tokens 2048 --no-ollama-think \
  --ollama-network-pool 172.24.2.0/24 --ollama-egress-interface ens1f0
```

Для Qwen3.5 9B на этом сервере контекст 8192 оказался недостаточным для
системных инструкций OpenClaw и инструментов: даже короткий запрос завершался
ошибкой переполнения. Изолированная проверка с контекстом 16384 прошла;
длинные диалоги по-прежнему могут потребовать сокращения истории. Для уже
созданного агента нельзя менять только runtime: его защищённая конфигурация
тоже должна соответствовать настройкам Supervisor.

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

```bash
cd /opt/bezr
export SUPERVISOR_SOCKET_DIR=/run/personal-agent-supervisor
export SUPERVISOR_TOKEN_FILE=/var/lib/personal-agent-supervisor/service.token
docker compose -f compose.yaml -f compose.supervisor.yaml config --quiet
# Только после проверки образа, volume, .env и наличия резервной копии:
# docker compose -f compose.yaml -f compose.supervisor.yaml up -d
```

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

Дальнейшие подробности проверок и инвариантов: [SUPERVISOR_RUN.md](SUPERVISOR_RUN.md),
[OLLAMA_ROUTE_ACCEPTANCE.md](OLLAMA_ROUTE_ACCEPTANCE.md) и
[DEPLOYMENT_CONFIG.md](DEPLOYMENT_CONFIG.md). Эти документы могут содержать
исторический статус; актуальность каждого утверждения проверяйте на целевом хосте.
