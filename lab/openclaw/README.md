# Этап 2: один реальный OpenClaw без LLM (Debian 12)

**Статус:** подготовленная лабораторная конфигурация; сборка и запуск на ВМ ещё не проверены. Изменения относятся только к `lab/openclaw/`; работающий Compose Open WebUI не изменяется. Не запускать здесь многопользовательское provisioning.

**Основа:** официальный `openclaw/openclaw`, commit `7c12438929e5d198616fe8f602d896e011647d39` (теоретический baseline из ROADMAP.md). Не используйте `latest`: совпадение образа с исходниками тогда не гарантировано. Сборка исходного OpenClaw потребует не менее 6 ГБ доступной RAM по документации и существенного дискового пространства; проверьте ресурсы ВМ заранее. Фиксация commit делает исходники определёнными, но сборка не гарантированно побайтово воспроизводима: некоторые зависимости и дистрибутивные пакеты в upstream Dockerfile могут обновляться. Для отчёта сохраняйте фактический image ID/digest. Node и npm на хост устанавливать не нужно.

## 0. Проверки исходной ВМ (ничего не устанавливается)

```bash
sudo docker version
sudo docker compose version
free -h
df -h
```

Дальнейшие шаги **клонируют внешний репозиторий и собирают новый образ**. Выполнять только после согласования загрузки исходников и базовых образов на ВМ. Ни `git push`, ни SSH-действия этой инструкцией автоматически не выполняются.

## 1. Сборка фиксированного образа OpenClaw

Команды на Debian 12, из временного рабочего каталога, не внутри рабочего проекта Open WebUI:

```bash
mkdir -p "$HOME/openclaw-src-stage2"
git clone https://github.com/openclaw/openclaw.git "$HOME/openclaw-src-stage2/openclaw"
cd "$HOME/openclaw-src-stage2/openclaw"
git checkout --detach 7c12438929e5d198616fe8f602d896e011647d39
test "$(git rev-parse HEAD)" = "7c12438929e5d198616fe8f602d896e011647d39"
sudo docker build \
  --build-arg "GIT_COMMIT=$(git rev-parse HEAD)" \
  --build-arg "OPENCLAW_BUILD_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t openclaw-stage2:7c12438929e5 .
```

Проверьте полученный image ID; не путать с успешным запуском Gateway:

```bash
sudo docker image inspect openclaw-stage2:7c12438929e5 \
  --format '{{.Id}}'
```

## 2. Конфигурация лабораторного Compose

Команды из клона **своего** проекта (в каталоге `lab/openclaw/` после копирования файлов пакета):

```bash
cd "$HOME/agent-platform/lab/openclaw"
python3 -m unittest discover -s tests -v
python3 init_env.py
stat -c '%a %n' .env    # ожидается 600 .env
sudo docker compose config --quiet
```

`init_env.py` создаёт случайный токен Gateway. Не публикуйте `.env` и результаты `docker compose config` без `--quiet` (значения могут содержать токен). Простой запуск `init_env.py` второй раз не перезаписывает секреты. Не выполняйте `docker compose down -v`: это удаляет лабораторные volumes.

**Перед запуском** создать минимальную конфигурацию штатной CLI закреплённого образа (без onboarding модели):

```bash
sudo docker compose run --rm --no-deps --entrypoint node gateway \
  dist/index.js config set --batch-json \
  '[{"path":"gateway.mode","value":"local"},{"path":"gateway.bind","value":"lan"},{"path":"gateway.auth.mode","value":"token"},{"path":"gateway.controlUi.allowedOrigins","value":["http://localhost:18789","http://127.0.0.1:18789"]}]'
```

Это экспериментальный bootstrap без модели: если закреплённый upstream отклонит такой вариант начальной конфигурации, сохранить точную ошибку и проверить штатные опции `onboard --help`, не отключая авторизацию и не выдавая ошибку за успешный запуск.

`lan` — интерфейс **внутри контейнера**; с хоста порт публикуется **только** на `127.0.0.1`. При нестандартном `OPENCLAW_LAB_PORT` из `.env` также скорректируйте Control UI origins. Не делайте конфигурацию read-only: startup Doctor и последующие изменения OpenClaw могут требовать атомарной записи, это отдельный проверяемый аспект этапа.

## 3. Старт и фактические проверки

```bash
sudo docker compose up -d gateway
sudo docker compose ps
sudo docker compose logs --tail=100 gateway
curl -i http://127.0.0.1:18789/healthz
curl -i http://127.0.0.1:18789/readyz
sudo docker compose run --rm cli gateway health --port 18789
sudo docker compose exec -T gateway node dist/index.js --version
sudo docker stats --no-stream
```

`/healthz` — liveness, `/readyz` — readiness. Их ответы и команда `gateway health` не являются проверкой модели или агентного чата. При отказе `gateway health` проверить в журналах авторизацию/pairing, но **не отключать** проверку токена ради зелёного статуса.

Для доступа с ноутбука откройте отдельный SSH-туннель, не открывая порт Gateway в Интернет:

```bash
ssh -N -L 18789:127.0.0.1:18789 VM_USER@VM_HOST
```

Потом `http://localhost:18789/`; при запросе токена в UI получите его **локально на ВМ** из `.env` (не присылайте в чат, логи или скриншоты). Pairing нового браузерного устройства может потребовать отдельного подтверждения — не воспринимать требование pairing как ошибку TLS или «отсутствие модели».

## 4. Проверка сохранения и работы при перезапуске

```bash
sudo docker compose restart gateway
sudo docker compose ps
curl -i http://127.0.0.1:18789/readyz
sudo docker compose run --rm cli config get gateway.mode
sudo docker compose run --rm cli config get gateway.auth.mode
```

Дополнительно: проверка непустых/сохранённых `state`, `workspace`, `auth_secrets` после перезапуска, фактической работы `gateway health` с разрешённой identity, отсутствия опубликованных портов `0.0.0.0` и отсутствия Docker socket в контейнере. До запуска стенда сохранить имена и ID volumes для резервного копирования. Не публиковать `config get` для путей с токенами.

## Что сознательно не включено

- LLM, токены провайдера, Telegram, плагины и инструменты, supervisor и создание контейнера из UI.
- Docker socket или host network в Gateway; отдельные volumes — основа, но сами по себе не полная гарантия изоляции.
- Внедрение в существующий Open WebUI. Ожидаемая надпись `/agent: Не подключён` остаётся правдивой.
- Имитация «готового Gateway»: только реальные `docker inspect`, `/readyz` и авторизованный CLI.
- Read-only `openclaw.json`, так как Docker entrypoint вызывает Doctor и конфигурация штатно заменяется атомарно.

**Критерий завершения этапа 2:** image ID и source SHA записаны, Gateway действительно стартует, соединение по токену (и pairing, если нужен) прошло, состояние пережило restart, зафиксированы журналы/метрики и отсутствие модели не смешано с ошибкой запуска. Пока этого нет, этап 2 *подготовлен, но не завершён*.

Документация, сверенная по этому commit: `docs/install/docker.md`, `docker-compose.yml`, `docker-entrypoint.mjs`. Документация текущей версии может отличаться: https://docs.openclaw.ai/docker
