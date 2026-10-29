# Этап 2: один реальный OpenClaw без LLM (Debian 12)

**Статус: этап 2 выполнен и проверен на ВМ пользователем.** Подтверждены health/readiness, разрешённый CLI и отказ с неверным токеном, pairing Control UI, restart и сохранение трёх volumes после пересоздания. Фактический Compose прошёл структурную проверку; commit проекта и image ID зафиксированы в `docs/ROADMAP.md`. Автоматическая проверка на основной Windows-системе это развёртывание не выполняла. Это отдельный лабораторный экземпляр без LLM; не запускать здесь многопользовательское provisioning. Ниже сохранены инструкции воспроизведения, не требование повторить уже принятую проверку.

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
LAB_DIR="$HOME/agent-platform/lab/openclaw"
SOURCE_DIR="$HOME/openclaw-src-stage2/openclaw"
mkdir -p "$HOME/openclaw-src-stage2" &&
git clone https://github.com/openclaw/openclaw.git "$SOURCE_DIR" &&
git -C "$SOURCE_DIR" checkout --detach 7c12438929e5d198616fe8f602d896e011647d39 &&
bash "$LAB_DIR/build_image.sh" "$SOURCE_DIR"
```

Цепочка `&&` останавливается при ошибке clone/checkout. `build_image.sh` дополнительно проверяет точный SHA и чистоту исходного дерева, включая untracked-файлы, и не вызывает Docker при отказе. Если каталог уже существует, clone завершится ошибкой: не удаляйте его автоматически. Для осознанной повторной сборки проверенного checkout можно отдельно вызвать `bash "$LAB_DIR/build_image.sh" "$SOURCE_DIR"`. Даже чистый checkout не гарантирует побайтовой воспроизводимости зависимостей.

Проверьте полученный image ID; не путать с успешным запуском Gateway:

```bash
sudo docker image inspect openclaw-stage2:7c12438929e5 \
  --format '{{.Id}}'
```

## 2. Конфигурация лабораторного Compose

Команды из клона **своего** проекта (в каталоге `lab/openclaw/` после копирования файлов пакета):

```bash
cd "$HOME/agent-platform/lab/openclaw" &&
python3 -m unittest discover -s tests -v &&
python3 init_env.py &&
stat -c '%a %n' .env &&
python3 validate_compose.py
```

`stat` на Debian должен показать `600 .env`. Если `.env` уже существует, не удаляйте его ради повторного запуска блока: пропустите только `python3 init_env.py`, затем повторите проверку прав и `python3 validate_compose.py`.

`init_env.py` создаёт случайный токен Gateway. Не публикуйте `.env` и результаты `docker compose config` без `--quiet` (значения могут содержать токен). Повторный запуск генератора не перезаписывает секреты. Не выполняйте `docker compose down -v`: это удаляет лабораторные volumes.

`validate_compose.py` вызывает настоящий `docker compose config --format json` и проверяет разобранную структуру: набор сервисов, закреплённый образ, loopback-порт, сети, dedicated volumes, запрет bind mounts/privileged/добавления capabilities, обязательные ограничения и согласованность токенов. Результат Compose и его диагностика не печатаются: они могут содержать секреты. Контейнеры не запускаются, YAML-библиотеки устанавливать не нужно. Это проверка перечисленных инвариантов, не полный аудит OpenClaw или доказательство изоляции.

Локально без Docker выполняются unit-тесты на явно обозначенных JSON-фикстурах и проверки build guard с тестовыми Git/Docker-функциями. Настоящий рендеринг Compose при отсутствии Docker пропускается, POSIX-права на Windows также пропускаются. На Debian с Docker обе проверки должны выполняться; `skipped` не считать успешной интеграционной проверкой.

**Перед запуском** создать минимальную конфигурацию штатной CLI закреплённого образа (без onboarding модели):

```bash
sudo docker compose run --rm --no-deps --entrypoint node gateway \
  dist/index.js config set --batch-json \
  '[{"path":"gateway.mode","value":"local"},{"path":"gateway.bind","value":"lan"},{"path":"gateway.auth.mode","value":"token"},{"path":"gateway.controlUi.allowedOrigins","value":["http://localhost:18789","http://127.0.0.1:18789"]}]'
```

Это экспериментальный bootstrap без модели: если закреплённый upstream отклонит такой вариант начальной конфигурации, сохранить точную ошибку и проверить штатные опции `onboard --help`, не отключая авторизацию и не выдавая ошибку за успешный запуск.

`lan` — интерфейс **внутри контейнера**; с хоста порт публикуется **только** на `127.0.0.1`. При нестандартном `OPENCLAW_LAB_PORT` из `.env` скорректируйте Control UI origins в bootstrap выше, переменную `LAB_PORT` для host-side curl ниже и удалённый порт SSH-туннеля. Внутренний порт Gateway/CLI остаётся 18789. Не делайте конфигурацию read-only: startup Doctor и последующие изменения OpenClaw могут требовать атомарной записи, это отдельный проверяемый аспект этапа.

## 3. Старт и фактические проверки

```bash
sudo docker compose up -d gateway
sudo docker compose ps
sudo docker compose logs --tail=100 gateway
LAB_PORT=18789    # тот же внешний порт, что OPENCLAW_LAB_PORT в .env
curl -i "http://127.0.0.1:${LAB_PORT}/healthz"
curl -i "http://127.0.0.1:${LAB_PORT}/readyz"
sudo docker compose run --rm cli gateway health --port 18789
sudo docker compose exec -T gateway node dist/index.js --version
sudo docker stats --no-stream
```

`/healthz` — liveness, `/readyz` — readiness. Дождитесь готовности после старта; единичный отказ сразу после `up -d` ещё не доказывает ошибку конфигурации. Эти HTTP-ответы не доказывают авторизацию, работу модели или агентного чата. При отказе `gateway health` проверить в журналах авторизацию/pairing, но **не отключать** проверку токена ради зелёного статуса.

### Отрицательная проверка авторизации

После успешного подключения штатного CLI повторите защищённую операцию с заведомо неправильным токеном:

```bash
if sudo docker compose run --rm -e OPENCLAW_GATEWAY_TOKEN=invalid-stage2-test-token cli gateway health --port 18789; then
  printf 'FAIL: операция с неправильным токеном завершилась успешно; разобраться в источниках credentials\n' >&2
else
  printf 'Проверить причину отказа: нужен именно отказ авторизации, а не сеть/парсер CLI/неготовый Gateway\n'
fi
```

Это не автоматический security PASS по любому ненулевому exit code. Запишите причину отказа, сопоставьте с успешным контрольным запросом. Если CLI использовал сохранённую device identity/другой источник credentials вместо изменённого токена, такая проверка не изолирует token auth: нужен отдельный чистый клиент и проверка штатных параметров через `gateway health --help`. Нельзя засчитывать отказ из-за неизвестного флага, pairing либо недоступного сервера как доказательство отклонения неверного токена.

Для доступа с ноутбука откройте отдельный SSH-туннель, не открывая порт Gateway в Интернет:

```bash
LAB_PORT=18789    # внешний порт Gateway на ВМ; согласовать с .env и origins
ssh -N -L "${LAB_PORT}:127.0.0.1:${LAB_PORT}" VM_USER@VM_HOST
```

Потом `http://localhost:18789/` (или выбранный `LAB_PORT`); при запросе токена в UI получите его **локально на ВМ** из `.env` (не присылайте в чат, логи или скриншоты). Pairing нового браузерного устройства может потребовать отдельного подтверждения — не воспринимать требование pairing как ошибку TLS или «отсутствие модели».

## 4. Проверка сохранения и работы при перезапуске

```bash
sudo docker compose restart gateway
sudo docker compose ps
curl -i "http://127.0.0.1:${LAB_PORT}/readyz"
sudo docker compose run --rm cli config get gateway.mode
sudo docker compose run --rm cli config get gateway.auth.mode
```

Дополнительно: проверка непустых/сохранённых `state`, `workspace`, `auth_secrets` после перезапуска, фактической работы `gateway health` с разрешённой identity, отсутствия опубликованных портов `0.0.0.0` и отсутствия Docker socket в контейнере. До запуска стенда сохранить имена и ID volumes для резервного копирования. Не публиковать `config get` для путей с токенами.

### Сохранение при пересоздании, а не только restart

`restart` сохраняет записываемый слой того же контейнера и не доказывает корректность volumes. Следующая проверка создаёт только собственные маркеры `.stage2-persistence-probe` в трёх лабораторных volumes. `flag: "wx"` запрещает перезапись существующего файла; если имя уже занято, остановитесь и разберитесь, не удаляя чужие данные.

```bash
sudo docker compose exec -T gateway node -e 'const fs=require("node:fs"); for (const d of ["/home/node/.openclaw","/home/node/.openclaw/workspace","/home/node/.config/openclaw"]) { fs.mkdirSync(d,{recursive:true}); fs.writeFileSync(d+"/.stage2-persistence-probe","stage2-persistence-check\n",{flag:"wx"}); }'
```

Только если создание маркеров завершилось успешно, пересоздать **лабораторный** Gateway, не удаляя volumes:

```bash
BEFORE=$(sudo docker compose ps -q gateway) &&
test -n "$BEFORE" &&
sudo docker compose up -d --force-recreate --no-deps gateway &&
AFTER=$(sudo docker compose ps -q gateway) &&
test -n "$AFTER" &&
test "$BEFORE" != "$AFTER" &&
sudo docker compose exec -T gateway node -e 'const fs=require("node:fs"); for (const d of ["/home/node/.openclaw","/home/node/.openclaw/workspace","/home/node/.config/openclaw"]) { if(fs.readFileSync(d+"/.stage2-persistence-probe","utf8")!=="stage2-persistence-check\n") throw Error("Persistence check failed"); } console.log("Stage 2 volume probes survived container recreation");'
```

Затем дождаться readiness, повторить авторизованный `gateway health` и чтение несекретной конфигурации. Убедиться, что собственные данные OpenClaw сохранились: маркеры подтверждают сохранение каталогов, но не заменяют проверку состояния приложения. Маркеры не содержат секретов и не требуют чтения содержимого credentials.

## Что сознательно не включено

- LLM, токены провайдера, Telegram, плагины и инструменты, supervisor и создание контейнера из UI.
- Docker socket или host network в Gateway; отдельные volumes — основа, но сами по себе не полная гарантия изоляции.
- Внедрение в существующий Open WebUI. Ожидаемая надпись `/agent: Не подключён` остаётся правдивой.
- Имитация «готового Gateway»: только реальные `docker inspect`, `/readyz` и авторизованный CLI.
- Read-only `openclaw.json`, так как Docker entrypoint вызывает Doctor и конфигурация штатно заменяется атомарно.

**Критерий завершения этапа 2:** image ID и source SHA записаны, структурная проверка фактического Compose прошла, Gateway действительно стартует, разрешённое подключение (и pairing, если нужен) прошло, изолированная проверка неверных credentials дала именно отказ авторизации, состояние пережило restart и пересоздание контейнера, зафиксированы журналы/метрики и отсутствие модели не смешано с ошибкой запуска. Пока этого нет, этап 2 *подготовлен, но не завершён*.

Документация, сверенная по этому commit: `docs/install/docker.md`, `docker-compose.yml`, `docker-entrypoint.mjs`. Документация текущей версии может отличаться: https://docs.openclaw.ai/docker
