# PortSentinel [![CI](https://github.com/minkinad/portsentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/minkinad/portsentinel/actions/workflows/ci.yml) [![CodeQL](https://github.com/minkinad/portsentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/minkinad/portsentinel/actions/workflows/codeql.yml) [![Security](https://github.com/minkinad/portsentinel/actions/workflows/security.yml/badge.svg)](https://github.com/minkinad/portsentinel/actions/workflows/security.yml)

PortSentinel помогает локализовать сбой соединения по цепочке DNS → TCP → TLS → HTTP и выдаёт воспроизводимый отчёт. CLI подходит для ручной диагностики; HTTP API служит основой для автоматизации.

**Статус:** рабочая основа v0.1. Лицензия MIT планируется, файл LICENSE пока отсутствует.

## Реализовано

- `portsentinel check URL` с текстовым или JSON-отчётом, кодами выхода 0/1/2.
- DNS resolution, TCP connect, TLS handshake с проверкой цепочки сертификатов и сроком действия, HTTP статус.
- Общий deadline, проверка разрешённых портов и адресов, запрет редиректов и ограничение чтения тела.
- HTTP `POST /v1/check`, `GET /health/live`, `GET /health/ready`; ограничение параллельных запросов.
- YAML и переменные окружения, `slog`, graceful shutdown.

**Запланировано:** история, несколько целей за запуск, distributed agents, Kubernetes, dashboard, полные метрики и tracing.

## Быстрый старт

```bash
make setup
make build
./bin/portsentinel check https://example.com
./bin/portsentinel check --format json --output report.json https://example.com
./bin/portsentinel-server --config configs/portsentinel.yaml
curl -X POST -H 'Content-Type: application/json' -d '{"target":"https://example.com"}' http://127.0.0.1:8081/v1/check
```

Для локального или приватного адреса CLI требует `--allow-private`; порт должен быть в `checks.allowed_ports`. Сервер не принимает приватные адреса даже при изменении listen. Сетевые проверки требуют доступа к указанной цели; стандартные тесты работают локально.

## Конфигурация

`configs/portsentinel.yaml` задаёт `server.listen`, `server.max_concurrent`, `checks.timeout`, `checks.allowed_ports`, `checks.allow_cidrs`, `checks.deny_cidrs`, `log.format`, `log.level`. Переменные `PORTSENTINEL_LISTEN`, `PORTSENTINEL_TIMEOUT`, `PORTSENTINEL_LOG_FORMAT`, `PORTSENTINEL_LOG_LEVEL` перекрывают YAML. Без файла CLI использует безопасные значения по умолчанию: listen `127.0.0.1:8081`, 4 параллельных запроса, 5s, только порты 80/443. Пример в `.env.example`. Секреты в отчёты и конфигурацию не добавляйте.

## Архитектура и проверки

`internal/security` разрешает цель и закрепляет IP; `internal/diagnostics` содержит расширяемый список проверок; `internal/server` ограничивает параллельность. См. [архитектуру](docs/ARCHITECTURE.md) и [roadmap](docs/ROADMAP.md).

```bash
go test ./...
go test -race ./...
go vet ./...
make docker-build
```

По тегу `v*` release workflow подготовлен для публикации server-образа amd64/arm64 в GHCR; реальный запуск GitHub Actions ещё не проверен. Docker Compose не нужен: обязательных внешних сервисов нет.

## Ограничения

Результат HTTP считает статусы 4xx/5xx ошибкой. Редиректы показываются как 3xx без перехода. HTTP API, в том числе в контейнере, по умолчанию слушает только localhost и пока не имеет аутентификации. Для доступа через опубликованный Docker-порт нужно явно задать `PORTSENTINEL_LISTEN=:8081` и поставить перед API auth proxy. Публичные адреса из некоторых специальных диапазонов блокируются; DNS ответ с одним запрещённым IP отклоняется целиком. Нет persistent job queue или distributed agents.
