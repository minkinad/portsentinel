# Инструкции для агентов

- README и `docs/ARCHITECTURE.md` задают реальные границы. Не добавляйте сетевые проверки без SSRF-анализа.
- CLI — `cmd/portsentinel`, сервер — `cmd/portsentinel-server`, настройки — `internal/config`, policy — `internal/security`, checks — `internal/diagnostics`, transport API — `internal/server`.
- Зависимости направлены от entrypoints к internal; diagnostics зависит от security target, server зависит от diagnostics. Не вводите общую mutable state.
- Новый Check реализует `Name`/`Run`; тесты должны использовать `httptest`, локальные адреса и явный `AllowPrivate`.
- Не следуйте редиректам на непроверенные адреса. Подключайтесь к pinned IP. Не логируйте полные URL с query-секретами. Ограничивайте время, параллельность и объём данных.
- Проверка: `make setup`, `make check`, `make build`, `make docker-build` при доступном Docker.
- Definition of Done: сценарий выполняется, security boundary покрыта тестом, формат отчёта совместим или версия обновлена, документация и roadmap соответствуют коду.
