# Интеграция CI нового проекта — без вмешательства в рабочие сборки

Ориентир: `CI_AUTOMATION_GUIDE_2026-10-19.md` (библиотека владельца).

1. Использовать публичный GitHub `Nakortanax/Keenetic-Route-Manager`. **Не загружать** старые конфигурации Keenetic, local-data, маршруты и пароли.
2. Залить исходники в `bridge/keenetic-route-manager-qt-20261024` (или `main`, если создаётся новый репозиторий без автоматического CI; затем рабочие правки — в `bridge/*`). Защитить `main`, проверить содержимое `.gitignore`.
3. Добавить отдельный локальный bare mirror и соответствующий Forgejo remote; настроить **отдельный** Git Bridge timer, синхронизацию `bridge/*`.
4. Добавить **отдельный** доверенный Forgejo workflow в `ci/forgejo-windows`, ограниченный `source_branch`/`source_sha`, с проверкой HEAD SHA перед сборкой. Ветка `ci/*` не синхронизируется Git Bridge автоматически.
5. Runner `linux-build` через существующий безопасный gateway с общей блокировкой Windows-сборок направляет сборку на Windows-host, указанный в закрытой конфигурации; запускает `build_windows.ps1` через `pwsh`.
6. Проверить результаты: лог unittest, `dist/KeeneticRouteManager.exe`, `dist/KeeneticRouteManager.exe.sha256`, SHA-256 фактического файла и `COMMIT.txt`/`BRANCH.txt`.
7. **Не считать** HTTP 204 у Forgejo Actions успехом сборки. **Не публиковать** релиз или менять `main` автоматически.

**Текущий статус:** интеграция CI для Keenetic Route Manager не выполнена, Windows EXE ещё не собран. Данный файл — инструкция, не действующий workflow.
