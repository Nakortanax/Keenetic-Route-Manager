# Changelog

## 0.2.0 — 2026-10-24

- Полная замена GUI с Tkinter на PySide6 / Qt в тёмном стиле, вдохновлённом интерфейсом Keenetic Racer.
- Пять разделов: обзор, IPv4-маршруты, сайты, импорт/экспорт, диагностика.
- Таблица `QTableView` с динамической фильтрацией для нескольких тысяч маршрутов.
- Сохранены парсеры маршрутов, Telnet-протокол, локальные подписи и безопасные точечные переключения сайтов из 0.1.7.
- Добавлен отдельный `RouterClient` без зависимостей от GUI; резервирование и повторное чтение перед сохранением.
- Заготовлена локальная сборка Windows EXE через PyInstaller и схема подключения к Forgejo.

**Note:** PySide6 GUI needs real Keenetic / Windows validation before public release. No automated build confirmed.
