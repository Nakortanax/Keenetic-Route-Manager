"""Optional Qt tab for KeeneticOS DNS-based routing.

Integrates with the existing asynchronous worker and shared Telnet credentials.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QLineEdit, QTextEdit, QCheckBox, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QSplitter, QFrame, QDialog, QDialogButtonBox,
    QMessageBox,
)
from .dns_routes import DnsClient, GLOBAL, plan_group, plan_rule
from .interface_choices import build_interface_choices


class DnsRoutingPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.setObjectName("pageSurface")
        self.main = main
        self.snapshot = None
        self.interfaces = {}
        self._loading = False
        self._build()

    @staticmethod
    def _text(value, muted=False):
        label = QLabel(value)
        label.setWordWrap(True)
        if muted:
            label.setObjectName("muted")
        return label

    @staticmethod
    def _panel():
        panel = QFrame()
        panel.setObjectName("panel")
        return panel

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 18, 22, 18)
        root.setSpacing(11)
        title = QLabel("DNS-маршрутизация")
        title.setObjectName("pageTitle")
        root.addWidget(title)
        root.addWidget(self._text(
            "Группы доменов и IPv4-подсетей KeeneticOS 5.x; привязка к общей таблице "
            "или отдельной политике PolicyN. Статические IP-маршруты не меняются.", True))
        top = QHBoxLayout()
        self.reload_btn = QPushButton("↻  Прочитать DNS-настройки")
        self.reload_btn.setObjectName("primary")
        self.reload_btn.clicked.connect(self.refresh)
        top.addWidget(self.reload_btn)
        self.count = self._text("Сначала прочитай настройки Keenetic", True)
        top.addWidget(self.count, 1)
        root.addLayout(top)

        splitter = QSplitter(Qt.Horizontal)
        left = self._panel()
        l = QVBoxLayout(left)
        l.setContentsMargins(15, 15, 15, 15)
        l.setSpacing(7)
        l.addWidget(self._text("ГРУППЫ ДОМЕНОВ"))
        self.groups = QComboBox()
        self.groups.currentIndexChanged.connect(self._select_group)
        l.addWidget(self.groups)
        l.addWidget(self._text("Имя группы (новую задайте латиницей)", True))
        self.group_name = QLineEdit()
        self.group_name.setPlaceholderText("DNS_WG2_NEW")
        l.addWidget(self.group_name)
        l.addWidget(self._text("Домены и IPv4-подсети — по одному в строке", True))
        self.includes = QTextEdit()
        self.includes.setPlaceholderText("instagram.com\ncdninstagram.com\n31.13.64.0/18")
        self.includes.setMinimumHeight(155)
        l.addWidget(self.includes, 3)
        l.addWidget(self._text("Исключения — по одному в строке", True))
        self.excludes = QTextEdit()
        self.excludes.setPlaceholderText("Например: example.com")
        self.excludes.setMinimumHeight(75)
        l.addWidget(self.excludes, 1)
        self.save_group = QPushButton("Сохранить список доменов")
        self.save_group.clicked.connect(self.save_group_clicked)
        l.addWidget(self.save_group)
        splitter.addWidget(left)

        right = self._panel()
        r = QVBoxLayout(right)
        r.setContentsMargins(15, 15, 15, 15)
        r.setSpacing(9)
        r.addWidget(self._text("ПРАВИЛО МАРШРУТИЗАЦИИ"))
        r.addWidget(self._text("Политика подключения", True))
        self.policy = QComboBox()
        self.policy.currentIndexChanged.connect(self._sync_rule)
        r.addWidget(self.policy)
        r.addWidget(self._text("Интерфейс (провайдер / VPN)", True))
        self.interface = QComboBox()
        r.addWidget(self.interface)
        self.auto = QCheckBox("Автоматически при доступности подключения (auto)")
        self.auto.setChecked(True)
        r.addWidget(self.auto)
        self.reject = QCheckBox("Исключительный маршрут (reject): без перехода на другой канал")
        self.reject.setChecked(True)
        r.addWidget(self.reject)
        row = QHBoxLayout()
        self.save_rule = QPushButton("Создать / изменить правило")
        self.save_rule.setObjectName("primary")
        self.save_rule.clicked.connect(self.save_rule_clicked)
        row.addWidget(self.save_rule)
        self.delete_rule = QPushButton("Удалить правило")
        self.delete_rule.setObjectName("danger")
        self.delete_rule.clicked.connect(self.delete_rule_clicked)
        row.addWidget(self.delete_rule)
        r.addLayout(row)
        r.addWidget(self._text("Существующие DNS-правила — выбери строку для редактирования", True))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Группа", "Политика", "Выход", "auto", "reject"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.cellClicked.connect(self._select_rule)
        r.addWidget(self.table, 1)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter, 1)
        root.addWidget(self._text(
            "Важно: клиент должен обращаться к DNS роутера (обычно 192.168.1.1). "
            "Частный DNS/DoH на устройстве может обходить правила. "
            "Смена назначения существующего правила может изменить его приоритет. "
            "Команды проверяются повторным чтением до сохранения.", True))

    def _select_group(self, _=None):
        if self._loading:
            return
        self._loading = True
        try:
            name = self.groups.currentData()
            group = self.snapshot.group(name) if self.snapshot and name else None
            self.group_name.setText(group.name if group else "")
            self.group_name.setReadOnly(bool(group))
            self.includes.setPlainText("\n".join(group.includes) if group else "")
            self.excludes.setPlainText("\n".join(group.excludes) if group else "")
        finally:
            self._loading = False
        self._sync_rule()

    def _sync_rule(self, _=None):
        if self._loading or not self.snapshot:
            return
        name = self.group_name.text().strip()
        scope = self.policy.currentData()
        found = next((x for x in self.snapshot.rules if x.group == name and x.scope == scope), None)
        if found:
            index = self.interface.findData(found.interface)
            if index >= 0:
                self.interface.setCurrentIndex(index)
            self.auto.setChecked(found.auto)
            self.reject.setChecked(found.reject)
        self.delete_rule.setEnabled(bool(found))

    def _select_rule(self, row, _col):
        if not self.snapshot or not (0 <= row < len(self.snapshot.rules)):
            return
        rule = self.snapshot.rules[row]
        group_index = self.groups.findData(rule.group)
        if group_index >= 0:
            self.groups.setCurrentIndex(group_index)
        scope_index = self.policy.findData(rule.scope)
        if scope_index >= 0:
            self.policy.setCurrentIndex(scope_index)
        self._sync_rule()

    def refresh(self):
        creds = self.main._credentials()
        self.main._run(
            lambda progress: DnsClient(*creds, journal=self.main.journal).read_dns(progress),
            lambda result: self.set_snapshot(*result),
            "Читаем DNS-группы и политики Keenetic…",
        )

    def set_snapshot(self, snapshot, interfaces):
        self.snapshot = snapshot
        self.interfaces = interfaces
        self._loading = True
        try:
            previous_group = self.groups.currentData()
            previous_scope = self.policy.currentData()
            self.groups.clear()
            self.groups.addItem("＋ Создать новую группу", "")
            for group in snapshot.groups:
                self.groups.addItem(f"{group.name} ({len(group.includes)} записей)", group.name)
            index = self.groups.findData(previous_group)
            self.groups.setCurrentIndex(index if index >= 0 else (1 if snapshot.groups else 0))
            self.policy.clear()
            self.policy.addItem("Общая таблица — dns-proxy", GLOBAL)
            for policy in snapshot.policies:
                self.policy.addItem(policy, policy)
            index = self.policy.findData(previous_scope)
            self.policy.setCurrentIndex(index if index >= 0 else max(0, self.policy.findData("Policy1")))
            self.interface.clear()
            for choice in build_interface_choices(interfaces):
                self.interface.addItem(choice.label, choice.identifier)
            self.table.setRowCount(len(snapshot.rules))
            for row, rule in enumerate(snapshot.rules):
                for col, value in enumerate((rule.group, rule.scope, rule.interface,
                                             "Да" if rule.auto else "Нет", "Да" if rule.reject else "Нет")):
                    self.table.setItem(row, col, QTableWidgetItem(value))
            self.count.setText(
                f"Групп: {len(snapshot.groups)} · правил: {len(snapshot.rules)} · "
                f"политик: {len(snapshot.policies)}" +
                (f" · ошибки разбора: {len(snapshot.errors)} — запись запрещена" if snapshot.errors else ""))
            can_write = not snapshot.errors
            self.save_group.setEnabled(can_write)
            self.save_rule.setEnabled(can_write)
        finally:
            self._loading = False
        self._select_group()
        self.main.status.setText("DNS-конфигурация прочитана." if not snapshot.errors else "DNS-конфигурация содержит неизвестные строки: только чтение.")
        if snapshot.errors:
            QMessageBox.warning(self, "Безопасный режим", "\n".join(snapshot.errors[:12]))

    def _require(self):
        if self.main.busy or self.snapshot is None:
            QMessageBox.warning(self, "DNS-маршрутизация", "Сначала прочитай DNS-настройки Keenetic и дождись завершения операций.")
            return False
        return True

    def save_group_clicked(self):
        if not self._require():
            return
        try:
            plan = plan_group(self.snapshot, self.group_name.text().strip(),
                              self.includes.toPlainText(), self.excludes.toPlainText())
        except ValueError as exc:
            QMessageBox.warning(self, "Проверь список", str(exc))
            return
        self._apply(plan)

    def save_rule_clicked(self):
        if not self._require():
            return
        try:
            plan = plan_rule(self.snapshot, self.group_name.text().strip(),
                             self.policy.currentData(), self.interface.currentData() or "",
                             self.auto.isChecked(), self.reject.isChecked())
        except ValueError as exc:
            QMessageBox.warning(self, "Проверь правило", str(exc))
            return
        self._apply(plan)

    def delete_rule_clicked(self):
        if not self._require():
            return
        try:
            plan = plan_rule(self.snapshot, self.group_name.text().strip(),
                             self.policy.currentData(), remove=True)
        except ValueError as exc:
            QMessageBox.warning(self, "Проверь правило", str(exc))
            return
        self._apply(plan)

    def _apply(self, plan):
        if not plan.ops:
            QMessageBox.information(self, "DNS-маршрутизация", "Изменений нет.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Подтверждение DNS-изменений")
        dialog.resize(780, 520)
        body = QVBoxLayout(dialog)
        body.addWidget(self._text(
            f"{plan.label}. Перед записью будет создан локальный резерв, затем "
            "выполнено повторное чтение. При ошибке — попытка отката без сохранения."))
        code = QTextEdit()
        code.setReadOnly(True)
        code.setPlainText(plan.preview() + "\n\n[после проверки] system configuration save")
        body.addWidget(code)
        buttons = QDialogButtonBox(QDialogButtonBox.Yes | QDialogButtonBox.No)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        body.addWidget(buttons)
        if dialog.exec() != QDialog.Accepted:
            return
        creds = self.main._credentials()
        old = self.snapshot
        self.main._run(
            lambda progress: DnsClient(*creds, journal=self.main.journal).apply_dns(old, plan, progress),
            self._applied,
            "Записываем и проверяем DNS-маршруты…",
        )

    def _applied(self, result):
        snapshot, interfaces, backup = result
        self.set_snapshot(snapshot, interfaces)
        QMessageBox.information(self, "Готово", "Изменения проверены и сохранены.\nРезервная копия:\n" + backup)