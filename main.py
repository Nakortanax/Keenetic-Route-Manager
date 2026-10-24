"""Keenetic Route Manager v0.2.1 — Qt UI over the proven CLI routing core."""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import sys
from collections import Counter
from pathlib import Path

from PySide6.QtCore import Qt, QObject, Signal, QRunnable, QThreadPool, QAbstractTableModel, QSortFilterProxyModel, QModelIndex
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QFrame, QStackedWidget, QPushButton, QLabel, QLineEdit, QSpinBox, QComboBox,
    QTableView, QHeaderView, QFileDialog, QMessageBox, QDialog, QDialogButtonBox,
    QTableWidget, QTableWidgetItem, QCheckBox, QTextEdit, QAbstractItemView,
    QProgressBar, QSplitter, QSizePolicy, QInputDialog
)
from keenetic_manager.core import (Route, normalized_network, can_edit, add_command,
                                  delete_command, ordered_edit_commands, plan_add,
                                  parse_text_routes, save_export, export_text)
from keenetic_manager.site_routes import site_ip_status, plan_site_interface_change
from keenetic_manager.interface_choices import build_interface_choices, default_interface
from keenetic_manager.metadata import MetadataStore, normalize_domain, identify_network
from keenetic_manager.controller import RouterClient, resolve_site

VERSION = '0.2.1'

THEME = '''
/* Do not paint every QWidget: that creates dark rectangles behind text labels. */
QWidget { color:#d8e7f7; font-family:'Segoe UI',Arial; font-size:12px; }
QMainWindow, QWidget#appRoot, QWidget#contentRoot, QWidget#pageSurface,
QStackedWidget { background:#101b2a; }
/* Labels and check boxes show the background of their containing surface. */
QLabel { background:transparent; border:none; }
QCheckBox { background:transparent; }
QFrame#sidebar { background:#182435; border-right:1px solid #29384a; }
QFrame#topbar { background:#172335; border-bottom:1px solid #29394d; }
QFrame#panel, QFrame#statCard { background:#1b2a3d; border:1px solid #2d4258; border-radius:11px; }
QLabel#appTitle { font-size:19px; font-weight:800; color:#39bbf8; letter-spacing:1px; }
QLabel#pageTitle { font-size:21px; font-weight:750; color:#f3f8fe; }
QLabel#cardValue { font-size:26px; font-weight:750; color:#f4fbff; }
QLabel#muted, QLabel#caption { color:#8da5bd; }
QLabel#accent { color:#36c4f8; }
QLabel#good { color:#52deb0; }
QLabel#warning { color:#ffce78; }
QPushButton { background:#273a4f; border:1px solid #3a5069; border-radius:7px; color:#edf6ff; min-height:30px; padding:3px 13px; }
QPushButton:hover { background:#314b65; border-color:#4c97c9; }
QPushButton:pressed { background:#234e69; }
QPushButton:disabled { color:#74879b; background:#1e2a39; border-color:#2c3c4d; }
QPushButton#primary { color:#051b2c; background:#3cc1ef; border:1px solid #3cc1ef; font-weight:700; }
QPushButton#primary:hover { background:#7edbfd; }
QPushButton#danger { color:#ffc7c7; border-color:#6b434c; background:#422b38; }
QPushButton#nav { background:transparent; border:0; border-radius:6px; text-align:left; padding:9px 13px; min-height:29px; color:#b4cadc; font-weight:600; }
QPushButton#nav:hover { background:#253d53; color:#fff; }
QPushButton#nav[active="true"] { background:#133e58; color:#50ceff; border-left:3px solid #38c2f3; }
QLineEdit, QSpinBox, QComboBox { background:#101e2c; color:#e8f4ff; border:1px solid #385067; border-radius:6px; padding:7px 9px; min-height:22px; selection-background-color:#176c9d; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border:1px solid #38b9ea; }
QLineEdit:read-only { color:#9eb4c7; }
QComboBox QAbstractItemView { background:#1d3043; selection-background-color:#2375a6; color:#e6f1fa; }
QTableView, QTableWidget { background:#162537; alternate-background-color:#192a3d; border:1px solid #2d4054; border-radius:8px; color:#e6f2ff; gridline-color:#23384b; selection-background-color:#17658f; selection-color:#fff; }
QHeaderView::section { background:#24374b; color:#93c9e7; padding:10px 8px; border:0; border-bottom:1px solid #36526b; font-weight:600; }
QTableView::item { padding:7px 5px; }
QScrollBar:vertical { background:#1b2b3e; width:11px; }
QScrollBar::handle:vertical { background:#43566a; min-height:30px; border-radius:5px; }
QDialog { background:#172638; }
QTextEdit { border:1px solid #385067; border-radius:6px; background:#101d2d; padding:8px; }
QCheckBox { spacing:8px; }
QProgressBar { border:0; border-radius:3px; height:4px; background:#2b4055; }
QProgressBar::chunk { border-radius:3px; background:#36bdf1; }
QToolTip { background:#293d50; color:#fff; border:1px solid #5d7487; }
'''


def info(title, message, parent=None):
    QMessageBox.information(parent, title, str(message))


def warn(title, message, parent=None):
    QMessageBox.warning(parent, title, str(message))


def confirm(title, message, parent=None):
    return QMessageBox.question(parent, title, message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes


def heading(text, muted=''):
    block = QWidget(); block.setObjectName('headingBlock')
    box = QVBoxLayout(block); box.setContentsMargins(0,0,0,5); box.setSpacing(2)
    t = QLabel(text); t.setObjectName('pageTitle'); box.addWidget(t)
    if muted:
        label=QLabel(muted); label.setObjectName('muted'); label.setWordWrap(True); box.addWidget(label)
    return block


def panel():
    x=QFrame();x.setObjectName('panel');return x


class WorkerSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str)


class Worker(QRunnable):
    def __init__(self, task):
        super().__init__(); self.task=task;self.signals=WorkerSignals()
    def run(self):
        try: self.signals.finished.emit(self.task(self.signals.progress.emit))
        except Exception as exc: self.signals.failed.emit(f'{type(exc).__name__}: {exc}')


COLS=[('cidr','IPv4 / ПОДСЕТЬ'),('site','САЙТ / СЕРВИС'),('interface','ИНТЕРФЕЙС'),
      ('status','СТАТУС'),('auto','АВТО'),('metric','МЕТРИКА'),('owner','ВЛАДЕЛЕЦ СЕТИ'),('ptr','PTR'),('source','ИСТОЧНИК')]


class RouteModel(QAbstractTableModel):
    def __init__(self): super().__init__(); self.routes=[];self.interfaces={};self.metadata=None
    def update(self,routes,interfaces,metadata):
        self.beginResetModel();self.routes=list(routes);self.interfaces=interfaces;self.metadata=metadata;self.endResetModel()
    def rowCount(self,parent=QModelIndex()): return 0 if parent.isValid() else len(self.routes)
    def columnCount(self,parent=QModelIndex()): return len(COLS)
    def route(self,row): return self.routes[row]
    def value(self,row,col):
        r=self.routes[row]; key=COLS[col][0]
        note=self.metadata.get(r.cidr) if self.metadata else None
        if key=='cidr':return r.cidr
        if key=='site':return note.site_label if note else ''
        if key=='interface':return (r.interface or ('Шлюз: '+r.gateway))
        if key=='status':return 'Выключен' if r.disabled else 'Включён'
        if key=='auto':return 'Да' if r.auto else 'Нет'
        if key=='metric':return r.metric or '—'
        if key=='owner':return note.owner if note else ''
        if key=='ptr':return note.ptr if note else ''
        if key=='source':return note.source if note else ''
        return ''
    def data(self,index,role=Qt.DisplayRole):
        if not index.isValid():return None
        r=self.routes[index.row()]
        if role==Qt.DisplayRole:return self.value(index.row(),index.column())
        if role==Qt.ForegroundRole:
            if r.disabled:return QColor('#748da4')
            if index.column()==2 and r.interface.startswith('Wireguard'):return QColor('#53ccfa')
            if index.column()==3:return QColor('#55dcb0')
        if role==Qt.ToolTipRole:
            if index.column()==1 and self.metadata:
                n=self.metadata.get(r.cidr)
                return f'Источник: {n.source or "Не установлен"}\nPTR: {n.ptr}\nВладелец: {n.owner}'
            if index.column()==2:return self.interfaces.get(r.interface,r.interface)
        return None
    def headerData(self,section,orientation,role=Qt.DisplayRole):
        if orientation==Qt.Horizontal and role==Qt.DisplayRole:return COLS[section][1]
        return None


class RouteFilter(QSortFilterProxyModel):
    def __init__(self):super().__init__();self.needle='';self.iface='';self.setDynamicSortFilter(True)
    def set_search(self,text):self.needle=text.strip().casefold();self.invalidateFilter()
    def set_interface(self,iface):self.iface=iface;self.invalidateFilter()
    def filterAcceptsRow(self,row,parent):
        m=self.sourceModel();r=m.route(row)
        if self.iface and r.interface!=self.iface:return False
        if not self.needle:return True
        return any(self.needle in str(m.value(row,c)).casefold() for c in range(len(COLS))) or (self.needle in m.interfaces.get(r.interface,'').casefold())
    def lessThan(self,left,right):
        if left.column()==0:
            try:
                a=ipaddress.IPv4Network(self.sourceModel().route(left.row()).cidr)
                b=ipaddress.IPv4Network(self.sourceModel().route(right.row()).cidr)
                return (int(a.network_address),a.prefixlen)<(int(b.network_address),b.prefixlen)
            except ValueError:pass
        return str(self.sourceModel().data(left) or '').casefold()<str(self.sourceModel().data(right) or '').casefold()


class RouteDialog(QDialog):
    def __init__(self,parent,interfaces,current=None,pref=''):
        super().__init__(parent);self.setWindowTitle('IPv4 маршрут');self.setMinimumWidth(480);self.result=None
        lay=QVBoxLayout(self);lay.setSpacing(12)
        lay.addWidget(QLabel('IPv4 / подсеть (например, 185.244.36.22 или 1.2.3.0/24)'))
        self.net=QLineEdit(current.cidr if current else '');lay.addWidget(self.net)
        lay.addWidget(QLabel('Интерфейс'))
        self.iface=QComboBox();lay.addWidget(self.iface)
        for item in build_interface_choices(interfaces):self.iface.addItem(item.label,item.identifier)
        choice=current.interface if current else (pref or default_interface(interfaces))
        idx=self.iface.findData(choice)
        if idx>=0:self.iface.setCurrentIndex(idx)
        lay.addWidget(QLabel('Метрика (необязательно)'))
        self.metric=QLineEdit(current.metric if current else '');lay.addWidget(self.metric)
        self.auto=QCheckBox('Автоматически (auto)');self.auto.setChecked(current.auto if current else True);lay.addWidget(self.auto)
        buttons=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept_checked);buttons.rejected.connect(self.reject);lay.addWidget(buttons)
    def accept_checked(self):
        try:
            metric=self.metric.text().strip()
            if metric and (not metric.isdigit() or not 0<=int(metric)<=255):raise ValueError('Метрика от 0 до 255')
            iface=self.iface.currentData()
            if not iface:raise ValueError('Выбери интерфейс из списка Keenetic')
            r=Route(normalized_network(self.net.text().strip()),iface,self.auto.isChecked(),metric)
            if not can_edit(r):raise ValueError('Этот вид маршрута нельзя редактировать')
            self.result=r;self.accept()
        except ValueError as e:warn('Параметры маршрута',e,self)


class SiteDialog(QDialog):
    def __init__(self,parent,domain,ips,routes,interfaces,preferred):
        super().__init__(parent);self.setWindowTitle('Сайт — '+domain);self.resize(870,460)
        self.domain=domain;self.ips=ips;self.routes=routes;self.result=None
        lay=QVBoxLayout(self);lay.setSpacing(12)
        title=QLabel(domain);title.setObjectName('pageTitle');lay.addWidget(title)
        tip=QLabel('Найденные DNS IPv4 и наиболее специфичные статические маршруты. Политики Keenetic могут переопределять путь.')
        tip.setObjectName('muted');tip.setWordWrap(True);lay.addWidget(tip)
        self.table=QTableWidget(len(ips),4);self.table.setHorizontalHeaderLabels(['IPv4 сайта','Маршрут / маска','Интерфейс','Совпадений'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        lay.addWidget(self.table)
        for row,ip in enumerate(ips):
            status=site_ip_status(ip,routes)
            values=(ip,', '.join(sorted({r.cidr for r in status.best})) or 'Нет статического',status.label,str(len(status.matches)))
            for col,value in enumerate(values):
                cell=QTableWidgetItem(value);cell.setFlags(cell.flags()&~Qt.ItemIsEditable);self.table.setItem(row,col,cell)
        self.table.selectAll()
        line=QHBoxLayout();line.addWidget(QLabel('Перенаправить выбранные адреса через:'))
        self.iface=QComboBox();line.addWidget(self.iface,1)
        for opt in build_interface_choices(interfaces):self.iface.addItem(opt.label,opt.identifier)
        idx=self.iface.findData(preferred)
        if idx>=0:self.iface.setCurrentIndex(idx)
        lay.addLayout(line)
        hint=QLabel('Общие подсети /16, /24 не изменяем: создаём исключения /32 только для адресов сайта.')
        hint.setObjectName('warning');hint.setWordWrap(True);lay.addWidget(hint)
        buttons=QDialogButtonBox(QDialogButtonBox.Ok|QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText('Просмотреть изменения')
        buttons.accepted.connect(self.plan);buttons.rejected.connect(self.reject);lay.addWidget(buttons)
    def plan(self):
        ips=[self.ips[x.row()] for x in self.table.selectionModel().selectedRows()]
        if not ips:warn('Нет выбора','Выдели хотя бы один IPv4',self);return
        try:
            adds,removes,notes=plan_site_interface_change(ips,self.routes,self.iface.currentData())
            self.result=adds,removes,notes;self.accept()
        except ValueError as exc:warn('Небезопасное изменение',str(exc),self)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__();self.setWindowTitle(f'Keenetic Route Manager {VERSION}');self.resize(1460,880);self.setMinimumSize(1050,650)
        self.threadpool=QThreadPool.globalInstance();self.workers=[]
        self.routes=[];self.interfaces={};self.bad_lines=[];self.loaded=False;self.metadata=None;self.busy=False
        self.model=RouteModel();self.proxy=RouteFilter();self.proxy.setSourceModel(self.model)
        self._build_ui();self._show_page(0)

    def _build_ui(self):
        root=QWidget();root.setObjectName('appRoot');self.setCentralWidget(root);allbox=QHBoxLayout(root);allbox.setContentsMargins(0,0,0,0);allbox.setSpacing(0)
        sidebar=QFrame();sidebar.setObjectName('sidebar');sidebar.setFixedWidth(230);s=QVBoxLayout(sidebar);s.setContentsMargins(14,21,14,15);s.setSpacing(8)
        logo=QLabel('◈  KEENETIC ROUTES');logo.setObjectName('appTitle');s.addWidget(logo)
        sub=QLabel('ROUTE MANAGER  /  0.2.1');sub.setObjectName('muted');s.addWidget(sub);s.addSpacing(32)
        self.nav=[]
        for i,(sym,name) in enumerate([('▦','Обзор'),('☷','Маршруты'),('◉','Сайты'),('⇅','Импорт / экспорт'),('⚙','Диагностика')]):
            b=QPushButton(f' {sym}   {name}');b.setObjectName('nav');b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _,n=i:self._show_page(n));s.addWidget(b);self.nav.append(b)
        s.addStretch()
        divider=QFrame();divider.setFrameShape(QFrame.HLine);divider.setStyleSheet('color:#30485d');s.addWidget(divider)
        tip=QLabel('●  Подключение только в LAN\n     Пароль хранится в памяти');tip.setObjectName('muted');s.addWidget(tip)
        allbox.addWidget(sidebar)
        main=QWidget();main.setObjectName('contentRoot');m=QVBoxLayout(main);m.setContentsMargins(0,0,0,0);m.setSpacing(0);allbox.addWidget(main,1)
        top=QFrame();top.setObjectName('topbar');h=QHBoxLayout(top);h.setContentsMargins(22,12,22,12);h.setSpacing(9)
        h.addWidget(QLabel('РОУТЕР'));self.ip=QLineEdit('192.168.1.1');self.ip.setFixedWidth(130);h.addWidget(self.ip)
        h.addWidget(QLabel('ПОРТ'));self.port=QSpinBox();self.port.setRange(1,65535);self.port.setValue(23);self.port.setFixedWidth(82);h.addWidget(self.port)
        h.addWidget(QLabel('ЛОГИН'));self.user=QLineEdit('admin');self.user.setFixedWidth(104);h.addWidget(self.user)
        h.addWidget(QLabel('ПАРОЛЬ'));self.password=QLineEdit();self.password.setEchoMode(QLineEdit.Password);self.password.setFixedWidth(160);h.addWidget(self.password)
        h.addStretch()
        self.check_button=QPushButton('Проверить связь');self.check_button.clicked.connect(self.check_connection);h.addWidget(self.check_button)
        self.read_button=QPushButton('↻  Обновить маршруты');self.read_button.setObjectName('primary');self.read_button.clicked.connect(self.refresh);h.addWidget(self.read_button)
        m.addWidget(top)
        self.stack=QStackedWidget();m.addWidget(self.stack,1)
        self._build_dashboard();self._build_routes();self._build_sites();self._build_exports();self._build_diagnostics()
        footer=QFrame();footer.setObjectName('topbar');fl=QHBoxLayout(footer);fl.setContentsMargins(19,7,19,7)
        self.status=QLabel('Готово. Подключись к Keenetic и прочитай маршруты.');self.status.setObjectName('muted');fl.addWidget(self.status,1)
        self.busybar=QProgressBar();self.busybar.setFixedWidth(120);self.busybar.setVisible(False);fl.addWidget(self.busybar)
        m.addWidget(footer)

    def _stat(self,label):
        frame=QFrame();frame.setObjectName('statCard');layout=QVBoxLayout(frame);layout.setContentsMargins(21,18,18,19);layout.setSpacing(10)
        l=QLabel(label.upper());l.setObjectName('muted');layout.addWidget(l)
        value=QLabel('—');value.setObjectName('cardValue');layout.addWidget(value)
        return frame,value
    def _build_dashboard(self):
        page=QWidget();page.setObjectName('pageSurface');lay=QVBoxLayout(page);lay.setContentsMargins(25,24,25,23);lay.setSpacing(20)
        lay.addWidget(heading('Состояние маршрутизации','Проверяй конфигурацию Keenetic и используй безопасное управление маршрутами.'))
        stats=QHBoxLayout();stats.setSpacing(14);self.stat_widgets=[]
        for name in ('Маршрутов','Интерфейсов','Маршрутов VPN','Отключённых'):
            f,l=self._stat(name);stats.addWidget(f);self.stat_widgets.append(l)
        lay.addLayout(stats)
        inf=panel();ins=QVBoxLayout(inf);ins.setContentsMargins(24,24,24,25)
        big=QLabel('Сеть под контролем');big.setObjectName('pageTitle');ins.addWidget(big)
        d=QLabel('Маршруты и домены — в одном месте. Данные роутера читаются по Telnet, а подписи сайтов хранятся только на этом ПК.');d.setObjectName('muted');d.setWordWrap(True);ins.addWidget(d)
        ins.addSpacing(18)
        actions=QHBoxLayout()
        for label,callback in [('☷  Таблица маршрутов',lambda:self._show_page(1)),('◉  Найти сайт',self.find_site),('⇅  Экспорт',lambda:self._show_page(3))]:
            b=QPushButton(label);b.clicked.connect(callback);actions.addWidget(b)
        actions.addStretch();ins.addLayout(actions);lay.addWidget(inf)
        small=QLabel('Безопасность: перед записью создаётся резервная копия списка маршрутов; команды отправляются только после подтверждения.');small.setObjectName('muted');small.setWordWrap(True);lay.addWidget(small)
        lay.addStretch();self.stack.addWidget(page)
    def _build_routes(self):
        page=QWidget();page.setObjectName('pageSurface');lay=QVBoxLayout(page);lay.setContentsMargins(24,18,24,18);lay.setSpacing(13)
        lay.addWidget(heading('IPv4-маршруты','Сортировка и фильтрация тысяч записей без загрузки веб-интерфейса роутера.'))
        tools=QHBoxLayout();tools.setSpacing(9)
        for name,func,style in [('+ Маршрут',self.add_route,'primary'),('✎ Изменить',self.edit_route,''),('− Удалить',self.delete_route,'danger'),('◉ Найти сайт',self.find_site,''),('☰ Подписать',self.label_route,''),('⌕ Определить IP',self.enrich_route,'')]:
            b=QPushButton(name);b.clicked.connect(func)
            if style:b.setObjectName(style)
            tools.addWidget(b)
        tools.addStretch();lay.addLayout(tools)
        bar=QHBoxLayout();bar.addWidget(QLabel('ИНТЕРФЕЙС'))
        self.iface_filter=QComboBox();self.iface_filter.setMinimumWidth(250);self.iface_filter.addItem('Все интерфейсы','');self.iface_filter.currentIndexChanged.connect(lambda _:self.proxy.set_interface(self.iface_filter.currentData() or ''));bar.addWidget(self.iface_filter)
        bar.addSpacing(13);self.search=QLineEdit();self.search.setPlaceholderText('Поиск по IP, сайту, интерфейсу, владельцу сети…');self.search.textChanged.connect(self.proxy.set_search);bar.addWidget(self.search,1)
        self.visible=QLabel('0 записей');self.visible.setObjectName('muted');bar.addWidget(self.visible);lay.addLayout(bar)
        self.table=QTableView();self.table.setModel(self.proxy);self.table.setSortingEnabled(True);self.table.sortByColumn(0,Qt.AscendingOrder)
        self.table.setAlternatingRowColors(True);self.table.setSelectionBehavior(QAbstractItemView.SelectRows);self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.verticalHeader().hide();self.table.verticalHeader().setDefaultSectionSize(33)
        self.table.horizontalHeader().setStretchLastSection(True);self.table.horizontalHeader().setMinimumSectionSize(80)
        for idx,width in enumerate([170,240,160,110,80,96,200,210,155]): self.table.setColumnWidth(idx,width)
        self.table.doubleClicked.connect(lambda _:self.edit_route());lay.addWidget(self.table,1)
        self.proxy.rowsInserted.connect(lambda *_:self.update_visible())
        self.proxy.rowsRemoved.connect(lambda *_:self.update_visible())
        self.proxy.modelReset.connect(self.update_visible)
        self.stack.addWidget(page)
    def _build_sites(self):
        page=QWidget();page.setObjectName('pageSurface');lay=QVBoxLayout(page);lay.setContentsMargins(24,22,24,20)
        lay.addWidget(heading('Сайты и домены','Найди адреса домена и переключи точные IP-маршруты между ISP и VPN.'))
        f=panel();v=QVBoxLayout(f);v.setContentsMargins(24,24,24,24)
        v.addWidget(QLabel('ДОМЕН САЙТА'));self.domain=QLineEdit();self.domain.setPlaceholderText('например: nnmclub.to или www.zfilm.homes');v.addWidget(self.domain)
        b=QPushButton('◉  Найти IPv4 и существующие маршруты');b.setObjectName('primary');b.clicked.connect(self.find_site);v.addWidget(b)
        v.addSpacing(12)
        tip=QLabel('При смене интерфейса программа не переносит общие сети /16, /24. Для конкретного сайта создаются точные исключения /32. Сайт может использовать несколько адресов и CDN.');tip.setObjectName('muted');tip.setWordWrap(True);v.addWidget(tip)
        lay.addWidget(f);lay.addStretch();self.stack.addWidget(page)
    def _build_exports(self):
        page=QWidget();page.setObjectName('pageSurface');lay=QVBoxLayout(page);lay.setContentsMargins(24,22,24,20)
        lay.addWidget(heading('Импорт и экспорт','Предпросмотр изменений, сохранение локальных комментариев и совместимость с Keenetic BAT.'))
        for title,desc,label,func in [('Экспорт маршрутов','JSON / CSV с подписями, CLI, BAT (BAT не хранит подписи сайтов).','Экспортировать',self.export_routes),('Импорт IPv4','BAT, CLI или список CIDR; перед записью проверяются существующие маршруты.','Открыть файл',self.import_routes)]:
            box=panel();row=QHBoxLayout(box);row.setContentsMargins(22,18,22,18)
            texts=QVBoxLayout();texts.addWidget(QLabel(title));d=QLabel(desc);d.setObjectName('muted');d.setWordWrap(True);texts.addWidget(d);row.addLayout(texts,1)
            b=QPushButton(label);b.clicked.connect(func);row.addWidget(b);lay.addWidget(box)
        lay.addStretch();self.stack.addWidget(page)
    def _build_diagnostics(self):
        page=QWidget();page.setObjectName('pageSurface');lay=QVBoxLayout(page);lay.setContentsMargins(24,22,24,20)
        lay.addWidget(heading('Диагностика','Без вывода паролей, VPN-ключей и полного running-config.'))
        self.diagnostics=QTextEdit();self.diagnostics.setReadOnly(True)
        self.diagnostics.setPlainText('Keenetic Route Manager 0.2.1\nНет загруженных данных.\n')
        lay.addWidget(self.diagnostics,1)
        row=QHBoxLayout()
        for label,cb in [('Проверить Telnet',self.check_connection),('Скопировать диагностику',self.copy_diag)]:
            b=QPushButton(label);b.clicked.connect(cb);row.addWidget(b)
        row.addStretch();lay.addLayout(row);self.stack.addWidget(page)
    def _show_page(self,n):
        self.stack.setCurrentIndex(n)
        for i,b in enumerate(self.nav): b.setProperty('active','true' if i==n else 'false');b.style().unpolish(b);b.style().polish(b)
    def _credentials(self): return (self.ip.text().strip(),self.port.value(),self.user.text().strip(),self.password.text())
    def _run(self,task,callback,label):
        if self.busy:return
        self.busy=True;self.read_button.setEnabled(False);self.check_button.setEnabled(False)
        self.busybar.setVisible(True);self.busybar.setRange(0,0);self.status.setText(label)
        worker=Worker(task);self.workers.append(worker)
        def complete(value):
            self._done(worker)
            try:callback(value)
            except Exception as ex:warn('Обработка результата',str(ex),self)
        def fail(message):
            self._done(worker);self.status.setText('Ошибка: '+message);warn('Ошибка Keenetic',message,self)
        worker.signals.finished.connect(complete);worker.signals.failed.connect(fail)
        worker.signals.progress.connect(lambda msg:self.status.setText(msg))
        self.threadpool.start(worker)
    def _done(self,worker):
        self.busy=False;self.read_button.setEnabled(True);self.check_button.setEnabled(True);self.busybar.setVisible(False)
        if worker in self.workers:self.workers.remove(worker)
    def check_connection(self):
        creds=self._credentials();self._run(lambda p:RouterClient(*creds).ping(p),lambda _:self.status.setText('Связь с Keenetic подтверждена. Маршруты не изменены.'),'Проверяем Telnet…')
    def refresh(self):
        creds=self._credentials();self._run(lambda p:RouterClient(*creds).read(p),lambda result:self._accept(*result),'Читаем конфигурацию Keenetic…')
    def _accept(self,routes,interfaces,bad):
        self.routes=list(routes);self.interfaces=interfaces;self.bad_lines=list(bad)
        try:self.metadata=MetadataStore(MetadataStore.default_path(self.ip.text().strip()))
        except Exception as ex:self.metadata=None;warn('Локальные заметки',str(ex),self)
        self.loaded=bool(routes) and not bad
        self.model.update(self.routes,self.interfaces,self.metadata)
        self.iface_filter.blockSignals(True);self.iface_filter.clear();self.iface_filter.addItem('Все интерфейсы','')
        for name in sorted(set(r.interface for r in routes if r.interface)|set(interfaces)):
            self.iface_filter.addItem(f'{name}  ·  {interfaces.get(name,name)}',name)
        self.iface_filter.blockSignals(False);self.proxy.set_interface('');self.update_visible()
        counts=Counter(r.interface for r in routes)
        for lbl,value in zip(self.stat_widgets,(len(routes),len(counts),sum(n for name,n in counts.items() if name.lower().startswith('wireguard')),sum(r.disabled for r in routes))):lbl.setText(f'{value:,}'.replace(',',' '))
        safe_lines='\n'.join(x[:180] for x in bad[:8])
        self.diagnostics.setPlainText(f'KeeneticOS 5.2 / IPv4 static routes\nМаршрутов: {len(routes)}\nИнтерфейсов: {len(counts)}\nНе распознано строк: {len(bad)}\nСтатус записи: {"РАЗРЕШЕНО с подтверждением" if self.loaded else "ТОЛЬКО ПРОСМОТР"}\n\n'+('Неизвестные строки маршрутов (без ключей):\n'+safe_lines if bad else 'Все статические маршруты разобраны.'))
        self.status.setText(f'Прочитано {len(routes)} маршрутов / интерфейсов {len(counts)} / ошибок {len(bad)}. '+('Готово.' if self.loaded else 'Запись заблокирована.'))
        if bad:warn('Безопасный режим',f'Невозможно разобрать {len(bad)} строк. Только чтение и экспорт.\n{safe_lines}',self)
    def update_visible(self):
        if hasattr(self,'visible'):self.visible.setText(f'{self.proxy.rowCount()} записей')
    def _require(self):
        if self.busy:warn('Операция выполняется','Заверши текущую операцию.',self);return False
        if not self.loaded:
            warn('Сначала прочитай маршруты','Для изменений требуется полностью прочитать маршруты Keenetic без ошибок.',self);return False
        return True
    def _chosen(self):
        seen=set();rows=[]
        for idx in self.table.selectionModel().selectedRows():
            r=self.model.route(self.proxy.mapToSource(idx).row())
            if (r.cidr,r.interface) not in seen:rows.append(r);seen.add((r.cidr,r.interface))
        return rows
    def _preferred(self):return default_interface(self.interfaces,self.iface_filter.currentData() or '')
    def _apply(self,adds,removes,desc,after=None):
        if not self._require():return
        if not adds and not removes:info('Без изменений','Маршруты уже соответствуют выбранному интерфейсу.',self);return
        commands=ordered_edit_commands(adds,removes)
        preview='\n'.join(commands[:18])+('\n…' if len(commands)>18 else '')
        message=f'{desc}\n\nДобавить: {len(adds)} / Удалить: {len(removes)}\n\nКоманды Keenetic:\n{preview}\n\nБудет создан локальный резервный список маршрутов. Продолжить?'
        if not confirm('Подтверждение изменения маршрутов',message,self):return
        old=list(self.routes);credentials=self._credentials()
        def complete(result):
            routes,ifaces,backup=result;self._accept(routes,ifaces,[])
            if after:
                try:after()
                except Exception as ex:warn('Маршруты изменены; подпись не сохранена',str(ex),self)
            info('Маршруты сохранены',f'Изменения проверены повторным чтением.\nРезервная копия: {backup}',self)
        self._run(lambda progress:RouterClient(*credentials).apply(adds,removes,old,progress),complete,'Записываем и проверяем маршруты…')
    def add_route(self):
        if not self._require():return
        d=RouteDialog(self,self.interfaces,pref=self._preferred())
        if d.exec()==QDialog.Accepted:
            adds,_,conflicts=plan_add([d.result],self.routes)
            if conflicts and not confirm('Перекрытие','Найдено перекрытие с маршрутом другого интерфейса. Добавить более специфичный маршрут?',self):return
            self._apply(adds,[],f'Добавить маршрут {d.result.cidr}')
    def edit_route(self):
        if not self._require():return
        chosen=self._chosen()
        if len(chosen)!=1:warn('Выбор','Выдели один маршрут для редактирования.',self);return
        old=chosen[0]
        if not can_edit(old):warn('Защита','Этот маршрут нельзя редактировать автоматически.',self);return
        d=RouteDialog(self,self.interfaces,current=old)
        if d.exec()==QDialog.Accepted and d.result!=old:self._apply([d.result],[old],f'Изменить маршрут {old.cidr}')
    def delete_route(self):
        if not self._require():return
        routes=self._chosen()
        if not routes:return
        if any(not can_edit(r) for r in routes):warn('Защита','Среди выбранных есть защищённые маршруты.',self);return
        self._apply([],routes,f'Удалить выбранные маршруты: {len(routes)}')
    def find_site(self):
        if not self._require():return
        domain=self.domain.text().strip() if self.stack.currentIndex()==2 else ''
        if not domain:
            from PySide6.QtWidgets import QInputDialog
            domain,ok=QInputDialog.getText(self,'Сайт','Введите домен (без https://):')
            if not ok:return
        try:domain=normalize_domain(domain)
        except ValueError as ex:warn('Домен',str(ex),self);return
        def ready(ips):
            dlg=SiteDialog(self,domain,ips,self.routes,self.interfaces,self._preferred())
            if self.metadata:
                try:self.metadata.add_site(domain,ips);self.model.update(self.routes,self.interfaces,self.metadata)
                except Exception:pass
            if dlg.exec()==QDialog.Accepted:
                adds,removes,notes=dlg.result
                self._apply(adds,removes,domain+'\n'+'\n'.join(notes),after=lambda:self.metadata.add_site(domain,ips) if self.metadata else None)
        self._run(lambda progress:resolve_site(domain),ready,f'Определяем IPv4: {domain}…')
    def label_route(self):
        routes=self._chosen()
        if not routes:return
        from PySide6.QtWidgets import QInputDialog
        val,ok=QInputDialog.getText(self,'Подпись сайта','Сайт / сервис (только на этом ПК):')
        if ok and self.metadata:
            try:
                for r in routes:self.metadata.set_manual(r.cidr,val)
                self.model.update(self.routes,self.interfaces,self.metadata)
            except Exception as ex:warn('Локальная база',str(ex),self)
    def enrich_route(self):
        routes=self._chosen()
        if not routes:
            warn('Определение IP','Выдели маршруты для проверки PTR/RDAP.',self);return
        networks=list(dict.fromkeys(r.cidr for r in routes))
        if len(networks)>30:
            warn('Лимит','За один раз можно проверить не более 30 сетей.',self);return
        if not self.metadata:
            warn('Локальная база','Подписи недоступны. Прочитай маршруты повторно.',self);return
        if not confirm('PTR / RDAP',f'Внешним DNS/RDAP будут отправлены запросы для {len(networks)} адресов/сетей. Эти запросы могут раскрывать интерес к IP. Продолжить?',self):return
        def task(progress):
            result=[]
            for index,network in enumerate(networks,1):
                result.append((network,identify_network(network)))
                progress(f'PTR / RDAP: {index}/{len(networks)}')
            return result
        def ready(result):
            try:
                for network,data in result:
                    self.metadata.add_enrichment(network,ptr=data['ptr'],verified=data['verified'],owner=data['owner'])
                self.model.update(self.routes,self.interfaces,self.metadata)
                self.status.setText(f'Сведения проверены для {len(result)} адресов. PTR и владелец не доказывают принадлежность сайту.')
            except Exception as exc:warn('Локальная база',str(exc),self)
        self._run(task,ready,'Проверяем PTR и RDAP…')

    def export_routes(self):
        if not self.routes:warn('Нет данных','Сначала прочитай маршруты.',self);return
        path,_=QFileDialog.getSaveFileName(self,'Экспорт маршрутов','keenetic-routes.json','JSON (*.json);;CSV (*.csv);;Keenetic CLI (*.txt);;Keenetic BAT (*.bat)')
        if not path:return
        suffix=Path(path).suffix.lower();kind={'.json':'json','.csv':'csv','.txt':'cli','.bat':'bat'}.get(suffix,'json')
        try:
            if kind=='json' and self.metadata: content=self.metadata.to_json_export(self.routes)
            elif kind=='csv' and self.metadata:
                from io import StringIO
                out=StringIO();writer=csv.writer(out);writer.writerow(['network','interface','auto','metric','disabled','site','ptr','owner','source'])
                for r in self.routes:
                    n=self.metadata.get(r.cidr);writer.writerow([r.cidr,r.interface,r.auto,r.metric,r.disabled,n.site_label,n.ptr,n.owner,n.source])
                content=out.getvalue()
            else:content=export_text(self.routes,kind)
            Path(path).write_text(content,encoding='utf-8')
            info('Экспорт',f'Сохранено {len(self.routes)} записей: {path}',self)
        except Exception as ex:warn('Ошибка экспорта',str(ex),self)
    def import_routes(self):
        if not self._require():return
        path,_=QFileDialog.getOpenFileName(self,'Импорт IPv4','', 'Маршруты (*.bat *.txt);;Все файлы (*)')
        if not path:return
        try:raw=Path(path).read_text(encoding='utf-8-sig')
        except UnicodeDecodeError:raw=Path(path).read_text(encoding='cp1251')
        choices=build_interface_choices(self.interfaces)
        labels=[x.label for x in choices]
        chosen,ok=QInputDialog.getItem(self,'Интерфейс для импорта',
                                        'Выбери интерфейс Keenetic:',labels,0,False)
        if not ok:return
        by_label={x.label:x.identifier for x in choices}
        chosen_interface=by_label.get(chosen)
        if not chosen_interface:return
        rr,bad=parse_text_routes(raw,chosen_interface)
        if bad:warn('Файл содержит неподдерживаемые строки','\n'.join(bad[:8]),self);return
        adds,dupes,conflicts=plan_add(rr,self.routes)
        if len(adds)>1000:warn('Лимит','Раздели импорт на части до 1000 записей.',self);return
        if conflicts and not confirm('Перекрытие подсетей',f'Конфликтов: {len(conflicts)}. Продолжить с предварительным просмотром?',self):return
        self._apply(adds,[],f'Импорт {len(adds)} новых маршрутов; уже покрыты: {len(dupes)}')
    def copy_diag(self):QApplication.clipboard().setText(self.diagnostics.toPlainText());self.status.setText('Диагностика скопирована без ключей.')


def main():
    app=QApplication(sys.argv);app.setApplicationName('Keenetic Route Manager');app.setStyle('Fusion');app.setStyleSheet(THEME)
    font=QFont('Segoe UI',10);app.setFont(font)
    window=MainWindow();window.show();sys.exit(app.exec())


if __name__=='__main__':main()
