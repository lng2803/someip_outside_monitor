import datetime
import ipaddress
import json
import os
import socket
import struct
import sys
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional

# Ensure both pc_monitor directory and repository root are on sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_current_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

try:
    from pc_monitor.someip_decoder import (
        MessageType,
        ReturnCode,
        SdEntryType,
        SdOptionType,
        decode_sd,
        decode_someip,
        format_hex_dump,
        interpret_payload,
    )
except ImportError:
    from someip_decoder import (
        MessageType,
        ReturnCode,
        SdEntryType,
        SdOptionType,
        decode_sd,
        decode_someip,
        format_hex_dump,
        interpret_payload,
    )

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

CONTROL_PORT = 47000
TELEMETRY_PORT = 47001
MAX_ROWS = 5000


def _get_asset_path(relative_path: str) -> str:
    """Return the absolute path to an asset file.

    Works both when running from source and when bundled with PyInstaller
    (where ``sys._MEIPASS`` points to the temporary extraction directory).
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base = sys._MEIPASS  # type: ignore[attr-defined]
    else:
        # Running from source: assets/ lives two levels up from this file
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)


WHITE_STYLESHEET = """
QWidget {
    background: #ffffff;
    color: #202124;
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 10pt;
}
QLineEdit, QComboBox {
    background: #ffffff;
    color: #202124;
    border: 1px solid #c9cdd2;
    border-radius: 5px;
    padding: 5px 8px;
    selection-background-color: #cfe3ff;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #1a73e8;
}
QPushButton {
    background: #f5f7fa;
    color: #202124;
    border: 1px solid #c9cdd2;
    border-radius: 5px;
    padding: 6px 12px;
    font-weight: 500;
}
QPushButton:hover {
    background: #eaf2ff;
    border-color: #8ab4f8;
    color: #1a73e8;
}
QPushButton:pressed {
    background: #d8e7ff;
}
QPushButton:disabled {
    background: #f1f3f4;
    color: #9aa0a6;
    border-color: #dadce0;
}
QTabWidget::pane {
    border: 1px solid #d9dde3;
    border-radius: 4px;
    background: #ffffff;
}
QTabBar::tab {
    background: #f1f3f4;
    color: #5f6368;
    padding: 8px 16px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
    font-weight: 500;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #1a73e8;
    border-bottom: 2px solid #1a73e8;
}
QTabBar::tab:hover:!selected {
    background: #e8eaed;
    color: #202124;
}
QTableWidget, QTreeWidget {
    background: #ffffff;
    alternate-background-color: #f8f9fa;
    color: #202124;
    gridline-color: #e0e3e7;
    border: 1px solid #d9dde3;
    selection-background-color: #cce4ff;
    selection-color: #1a365d;
}
QHeaderView::section {
    background: #f1f3f4;
    color: #202124;
    padding: 6px 5px;
    border: 0;
    border-right: 1px solid #d9dde3;
    border-bottom: 1px solid #d9dde3;
    font-weight: 600;
}
QPlainTextEdit {
    background: #fdfdfd;
    color: #202124;
    border: 1px solid #d9dde3;
    border-radius: 4px;
}
QSplitter::handle {
    background: #e0e3e7;
}
QSplitter::handle:horizontal {
    width: 4px;
}
QSplitter::handle:vertical {
    height: 4px;
}
QCheckBox {
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
}
QLabel {
    background: transparent;
}
"""


class TelemetryWorker(QObject):
    message = Signal(dict)
    error = Signal(str)

    def __init__(self, listen_ip="0.0.0.0"):
        super().__init__()
        self.listen_ip = listen_ip
        self.running = False
        self.sock = None
        self.thread = None

    def start(self, listen_ip=None):
        if self.running:
            return
        if listen_ip:
            self.listen_ip = listen_ip
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.listen_ip, TELEMETRY_PORT))
            sock.settimeout(0.5)
            self.sock = sock
        except OSError as exc:
            self.error.emit(
                f"Cannot listen on {self.listen_ip}:{TELEMETRY_PORT}: {exc}"
            )
            return

        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.error.emit(
            f"Telemetry listener started on {self.listen_ip}:{TELEMETRY_PORT}"
        )

    def _loop(self):
        while self.running:
            sock = self.sock
            if sock is None:
                break
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                msg = json.loads(data.decode("utf-8", errors="replace"))
                if isinstance(msg, dict):
                    msg["_agent"] = addr[0]
                    self.message.emit(msg)
                else:
                    self.error.emit(f"Telemetry from {addr[0]} was not a JSON object")
            except json.JSONDecodeError:
                self.error.emit(f"Invalid telemetry JSON from {addr[0]}")

    def stop(self):
        self.running = False
        sock = self.sock
        self.sock = None
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)


class MainWindow(QMainWindow):
    PACKET_COLUMNS = [
        "#",
        "Time",
        "Type",
        "Transport",
        "Source",
        "Destination",
        "Service ID",
        "Method / Event",
        "Message Type",
        "Return Code",
        "Client / Session",
        "Length",
        "Summary",
    ]

    SERVICES_COLUMNS = [
        "Service ID",
        "Instance ID",
        "Major",
        "Minor",
        "Provider Endpoint",
        "Protocol",
        "TTL (s)",
        "Status",
        "Last Seen",
        "SBC Agent",
    ]

    SUBSCRIPTIONS_COLUMNS = [
        "Service ID",
        "Instance ID",
        "Eventgroup ID",
        "Subscriber Endpoint",
        "Initial Data",
        "TTL (s)",
        "Status",
        "Last Seen",
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOME/IP Detailed Protocol Analyzer & Monitor")
        self.setWindowIcon(QIcon(_get_asset_path(os.path.join("assets", "icon.ico"))))
        self.resize(1500, 880)
        self.setStyleSheet(WHITE_STYLESHEET)


        self.worker = TelemetryWorker()
        self.worker.message.connect(self.handle_message)
        self.worker.error.connect(self.log)

        # In-memory storage for packets and discovered services
        self.packets_data: List[Dict[str, Any]] = []
        self.services_catalog: Dict[str, Dict[str, Any]] = {}
        self.subscriptions_catalog: Dict[str, Dict[str, Any]] = {}

        # Counters
        self.total_packets_count = 0
        self.someip_count = 0
        self.sd_count = 0
        self.notification_count = 0
        self.request_count = 0
        self.response_count = 0
        self.error_code_count = 0

        # Rate tracking
        self.recent_packet_times: List[float] = []

        self._build_ui()

        # Timer to refresh rate and service TTLs
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._periodic_check)
        self.timer.start(1000)

    def _build_ui(self):
        root = QWidget()
        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(8)

        # 1. Top Connection & Control Bar
        ctrl_frame = QFrame()
        ctrl_frame.setFrameShape(QFrame.StyledPanel)
        ctrl_layout = QHBoxLayout(ctrl_frame)
        ctrl_layout.setContentsMargins(10, 8, 10, 8)
        ctrl_layout.setSpacing(10)

        self.agent_ip = QLineEdit("192.168.1.55")
        self.agent_ip.setPlaceholderText("SBC IP (e.g. 192.168.1.55)")
        self.agent_ip.setFixedWidth(130)

        self.pc_listen_ip = QLineEdit("0.0.0.0")
        self.pc_listen_ip.setPlaceholderText("PC Listen IP")
        self.pc_listen_ip.setFixedWidth(110)

        self.capture_filter = QLineEdit("(udp or tcp) and not (port 47000 or port 47001)")
        self.capture_filter.setPlaceholderText("BPF filter, e.g. (udp or tcp) and not (port 47000 or port 47001)")

        ctrl_layout.addWidget(QLabel("<b>SBC IP:</b>"))
        ctrl_layout.addWidget(self.agent_ip)
        ctrl_layout.addWidget(QLabel("<b>Listen IP:</b>"))
        ctrl_layout.addWidget(self.pc_listen_ip)
        ctrl_layout.addWidget(QLabel("<b>Filter:</b>"))
        ctrl_layout.addWidget(self.capture_filter, 1)

        self.listen_button = QPushButton("Start listener")
        self.listen_button.clicked.connect(self.start_listener)
        ctrl_layout.addWidget(self.listen_button)

        for label, cmd in [
            ("Start capture", "START"),
            ("Stop capture", "STOP"),
            ("Refresh services", "GET_SERVICES"),
        ]:
            b = QPushButton(label)
            b.clicked.connect(lambda checked=False, c=cmd: self.send_command(c))
            ctrl_layout.addWidget(b)

        apply_btn = QPushButton("Apply filter")
        apply_btn.clicked.connect(self.apply_filter)
        ctrl_layout.addWidget(apply_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_all)
        ctrl_layout.addWidget(clear_btn)

        export_btn = QPushButton("Export JSON")
        export_btn.clicked.connect(self.export_packets)
        ctrl_layout.addWidget(export_btn)

        import_btn = QPushButton("Import JSON")
        import_btn.clicked.connect(self.import_packets)
        ctrl_layout.addWidget(import_btn)

        main_layout.addWidget(ctrl_frame)

        # 2. Main Tabbed Area
        self.tabs = QTabWidget()

        # Tab 1: Live Packets & Dissection
        self.tab_packets = QWidget()
        self._build_packets_tab()
        self.tabs.addTab(self.tab_packets, "Live Packets & Dissection")

        # Tab 2: Discovered Services
        self.tab_services = QWidget()
        self._build_services_tab()
        self.tabs.addTab(self.tab_services, "Discovered Services (Catalog)")

        # Tab 3: Eventgroups & Subscriptions
        self.tab_subscriptions = QWidget()
        self._build_subscriptions_tab()
        self.tabs.addTab(self.tab_subscriptions, "Eventgroups & Subscriptions")

        # Tab 4: Statistics
        self.tab_stats = QWidget()
        self._build_stats_tab()
        self.tabs.addTab(self.tab_stats, "Statistics & Metrics")

        # Tab 5: Agent Logs
        self.tab_logs = QWidget()
        self._build_logs_tab()
        self.tabs.addTab(self.tab_logs, "Agent Logs")

        main_layout.addWidget(self.tabs, 1)

        # Status Bar / Footer
        self.status_label = QLabel("Listener not started")
        self.status_label.setStyleSheet("color: #5f6368; font-size: 9pt;")
        main_layout.addWidget(self.status_label)

        self.setCentralWidget(root)

    def _build_packets_tab(self):
        layout = QVBoxLayout(self.tab_packets)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        # Filter bar
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(8)

        filter_bar.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by any keyword, IP, Service ID, Method...")
        self.search_input.textChanged.connect(self._apply_table_filters)
        filter_bar.addWidget(self.search_input, 2)

        filter_bar.addWidget(QLabel("Service:"))
        self.filter_service = QLineEdit()
        self.filter_service.setPlaceholderText("e.g. 0x1234")
        self.filter_service.setFixedWidth(90)
        self.filter_service.textChanged.connect(self._apply_table_filters)
        filter_bar.addWidget(self.filter_service)

        filter_bar.addWidget(QLabel("Type:"))
        self.filter_type_combo = QComboBox()
        self.filter_type_combo.addItems([
            "All Types",
            "SOME/IP Only",
            "SOME/IP-SD Only",
            "REQUEST",
            "RESPONSE",
            "NOTIFICATION",
            "ERRORS",
        ])
        self.filter_type_combo.currentIndexChanged.connect(self._apply_table_filters)
        filter_bar.addWidget(self.filter_type_combo)

        self.chk_autoscroll = QCheckBox("Auto-scroll")
        self.chk_autoscroll.setChecked(True)
        filter_bar.addWidget(self.chk_autoscroll)

        self.chk_pause = QCheckBox("Pause View")
        filter_bar.addWidget(self.chk_pause)

        layout.addLayout(filter_bar)

        # Vertical Splitter: Packets Table (top) and Dissection Inspector (bottom)
        v_splitter = QSplitter(Qt.Vertical)

        # Packets Table
        self.table = QTableWidget(0, len(self.PACKET_COLUMNS))
        self.table.setHorizontalHeaderLabels(self.PACKET_COLUMNS)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_packet_selected)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        widths = [45, 85, 90, 75, 150, 150, 95, 120, 110, 85, 130, 65, 240]
        for idx, w in enumerate(widths):
            self.table.setColumnWidth(idx, w)

        v_splitter.addWidget(self.table)

        # Horizontal Splitter: Inspector Tree (left) and Hex Dump (right)
        h_splitter = QSplitter(Qt.Horizontal)

        # Left: Dissection Tree
        inspector_box = QGroupBox("Packet Dissection Details")
        tree_layout = QVBoxLayout(inspector_box)
        tree_layout.setContentsMargins(4, 4, 4, 4)

        self.tree_inspector = QTreeWidget()
        self.tree_inspector.setHeaderLabels(["Field", "Value"])
        self.tree_inspector.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree_inspector.header().setStretchLastSection(True)
        tree_layout.addWidget(self.tree_inspector)
        h_splitter.addWidget(inspector_box)

        # Right: Hex Dump & Payload Inspector
        hex_box = QGroupBox("Raw Payload Hex & Interpretations")
        hex_layout = QVBoxLayout(hex_box)
        hex_layout.setContentsMargins(4, 4, 4, 4)

        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        mono_font = QFont("Consolas" if sys.platform == "win32" else "Monospace", 9)
        self.hex_view.setFont(mono_font)
        self.hex_view.setPlaceholderText("Raw packet hex dump (Offset | Hex | ASCII)...")
        hex_layout.addWidget(self.hex_view, 2)

        self.interp_table = QTableWidget(0, 2)
        self.interp_table.setHorizontalHeaderLabels(["Data Interpretation", "Decoded Value"])
        self.interp_table.horizontalHeader().setStretchLastSection(True)
        self.interp_table.verticalHeader().setVisible(False)
        self.interp_table.setMaximumHeight(140)
        hex_layout.addWidget(self.interp_table, 1)

        h_splitter.addWidget(hex_box)
        h_splitter.setSizes([750, 650])

        v_splitter.addWidget(h_splitter)
        v_splitter.setSizes([420, 320])

        layout.addWidget(v_splitter)

    def _build_services_tab(self):
        layout = QVBoxLayout(self.tab_services)
        self.services_table = QTableWidget(0, len(self.SERVICES_COLUMNS))
        self.services_table.setHorizontalHeaderLabels(self.SERVICES_COLUMNS)
        self.services_table.setAlternatingRowColors(True)
        self.services_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.services_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.services_table.verticalHeader().setVisible(False)
        header = self.services_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        widths = [110, 110, 70, 70, 180, 80, 80, 90, 140, 130]
        for idx, w in enumerate(widths):
            self.services_table.setColumnWidth(idx, w)
        layout.addWidget(self.services_table)

    def _build_subscriptions_tab(self):
        layout = QVBoxLayout(self.tab_subscriptions)
        self.subscriptions_table = QTableWidget(0, len(self.SUBSCRIPTIONS_COLUMNS))
        self.subscriptions_table.setHorizontalHeaderLabels(self.SUBSCRIPTIONS_COLUMNS)
        self.subscriptions_table.setAlternatingRowColors(True)
        self.subscriptions_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.subscriptions_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.subscriptions_table.verticalHeader().setVisible(False)
        header = self.subscriptions_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        layout.addWidget(self.subscriptions_table)

    def _build_stats_tab(self):
        layout = QVBoxLayout(self.tab_stats)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        self.stats_labels: Dict[str, QLabel] = {}
        metrics = [
            ("Total Packets Captured", "0"),
            ("SOME/IP Messages", "0"),
            ("SOME/IP-SD Packets", "0"),
            ("Notifications (Events)", "0"),
            ("Requests", "0"),
            ("Responses", "0"),
            ("Errors (Return Code != E_OK)", "0"),
            ("Discovered Services Count", "0"),
            ("Current Throughput", "0.0 pkts/sec"),
        ]

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        for name, default_val in metrics:
            lbl = QLabel(default_val)
            lbl.setStyleSheet("font-size: 11pt; font-weight: bold; color: #1a73e8;")
            self.stats_labels[name] = lbl
            form.addRow(f"<b>{name}:</b>", lbl)

        layout.addLayout(form)
        layout.addStretch()

    def _build_logs_tab(self):
        layout = QVBoxLayout(self.tab_logs)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        self.log_view.setPlaceholderText("Agent status and application logs...")
        layout.addWidget(self.log_view)

    def log(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{timestamp}] {message}")

    def start_listener(self):
        listen_ip = self.pc_listen_ip.text().strip() or "0.0.0.0"
        self.worker.start(listen_ip)
        if self.worker.running:
            self.status_label.setText(
                f"Listening for SBC telemetry on {listen_ip}:{TELEMETRY_PORT}"
            )
            self.listen_button.setEnabled(False)

    def send_command(self, command: str):
        agent_ip = self.agent_ip.text().strip()
        if not agent_ip:
            QMessageBox.warning(self, "Missing IP", "Enter the SBC Agent IP.")
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(command.encode("utf-8"), (agent_ip, CONTROL_PORT))
            self.log(f"Sent command {command!r} to {agent_ip}:{CONTROL_PORT}")
        except OSError as exc:
            self.log(f"Failed to send command to {agent_ip}: {exc}")

    def apply_filter(self):
        expression = self.capture_filter.text().strip()
        if not expression:
            QMessageBox.warning(self, "Missing filter", "Enter a capture filter.")
            return
        self.send_command("SET_FILTER " + expression)

    def clear_all(self):
        self.table.setRowCount(0)
        self.packets_data.clear()
        self.tree_inspector.clear()
        self.hex_view.clear()
        self.interp_table.setRowCount(0)
        self.total_packets_count = 0
        self.someip_count = 0
        self.sd_count = 0
        self.notification_count = 0
        self.request_count = 0
        self.response_count = 0
        self.error_code_count = 0
        self._update_stats_display()
        self.log("Packets and inspector cleared")

    def export_packets(self):
        if not self.packets_data:
            QMessageBox.information(self, "Export", "No packets to export.")
            return
        default_name = f"someip_capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Save Captured Packets", default_name, "JSON Files (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.packets_data, f, indent=2, ensure_ascii=False)
            self.log(f"Exported {len(self.packets_data)} packets to {path}")
            QMessageBox.information(self, "Export Successful", f"Saved {len(self.packets_data)} packets.")
        except Exception as exc:
            self.log(f"Export failed: {exc}")
            QMessageBox.critical(self, "Export Failed", str(exc))

    def import_packets(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Captured Packets JSON", "", "JSON Files (*.json);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                packets = data.get("packets", []) if "packets" in data else [data]
            elif isinstance(data, list):
                packets = [p for p in data if isinstance(p, dict)]
            else:
                raise ValueError("JSON file root must be a list of packets or a packet object.")

            if not packets:
                QMessageBox.information(self, "Import", "No valid packet records found in file.")
                return

            reply = QMessageBox.question(
                self,
                "Import Options",
                f"Found {len(packets)} packets to import.\n\n"
                "Clear current packets and catalog before importing?\n"
                "(Choose 'Yes' to replace existing data, 'No' to append)",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Yes,
            )
            if reply == QMessageBox.Cancel:
                return

            if reply == QMessageBox.Yes:
                self.clear_all()
                self.services_catalog.clear()
                self.subscriptions_catalog.clear()
                self._refresh_services_table()
                self._refresh_subscriptions_table()

            # Pause autoscroll/view temporarily to speed up batch insertion
            self.table.setUpdatesEnabled(False)
            try:
                for pkt in packets:
                    self.total_packets_count += 1
                    pkt_data = dict(pkt)
                    if "_id" not in pkt_data:
                        pkt_data["_id"] = self.total_packets_count
                    if "_rx_time" not in pkt_data:
                        pkt_data["_rx_time"] = time.strftime("%H:%M:%S")

                    proto = str(pkt_data.get("protocol", "")).upper()
                    m_type = str(pkt_data.get("type", "")).lower()
                    is_sd = (m_type == "sd_packet") or (proto == "SOME/IP-SD")

                    if is_sd:
                        self.sd_count += 1
                        self._handle_sd_telemetry(pkt_data)
                    else:
                        self.someip_count += 1
                        self._handle_someip_telemetry(pkt_data)

                    self.packets_data.append(pkt_data)
                    if len(self.packets_data) > MAX_ROWS:
                        self.packets_data.pop(0)

                    self._insert_packet_row(pkt_data)
            finally:
                self.table.setUpdatesEnabled(True)

            self._apply_table_filters()
            self._update_stats_display()

            self.log(f"Imported {len(packets)} packets from {path}")
            QMessageBox.information(
                self,
                "Import Successful",
                f"Successfully imported {len(packets)} packets from:\n{path}",
            )
        except Exception as exc:
            self.log(f"Import failed: {exc}")
            QMessageBox.critical(self, "Import Failed", f"Failed to import JSON file:\n{exc}")


    def _periodic_check(self):
        now = time.time()
        # Clean packet rate timestamps
        self.recent_packet_times = [t for t in self.recent_packet_times if now - t <= 2.0]
        rate = len(self.recent_packet_times) / 2.0
        if "Current Throughput" in self.stats_labels:
            self.stats_labels["Current Throughput"].setText(f"{rate:.1f} pkts/sec")

        # Update service active status based on TTL expiration
        now_dt = datetime.datetime.now()
        for key, svc in list(self.services_catalog.items()):
            if svc.get("active") and svc.get("ttl", 0) > 0:
                elapsed = (now_dt - svc["last_seen_dt"]).total_seconds()
                if elapsed > svc["ttl"]:
                    svc["active"] = False
                    self._refresh_services_table()

    def handle_message(self, msg: Dict[str, Any]):
        msg_type = str(msg.get("type", "")).lower()
        agent_ip = str(msg.get("_agent", ""))
        now_str = time.strftime("%H:%M:%S")

        if msg_type == "status":
            message = str(msg.get("message", "Agent status"))
            capture = msg.get("capture_enabled")
            backend = msg.get("backend", "")
            status_text = f"{message} | agent={agent_ip}"
            if backend:
                status_text += f" | backend={backend}"
            self.status_label.setText(status_text)
            self.log(f"Agent {agent_ip}: {message}")
            return

        # Record arrival time for rate
        self.recent_packet_times.append(time.time())
        self.total_packets_count += 1

        # Normalized packet structure
        pkt_data = dict(msg)
        pkt_data["_rx_time"] = now_str
        pkt_data["_id"] = self.total_packets_count
        pkt_data["_agent"] = agent_ip

        # Check for SD packet vs standard SOME/IP packet
        is_sd = (msg_type == "sd_packet") or (
            str(msg.get("protocol", "")).upper() == "SOME/IP-SD"
        )
        if is_sd:
            self.sd_count += 1
            self._handle_sd_telemetry(pkt_data)
        elif msg_type == "packet":
            self.someip_count += 1
            self._handle_someip_telemetry(pkt_data)
        elif msg_type == "service":
            # Legacy service snapshot from agent
            self._handle_legacy_service(pkt_data)
            return

        self.packets_data.append(pkt_data)
        if len(self.packets_data) > MAX_ROWS:
            self.packets_data.pop(0)

        # Update table if view is not paused
        if not self.chk_pause.isChecked():
            self._insert_packet_row(pkt_data)

        self._update_stats_display()

    def _handle_sd_telemetry(self, pkt: Dict[str, Any]):
        entries = pkt.get("entries", [])
        src_ip = pkt.get("src_ip", "")
        proto = pkt.get("transport", "UDP")

        for entry in entries:
            service_hex = entry.get("service", "")
            instance_hex = entry.get("instance", "")
            major = entry.get("major", 0)
            minor = entry.get("minor", 0)
            ttl = entry.get("ttl", 0)
            entry_type = str(entry.get("type_name", ""))

            # Endpoint
            endpoints = entry.get("endpoints", [])
            provider_ip = src_ip
            provider_port = pkt.get("src_port", 0)
            if endpoints:
                ep = endpoints[0]
                if ep.get("ip"):
                    provider_ip = ep["ip"]
                if ep.get("port"):
                    provider_port = ep["port"]
                if ep.get("proto"):
                    proto = ep["proto"]

            if "offerservice" in entry_type.lower():
                key = f"{service_hex}:{instance_hex}@{provider_ip}"
                active = (ttl > 0)
                self.services_catalog[key] = {
                    "service_id": service_hex,
                    "instance_id": instance_hex,
                    "major": major,
                    "minor": minor,
                    "endpoint": f"{provider_ip}:{provider_port}",
                    "proto": proto,
                    "ttl": ttl,
                    "active": active,
                    "last_seen_dt": datetime.datetime.now(),
                    "last_seen": time.strftime("%H:%M:%S"),
                    "agent": pkt.get("_agent", ""),
                }
                self._refresh_services_table()

            elif "subscribeeventgroup" in entry_type.lower():
                evg_id = entry.get("eventgroup_id", 0)
                key = f"{service_hex}:{instance_hex}:{evg_id}@{src_ip}"
                active = (ttl > 0)
                self.subscriptions_catalog[key] = {
                    "service_id": service_hex,
                    "instance_id": instance_hex,
                    "eventgroup_id": f"0x{evg_id:04X}" if isinstance(evg_id, int) else str(evg_id),
                    "subscriber": f"{src_ip}:{pkt.get('src_port', '')}",
                    "initial_data": str(entry.get("initial_data", False)),
                    "ttl": ttl,
                    "status": entry_type,
                    "last_seen": time.strftime("%H:%M:%S"),
                }
                self._refresh_subscriptions_table()

    def _handle_someip_telemetry(self, pkt: Dict[str, Any]):
        msg_type_name = str(pkt.get("msg_type_name", "")).upper()
        return_code_name = str(pkt.get("return_code_name", "")).upper()

        if "NOTIFICATION" in msg_type_name:
            self.notification_count += 1
        elif "REQUEST" in msg_type_name:
            self.request_count += 1
        elif "RESPONSE" in msg_type_name:
            self.response_count += 1

        if return_code_name and return_code_name not in ("E_OK", "0X00", "0"):
            self.error_code_count += 1

    def _handle_legacy_service(self, pkt: Dict[str, Any]):
        service = pkt.get("service", "")
        instance = pkt.get("instance", "")
        provider_ip = pkt.get("provider_ip", pkt.get("_agent", ""))
        provider_port = pkt.get("provider_port", 0)
        proto = pkt.get("proto", "UDP")
        ttl = pkt.get("ttl", 0)
        active = pkt.get("active", True)
        key = f"{service}:{instance}@{provider_ip}"

        self.services_catalog[key] = {
            "service_id": service,
            "instance_id": instance,
            "major": pkt.get("major", 0),
            "minor": pkt.get("minor", 0),
            "endpoint": f"{provider_ip}:{provider_port}",
            "proto": proto,
            "ttl": ttl,
            "active": active,
            "last_seen_dt": datetime.datetime.now(),
            "last_seen": time.strftime("%H:%M:%S"),
            "agent": pkt.get("_agent", ""),
        }
        self._refresh_services_table()

    def _refresh_services_table(self):
        self.services_table.setRowCount(0)
        for svc in self.services_catalog.values():
            row = self.services_table.rowCount()
            self.services_table.insertRow(row)

            is_active = svc.get("active", True)
            bg = QColor("#F0FFF4") if is_active else QColor("#F8F9FA")
            fg = QColor("#1C7338") if is_active else QColor("#5F6368")

            values = [
                svc.get("service_id", ""),
                svc.get("instance_id", ""),
                str(svc.get("major", "")),
                str(svc.get("minor", "")),
                svc.get("endpoint", ""),
                svc.get("proto", "UDP"),
                str(svc.get("ttl", "")),
                "Active" if is_active else "Expired",
                svc.get("last_seen", ""),
                svc.get("agent", ""),
            ]

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                item.setBackground(bg)
                item.setForeground(fg)
                if col in (2, 3, 5, 6, 7):
                    item.setTextAlignment(Qt.AlignCenter)
                self.services_table.setItem(row, col, item)

    def _refresh_subscriptions_table(self):
        self.subscriptions_table.setRowCount(0)
        for sub in self.subscriptions_catalog.values():
            row = self.subscriptions_table.rowCount()
            self.subscriptions_table.insertRow(row)
            values = [
                sub.get("service_id", ""),
                sub.get("instance_id", ""),
                sub.get("eventgroup_id", ""),
                sub.get("subscriber", ""),
                sub.get("initial_data", "False"),
                str(sub.get("ttl", "")),
                sub.get("status", ""),
                sub.get("last_seen", ""),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.subscriptions_table.setItem(row, col, item)

    def _update_stats_display(self):
        if "Total Packets Captured" in self.stats_labels:
            self.stats_labels["Total Packets Captured"].setText(str(self.total_packets_count))
            self.stats_labels["SOME/IP Messages"].setText(str(self.someip_count))
            self.stats_labels["SOME/IP-SD Packets"].setText(str(self.sd_count))
            self.stats_labels["Notifications (Events)"].setText(str(self.notification_count))
            self.stats_labels["Requests"].setText(str(self.request_count))
            self.stats_labels["Responses"].setText(str(self.response_count))
            self.stats_labels["Errors (Return Code != E_OK)"].setText(str(self.error_code_count))
            self.stats_labels["Discovered Services Count"].setText(str(len(self.services_catalog)))

    def _insert_packet_row(self, pkt: Dict[str, Any]):
        row = self.table.rowCount()
        if row >= MAX_ROWS:
            self.table.removeRow(0)
            row = self.table.rowCount()

        self.table.insertRow(row)

        pkt_id = str(pkt.get("_id", row + 1))
        rx_time = str(pkt.get("_rx_time", time.strftime("%H:%M:%S")))
        proto = str(pkt.get("protocol", "SOME/IP"))
        transport = str(pkt.get("transport", "UDP"))
        src = f"{pkt.get('src_ip', '')}:{pkt.get('src_port', '')}"
        dst = f"{pkt.get('dst_ip', '')}:{pkt.get('dst_port', '')}"
        service_id = str(pkt.get("service", ""))
        method_id = str(pkt.get("method", ""))
        is_event = pkt.get("is_event", False)
        if is_event and not method_id.endswith("(Evt)"):
            method_display = f"{method_id} (Evt)"
        else:
            method_display = method_id

        msg_type_name = str(pkt.get("msg_type_name", pkt.get("type", "")))
        return_code_name = str(pkt.get("return_code_name", "E_OK"))
        client_session = f"C:{pkt.get('client_id', '')} S:{pkt.get('session_id', '')}"
        length = str(pkt.get("length", ""))

        # Summary
        summary = ""
        if proto == "SOME/IP-SD":
            entries = pkt.get("entries", [])
            if entries:
                types = [e.get("type_name", "") for e in entries]
                summary = f"SD Entries: {', '.join(types)}"
            else:
                summary = "SOME/IP Service Discovery"
        else:
            summary = f"{msg_type_name} [{return_code_name}]"
            if pkt.get("payload_len"):
                summary += f" (Payload {pkt['payload_len']} B)"

        values = [
            pkt_id,
            rx_time,
            proto,
            transport,
            src,
            dst,
            service_id,
            method_display,
            msg_type_name,
            return_code_name,
            client_session,
            length,
            summary,
        ]

        # Coloring
        bg = QColor("#FFFFFF")
        fg = QColor("#202124")

        is_error = return_code_name and return_code_name not in ("E_OK", "0X00", "0")
        if is_error:
            bg = QColor("#FFF5F5")
            fg = QColor("#9B2C2C")
        elif proto == "SOME/IP-SD":
            bg = QColor("#FFF9E6")
            fg = QColor("#873800")
        elif "NOTIFICATION" in msg_type_name.upper():
            bg = QColor("#F0FFF4")
            fg = QColor("#1C7338")
        elif "REQUEST" in msg_type_name.upper():
            bg = QColor("#EBF8FF")
            fg = QColor("#1A365D")
        elif "RESPONSE" in msg_type_name.upper():
            bg = QColor("#F0F5FF")
            fg = QColor("#173B68")

        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            item.setBackground(bg)
            item.setForeground(fg)
            if col in (0, 1, 2, 3, 6, 9, 11):
                item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, col, item)

        if self.chk_autoscroll.isChecked():
            self.table.scrollToBottom()

        # Apply the active filters to the newly inserted row so live packets
        # obey whatever filter is currently selected.
        if not self._row_passes_filters(row):
            self.table.setRowHidden(row, True)

    def _row_passes_filters(self, row: int) -> bool:
        """Return True if *row* should be visible given the current filter state.

        Shared by ``_apply_table_filters`` (bulk scan) and
        ``_insert_packet_row`` (per-row check on new arrivals).
        """
        query = self.search_input.text().strip().lower()
        filter_svc = self.filter_service.text().strip().lower()
        filter_type = self.filter_type_combo.currentText()

        # Text search filter
        if query:
            row_text = " ".join(
                self.table.item(row, col).text().lower()
                for col in range(self.table.columnCount())
                if self.table.item(row, col)
            )
            if query not in row_text:
                return False

        # Service ID filter (col 6)
        if filter_svc:
            svc_item = self.table.item(row, 6)
            if svc_item and filter_svc not in svc_item.text().lower():
                return False

        # Type combo filter
        if filter_type != "All Types":
            proto_item = self.table.item(row, 2)   # "Type" column  → protocol
            type_item  = self.table.item(row, 8)   # "Message Type" → msg_type_name
            ret_item   = self.table.item(row, 9)   # "Return Code"  → return_code_name

            proto_text = proto_item.text() if proto_item else ""
            type_text  = type_item.text()  if type_item  else ""
            # Normalise to uppercase so "0x00" and "0X00" both match
            ret_text   = ret_item.text().upper() if ret_item else ""

            if filter_type == "SOME/IP Only" and "SOME/IP-SD" in proto_text:
                return False
            elif filter_type == "SOME/IP-SD Only" and "SOME/IP-SD" not in proto_text:
                return False
            elif filter_type == "REQUEST" and "REQUEST" not in type_text.upper():
                return False
            elif filter_type == "RESPONSE" and "RESPONSE" not in type_text.upper():
                return False
            elif filter_type == "NOTIFICATION" and "NOTIFICATION" not in type_text.upper():
                return False
            elif filter_type == "ERRORS" and ret_text in ("E_OK", "0X00", "0"):
                # Hide rows where return code indicates *no* error
                return False

        return True

    def _apply_table_filters(self):
        """Re-evaluate visibility for every row in the table."""
        for row in range(self.table.rowCount()):
            self.table.setRowHidden(row, not self._row_passes_filters(row))

    def _on_packet_selected(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        id_item = self.table.item(row, 0)
        if not id_item:
            return

        pkt_id = int(id_item.text())
        pkt = next((p for p in self.packets_data if p.get("_id") == pkt_id), None)
        if not pkt:
            return

        self._populate_dissection_tree(pkt)
        self._populate_hex_and_interpretations(pkt)

    def _populate_dissection_tree(self, pkt: Dict[str, Any]):
        self.tree_inspector.clear()

        # 1. Transport Frame node
        frame_node = QTreeWidgetItem(self.tree_inspector, ["Frame & Transport"])
        frame_node.setIcon(0, self.style().standardIcon(self.style().StandardPixmap.SP_DriveNetIcon))
        QTreeWidgetItem(frame_node, ["SBC Agent Source", str(pkt.get("_agent", "Local"))])
        QTreeWidgetItem(frame_node, ["Transport Protocol", str(pkt.get("transport", "UDP"))])
        QTreeWidgetItem(frame_node, ["Source Endpoint", f"{pkt.get('src_ip', '')}:{pkt.get('src_port', '')}"])
        QTreeWidgetItem(frame_node, ["Destination Endpoint", f"{pkt.get('dst_ip', '')}:{pkt.get('dst_port', '')}"])
        QTreeWidgetItem(frame_node, ["Total Message Length", f"{pkt.get('length', '')} bytes"])

        # 2. SOME/IP Header node
        someip_node = QTreeWidgetItem(self.tree_inspector, ["SOME/IP Header"])
        someip_node.setIcon(0, self.style().standardIcon(self.style().StandardPixmap.SP_FileIcon))

        msg_id_node = QTreeWidgetItem(someip_node, ["Message ID", f"{pkt.get('service', '')} {pkt.get('method', '')}"])
        QTreeWidgetItem(msg_id_node, ["Service ID", f"{pkt.get('service', '')} ({pkt.get('service_id', '')})"])
        is_evt = pkt.get("is_event", False)
        QTreeWidgetItem(msg_id_node, ["Method / Event ID", f"{pkt.get('method', '')} ({pkt.get('method_id', '')}) [{'Event' if is_evt else 'Method'}]"])

        QTreeWidgetItem(someip_node, ["Length Field", f"{pkt.get('length', '')} bytes"])

        req_node = QTreeWidgetItem(someip_node, ["Request ID", f"Client: {pkt.get('client_id', '')}, Session: {pkt.get('session_id', '')}"])
        QTreeWidgetItem(req_node, ["Client ID", str(pkt.get("client_id", ""))])
        QTreeWidgetItem(req_node, ["Session ID", str(pkt.get("session_id", ""))])

        QTreeWidgetItem(someip_node, ["Protocol Version", str(pkt.get("proto_ver", 1))])
        QTreeWidgetItem(someip_node, ["Interface Version", str(pkt.get("iface_ver", 1))])

        msg_type_str = f"{pkt.get('msg_type', '')} ({pkt.get('msg_type_name', '')})"
        QTreeWidgetItem(someip_node, ["Message Type", msg_type_str])

        return_code_str = f"{pkt.get('return_code', '')} ({pkt.get('return_code_name', '')})"
        QTreeWidgetItem(someip_node, ["Return Code", return_code_str])

        # 3. SOME/IP-TP (if present)
        if pkt.get("is_tp"):
            tp_node = QTreeWidgetItem(self.tree_inspector, ["SOME/IP-TP (Transport Protocol)"])
            tp_node.setIcon(0, self.style().standardIcon(self.style().StandardPixmap.SP_ArrowForward))
            QTreeWidgetItem(tp_node, ["Segment Offset", f"{pkt.get('tp_offset', 0)} bytes"])
            QTreeWidgetItem(tp_node, ["More Segments Flag", str(pkt.get("tp_more", False))])
            tp_node.setExpanded(True)

        # 4. SOME/IP-SD (if SD packet)
        if str(pkt.get("protocol", "")).upper() == "SOME/IP-SD" or pkt.get("flags") or pkt.get("entries"):
            sd_node = QTreeWidgetItem(self.tree_inspector, ["SOME/IP-SD (Service Discovery)"])
            sd_node.setIcon(0, self.style().standardIcon(self.style().StandardPixmap.SP_ComputerIcon))

            # Flags
            flags = pkt.get("flags", {})
            flags_node = QTreeWidgetItem(sd_node, ["Flags", f"Reboot={flags.get('reboot', False)}, Unicast={flags.get('unicast', False)}"])
            QTreeWidgetItem(flags_node, ["Reboot Flag", str(flags.get("reboot", False))])
            QTreeWidgetItem(flags_node, ["Unicast Flag", str(flags.get("unicast", False))])
            QTreeWidgetItem(flags_node, ["Raw Flags Byte", f"0x{flags.get('raw', 0):02X}"])

            # Entries
            entries = pkt.get("entries", [])
            entries_node = QTreeWidgetItem(sd_node, ["Entries Array", f"{len(entries)} entries"])
            for idx, e in enumerate(entries):
                e_node = QTreeWidgetItem(entries_node, [f"Entry #{idx+1}: {e.get('type_name', '')}", f"Service {e.get('service', '')}:{e.get('instance', '')}"])
                QTreeWidgetItem(e_node, ["Type", f"{e.get('type_name', '')} (0x{e.get('type', 0):02X})"])
                QTreeWidgetItem(e_node, ["Service ID", f"{e.get('service', '')} ({e.get('service_id', '')})"])
                QTreeWidgetItem(e_node, ["Instance ID", f"{e.get('instance', '')} ({e.get('instance_id', '')})"])
                QTreeWidgetItem(e_node, ["Major Version", str(e.get("major", ""))])
                QTreeWidgetItem(e_node, ["Minor Version", str(e.get("minor", ""))])
                QTreeWidgetItem(e_node, ["TTL", f"{e.get('ttl', '')} seconds"])
                if e.get("eventgroup_id"):
                    QTreeWidgetItem(e_node, ["Eventgroup ID", f"0x{e.get('eventgroup_id', 0):04X}"])

                endpoints = e.get("endpoints", [])
                if endpoints:
                    ep_node = QTreeWidgetItem(e_node, ["Resolved Endpoints", f"{len(endpoints)} endpoint(s)"])
                    for ep in endpoints:
                        QTreeWidgetItem(ep_node, [ep.get("type", "ENDPOINT"), f"{ep.get('ip', '')}:{ep.get('port', '')} [{ep.get('proto', '')}]"])
                    ep_node.setExpanded(True)

            entries_node.setExpanded(True)

            # Options
            options = pkt.get("options", [])
            if options:
                opts_node = QTreeWidgetItem(sd_node, ["Options Array", f"{len(options)} option(s)"])
                for idx, opt in enumerate(options):
                    o_node = QTreeWidgetItem(opts_node, [f"Option #{idx+1}: {opt.get('type_name', '')}", f"{opt.get('ip', '')}:{opt.get('port', '')} [{opt.get('proto', '')}]"])
                    if opt.get("config"):
                        QTreeWidgetItem(o_node, ["Config String", opt["config"]])
                opts_node.setExpanded(True)

            sd_node.setExpanded(True)

        # 5. Payload Node
        payload_len = pkt.get("payload_len", 0)
        p_node = QTreeWidgetItem(self.tree_inspector, ["Payload Information", f"{payload_len} bytes"])
        p_node.setIcon(0, self.style().standardIcon(self.style().StandardPixmap.SP_FileDialogDetailedView))
        QTreeWidgetItem(p_node, ["Payload Length", f"{payload_len} bytes"])
        if pkt.get("payload_hex"):
            QTreeWidgetItem(p_node, ["Hex Preview", pkt["payload_hex"][:64] + ("..." if len(pkt["payload_hex"]) > 64 else "")])

        self.tree_inspector.expandAll()

    def _populate_hex_and_interpretations(self, pkt: Dict[str, Any]):
        hex_str = pkt.get("payload_hex", "")
        raw_bytes = b""
        if hex_str:
            try:
                raw_bytes = bytes.fromhex(hex_str)
            except ValueError:
                raw_bytes = b""

        # Hex Dump view
        if raw_bytes:
            formatted_dump = format_hex_dump(raw_bytes)
            self.hex_view.setPlainText(formatted_dump)
        else:
            self.hex_view.setPlainText("(No payload bytes recorded)")

        # Interpretations table
        interps = interpret_payload(raw_bytes) if raw_bytes else {}
        self.interp_table.setRowCount(0)
        for key, val in interps.items():
            r = self.interp_table.rowCount()
            self.interp_table.insertRow(r)
            k_item = QTableWidgetItem(str(key))
            v_item = QTableWidgetItem(str(val))
            k_item.setFlags(k_item.flags() & ~Qt.ItemIsEditable)
            v_item.setFlags(v_item.flags() & ~Qt.ItemIsEditable)
            self.interp_table.setItem(r, 0, k_item)
            self.interp_table.setItem(r, 1, v_item)

    def closeEvent(self, event):
        self.worker.stop()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(WHITE_STYLESHEET)
    app.setWindowIcon(QIcon(_get_asset_path(os.path.join("assets", "icon.ico"))))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
