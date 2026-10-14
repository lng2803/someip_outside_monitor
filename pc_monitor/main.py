import json
import socket
import sys
import threading
import time
from collections import OrderedDict

from PySide6.QtCore import QObject, Signal, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)

CONTROL_PORT = 47000
TELEMETRY_PORT = 47001
MAX_ROWS = 2000

WHITE_STYLESHEET = """
QWidget {
    background: #ffffff;
    color: #202124;
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 10pt;
}
QLineEdit {
    background: #ffffff;
    color: #202124;
    border: 1px solid #c9cdd2;
    border-radius: 5px;
    padding: 6px 8px;
    selection-background-color: #cfe3ff;
}
QPushButton {
    background: #f5f7fa;
    color: #202124;
    border: 1px solid #c9cdd2;
    border-radius: 5px;
    padding: 7px 12px;
}
QPushButton:hover { background: #eaf2ff; border-color: #8ab4f8; }
QPushButton:pressed { background: #d8e7ff; }
QTableWidget {
    background: #ffffff;
    alternate-background-color: #f7f9fc;
    color: #202124;
    gridline-color: #e0e3e7;
    border: 1px solid #d9dde3;
    selection-background-color: #d9eaff;
    selection-color: #202124;
}
QHeaderView::section {
    background: #f1f3f4;
    color: #202124;
    padding: 7px 5px;
    border: 0;
    border-right: 1px solid #d9dde3;
    border-bottom: 1px solid #d9dde3;
    font-weight: 600;
}
QPlainTextEdit {
    background: #ffffff;
    color: #202124;
    border: 1px solid #d9dde3;
    border-radius: 4px;
}
QLabel { background: transparent; }
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
    COLUMNS = [
        "Time",
        "Type",
        "Transport",
        "Source",
        "Destination",
        "Service ID",
        "Instance ID",
        "Method / Event",
        "Length",
        "Details",
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOME/IP Monitor")
        self.resize(1450, 820)
        self.setStyleSheet(WHITE_STYLESHEET)

        self.worker = TelemetryWorker()
        self.worker.message.connect(self.handle_message)
        self.worker.error.connect(self.log)

        # Persistent rows for OfferService entries are grouped by source + service.
        # The current SBC Agent sends one telemetry JSON per SD entry, without an
        # SD-datagram identifier, so exact grouping by original SD packet is not possible.
        self.offer_rows = {}
        self.sd_rows = {}
        self.packet_count = 0
        self.status_count = 0

        root = QWidget()
        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        form = QFormLayout()
        self.agent_ip = QLineEdit("192.168.1.55")
        self.pc_listen_ip = QLineEdit("0.0.0.0")
        self.capture_filter = QLineEdit("udp or tcp")
        self.agent_ip.setPlaceholderText("e.g. 192.168.1.55")
        self.pc_listen_ip.setPlaceholderText("0.0.0.0 to listen on all interfaces")
        self.capture_filter.setPlaceholderText("BPF filter, e.g. udp or tcp")
        form.addRow("SBC Agent IP", self.agent_ip)
        form.addRow("PC listen IP", self.pc_listen_ip)
        form.addRow("Capture filter", self.capture_filter)
        main_layout.addLayout(form)

        buttons = QHBoxLayout()
        self.listen_button = QPushButton("Start listener")
        self.listen_button.clicked.connect(self.start_listener)
        buttons.addWidget(self.listen_button)

        for label, command in [
            ("Start capture", "START"),
            ("Stop capture", "STOP"),
            ("Get status", "GET_STATUS"),
            ("Refresh services", "GET_SERVICES"),
        ]:
            button = QPushButton(label)
            button.clicked.connect(
                lambda checked=False, cmd=command: self.send_command(cmd)
            )
            buttons.addWidget(button)

        apply_filter_button = QPushButton("Apply filter")
        apply_filter_button.clicked.connect(self.apply_filter)
        buttons.addWidget(apply_filter_button)

        clear_button = QPushButton("Clear table")
        clear_button.clicked.connect(self.clear_table)
        buttons.addWidget(clear_button)
        main_layout.addLayout(buttons)

        self.status_label = QLabel("Listener not started")
        self.status_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        main_layout.addWidget(self.status_label)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        widths = [90, 100, 75, 170, 170, 105, 120, 135, 75, 260]
        for index, width in enumerate(widths):
            self.table.setColumnWidth(index, width)
        main_layout.addWidget(self.table, 1)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(1000)
        self.log_view.setPlaceholderText("Agent status and application logs...")
        self.log_view.setMaximumHeight(120)
        main_layout.addWidget(self.log_view)

        self.setCentralWidget(root)

    def log(self, message):
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

    def send_command(self, command):
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

    @staticmethod
    def _text(value, default=""):
        if value is None:
            return default
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    @staticmethod
    def _first(msg, *keys, default=""):
        for key in keys:
            value = msg.get(key)
            if value is not None and value != "":
                return value
        return default

    def _insert_row(self, values, row_key=None):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, value in enumerate(values):
            item = QTableWidgetItem(self._text(value))
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if col == 0:
                item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, col, item)
        if row_key is not None:
            self.table.setVerticalHeaderItem(row, QTableWidgetItem(str(row_key)))
        self.table.scrollToBottom()
        self._trim_table()
        return row

    def _update_cell(self, row, col, value):
        if row < 0 or row >= self.table.rowCount():
            return
        item = self.table.item(row, col)
        if item is None:
            item = QTableWidgetItem()
            self.table.setItem(row, col, item)
        item.setText(self._text(value))

    def _trim_table(self):
        while self.table.rowCount() > MAX_ROWS:
            self.table.removeRow(0)
            # Row indexes shift after deletion, so discard row indexes and let
            # subsequent telemetry recreate aggregate rows when needed.
            self.offer_rows.clear()
            self.sd_rows.clear()

    def clear_table(self):
        self.table.setRowCount(0)
        self.offer_rows.clear()
        self.sd_rows.clear()
        self.log("Unified packet/event table cleared")

    def handle_message(self, msg):
        msg_type = str(msg.get("type", "")).lower()
        now = time.strftime("%H:%M:%S")
        agent_ip = self._text(msg.get("_agent", ""))

        if msg_type == "status":
            message = self._text(msg.get("message", "Agent status"))
            capture = msg.get("capture_enabled")
            self.status_label.setText(
                f"{message} | agent={agent_ip} | telemetry packets={self.packet_count}"
            )
            self.log(f"{agent_ip}: {message}")
            if capture is not None:
                self.log(f"Capture enabled: {capture}")
            return

        if msg_type == "packet":
            self.packet_count += 1
            transport = self._text(msg.get("transport", ""))
            src = f"{self._first(msg, 'src_ip')}:{self._first(msg, 'src_port')}"
            dst = f"{self._first(msg, 'dst_ip')}:{self._first(msg, 'dst_port')}"
            service_id = self._first(msg, "service_id", "service")
            method_id = self._first(msg, "method_id", "method")
            instance_id = self._first(msg, "instance_id", default="")
            detail = f"agent={agent_ip}"
            if msg.get("info"):
                detail += f"; {msg['info']}"
            self._insert_row([
                now, "SOME/IP", transport, src, dst, service_id, instance_id,
                method_id, self._first(msg, "length"), detail
            ])
            self.status_label.setText(
                f"Receiving telemetry | packets={self.packet_count} | last agent={agent_ip}"
            )
            return

        if msg_type == "service":
            # Current SBC Agent emits one JSON telemetry record per OfferService entry.
            # Merge records from the same provider and service ID; list unique instance IDs
            # separated by semicolons, as requested.
            event = self._text(msg.get("event", "OfferService"))
            service_id = self._text(self._first(msg, "service_id", "service", default=""))
            instance_id = self._text(self._first(msg, "instance_id", "instance", default=""))
            provider_ip = self._text(self._first(msg, "provider_ip", "source_ip", default=""))
            provider_port = self._text(self._first(msg, "provider_port", "src_port", default=""))
            ttl = self._text(msg.get("ttl", ""))
            major = self._text(msg.get("major", ""))
            active = msg.get("active", True)
            key = (agent_ip, event, service_id, provider_ip)

            if event.lower() == "offerservice" or key in self.offer_rows:
                if key in self.offer_rows and self.offer_rows[key] < self.table.rowCount():
                    row = self.offer_rows[key]
                    existing = self.table.item(row, 6)
                    ids = [x.strip() for x in (existing.text() if existing else "").split(";") if x.strip()]
                    if instance_id and instance_id not in ids:
                        ids.append(instance_id)
                    self._update_cell(row, 0, now)
                    self._update_cell(row, 6, "; ".join(ids))
                    self._update_cell(row, 7, event)
                    self._update_cell(row, 9,
                        f"major={major}; TTL={ttl}; active={active}; provider_port={provider_port}; agent={agent_ip}")
                else:
                    row = self._insert_row([
                        now, "SOME/IP-SD", "UDP",
                        f"{provider_ip}:{provider_port}" if provider_port else provider_ip,
                        "224.224.224.245:30490",
                        service_id, instance_id, event, "",
                        f"major={major}; TTL={ttl}; active={active}; agent={agent_ip}"
                    ])
                    self.offer_rows[key] = row
            else:
                self._insert_row([
                    now, "SOME/IP-SD", "UDP", provider_ip, "",
                    service_id, instance_id, event, "",
                    f"major={major}; TTL={ttl}; active={active}; agent={agent_ip}"
                ])
            self.status_label.setText(
                f"Receiving telemetry | packets={self.packet_count} | last agent={agent_ip}"
            )
            return

        if msg_type == "sd":
            event = self._text(msg.get("event", "SD entry"))
            service_id = self._text(self._first(msg, "service_id", "service", default=""))
            instance_id = self._text(self._first(msg, "instance_id", "instance", default=""))
            src_ip = self._text(self._first(msg, "source_ip", "src_ip", default=""))
            src_port = self._text(self._first(msg, "source_port", "src_port", default=""))
            dst_ip = self._text(self._first(msg, "destination_ip", "dst_ip", default=""))
            dst_port = self._text(self._first(msg, "destination_port", "dst_port", default=""))
            ttl = self._text(msg.get("ttl", ""))
            key = (agent_ip, event, service_id, src_ip)

            if key in self.sd_rows and self.sd_rows[key] < self.table.rowCount():
                row = self.sd_rows[key]
                existing = self.table.item(row, 6)
                ids = [x.strip() for x in (existing.text() if existing else "").split(";") if x.strip()]
                if instance_id and instance_id not in ids:
                    ids.append(instance_id)
                self._update_cell(row, 0, now)
                self._update_cell(row, 6, "; ".join(ids))
                self._update_cell(row, 9, f"TTL={ttl}; agent={agent_ip}")
            else:
                dst = f"{dst_ip}:{dst_port}" if dst_ip and dst_port else dst_ip
                row = self._insert_row([
                    now, "SOME/IP-SD", "UDP",
                    f"{src_ip}:{src_port}" if src_port else src_ip,
                    dst, service_id, instance_id, event, "",
                    f"TTL={ttl}; agent={agent_ip}"
                ])
                self.sd_rows[key] = row
            self.status_label.setText(
                f"Receiving telemetry | packets={self.packet_count} | last agent={agent_ip}"
            )
            return

        self.log(f"Unknown telemetry type from {agent_ip}: {msg_type or '(empty)'}")


    def closeEvent(self, event):
        self.worker.stop()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(WHITE_STYLESHEET)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
