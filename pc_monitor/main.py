import json
import socket
import sys
import threading
import time
from PySide6.QtCore import QObject, Signal, Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QPlainTextEdit,
    QTabWidget, QMessageBox
)

CONTROL_PORT = 47000
TELEMETRY_PORT = 47001

class TelemetryWorker(QObject):
    message = Signal(dict)
    error = Signal(str)

    def __init__(self, listen_ip="0.0.0.0"):
        super().__init__()
        self.listen_ip = listen_ip
        self.running = False
        self.sock = None

    def start(self):
        if self.running:
            return
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.listen_ip, TELEMETRY_PORT))
            self.sock.settimeout(0.5)
        except OSError as exc:
            self.error.emit(f"Cannot listen on UDP {TELEMETRY_PORT}: {exc}")
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.running and self.sock:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = json.loads(data.decode("utf-8", errors="replace"))
                msg["_agent"] = addr[0]
                self.message.emit(msg)
            except json.JSONDecodeError:
                self.error.emit(f"Invalid telemetry JSON from {addr[0]}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOME/IP Monitor")
        self.resize(1100, 700)
        self.services = {}
        self.packet_count = 0
        self.worker = TelemetryWorker()
        self.worker.message.connect(self.handle_message)
        self.worker.error.connect(self.log)

        root = QWidget()
        layout = QVBoxLayout(root)
        form = QFormLayout()
        self.agent_ip = QLineEdit("192.168.1.3")
        self.pc_ip = QLineEdit("0.0.0.0")
        self.filter = QLineEdit("udp or tcp")
        form.addRow("SBC agent IP", self.agent_ip)
        form.addRow("PC listen IP (informational)", self.pc_ip)
        form.addRow("Capture filter", self.filter)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        for label, command in [
            ("Start agent listener", "LISTEN"), ("Start capture", "START"),
            ("Stop capture", "STOP"), ("Get status", "GET_STATUS"),
            ("Refresh services", "GET_SERVICES")
        ]:
            b = QPushButton(label)
            b.clicked.connect(lambda checked=False, c=command: self.action(c))
            buttons.addWidget(b)
        self.filter_btn = QPushButton("Apply filter")
        self.filter_btn.clicked.connect(self.apply_filter)
        buttons.addWidget(self.filter_btn)
        layout.addLayout(buttons)

        self.status = QLabel("Listener not started")
        layout.addWidget(self.status)
        self.tabs = QTabWidget()
        self.packet_table = QTableWidget(0, 7)
        self.packet_table.setHorizontalHeaderLabels(
            ["Time", "Transport", "Source", "Destination", "Service", "Method", "Length"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.service_table = QTableWidget(0, 6)
        self.service_table.setHorizontalHeaderLabels(
            ["Service", "Instance", "Major", "Provider IP", "Port", "TTL"])
        self.service_table.horizontalHeader().setStretchLastSection(True)
        self.sd_log = QPlainTextEdit()
        self.sd_log.setReadOnly(True)
        self.event_log = QPlainTextEdit()
        self.event_log.setReadOnly(True)
        self.tabs.addTab(self.packet_table, "SOME/IP packets")
        self.tabs.addTab(self.service_table, "Offered services")
        self.tabs.addTab(self.sd_log, "SOME/IP-SD events")
        self.tabs.addTab(self.event_log, "Agent log")
        layout.addWidget(self.tabs)
        self.setCentralWidget(root)

    def log(self, text):
        self.event_log.appendPlainText(f"[{time.strftime('%H:%M:%S')}] {text}")

    def action(self, command):
        if command == "LISTEN":
            self.worker.start()
            self.status.setText(f"Listening on UDP {TELEMETRY_PORT}")
            return
        ip = self.agent_ip.text().strip()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(command.encode(), (ip, CONTROL_PORT))
            sock.close()
            self.log(f"Sent {command} to {ip}:{CONTROL_PORT}")
        except OSError as exc:
            self.log(f"Send failed: {exc}")

    def apply_filter(self):
        self.action("SET_FILTER " + self.filter.text().strip())

    def handle_message(self, msg):
        typ = msg.get("type", "")
        if typ == "status":
            self.status.setText(msg.get("message", "Agent status"))
            self.log(f"{msg.get('_agent')}: {msg.get('message', '')}")
        elif typ == "packet":
            self.packet_count += 1
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            values = [
                time.strftime("%H:%M:%S"), msg.get("transport", ""),
                f"{msg.get('src_ip','')}:{msg.get('src_port','')}",
                f"{msg.get('dst_ip','')}:{msg.get('dst_port','')}",
                msg.get("service", ""), msg.get("method", ""), str(msg.get("length", ""))
            ]
            for col, value in enumerate(values):
                self.packet_table.setItem(row, col, QTableWidgetItem(str(value)))
            if self.packet_table.rowCount() > 1000:
                self.packet_table.removeRow(0)
        elif typ == "service":
            key = f"{msg.get('service')}:{msg.get('instance')}@{msg.get('provider_ip')}"
            self.services[key] = msg
            self.refresh_services()
            self.sd_log.appendPlainText(
                f"{time.strftime('%H:%M:%S')} {msg.get('event')} "
                f"{msg.get('service')}/{msg.get('instance')} from {msg.get('provider_ip')} "
                f"TTL={msg.get('ttl')}"
            )
        elif typ == "sd":
            self.sd_log.appendPlainText(
                f"{time.strftime('%H:%M:%S')} {msg.get('event')} "
                f"{msg.get('service')}/{msg.get('instance')} from {msg.get('source_ip')} "
                f"TTL={msg.get('ttl')}"
            )

    def refresh_services(self):
        self.service_table.setRowCount(0)
        for msg in self.services.values():
            if not msg.get("active", True):
                continue
            row = self.service_table.rowCount()
            self.service_table.insertRow(row)
            vals = [msg.get("service", ""), msg.get("instance", ""),
                    str(msg.get("major", "")), msg.get("provider_ip", ""),
                    str(msg.get("provider_port", "")), str(msg.get("ttl", ""))]
            for col, value in enumerate(vals):
                self.service_table.setItem(row, col, QTableWidgetItem(str(value)))

    def closeEvent(self, event):
        self.worker.stop()
        event.accept()

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
