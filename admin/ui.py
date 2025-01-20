import sys
import threading
import subprocess
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QPushButton,
    QVBoxLayout,
    QTextEdit,
    QLineEdit,
    QLabel,
    QMessageBox,
    QFileDialog
)
from server.server import *  # Import server module

class AdminPanel(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()
        self.server_thread = None
        self.server = None
        self.client_process = None

    def init_ui(self):
        self.setWindowTitle("Admin Panel TCP Server")
        self.setGeometry(400, 400, 800, 600)

        self.log_area = QTextEdit(self)
        self.log_area.setReadOnly(True)

        self.start_button = QPushButton("Start Server", self)
        self.stop_button = QPushButton("Stop Server", self)
        self.send_button = QPushButton("Send Message", self)

        self.input_field = QLineEdit(self)
        self.input_label = QLabel("Enter message:", self)

        self.start_button.clicked.connect(self.start_server)
        self.stop_button.clicked.connect(self.stop_server)
        self.send_button.clicked.connect(self.send_message)

        layout = QVBoxLayout()
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.input_label)
        layout.addWidget(self.input_field)
        layout.addWidget(self.send_button)
        layout.addWidget(self.log_area)

        self.setLayout(layout)

        self.open_logs_button = QPushButton("Open Logs", self)
        self.open_logs_button.clicked.connect(self.open_logs)
        layout.addWidget(self.open_logs_button)

    def start_server(self):
        if not self.server_thread:
            self.server = TCPServer(HOST, PORT, MAX_CONNECTIONS)
            self.server_thread = threading.Thread(target=self.server.start)
            self.server_thread.daemon = True
            self.server_thread.start()
            self.log_area.append("Server started...")

            # Launch C++ client as a separate process
            try:
                self.client_process = subprocess.Popen(
                    ["./client/client"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                self.log_area.append("C++ client started.")
            except FileNotFoundError:
                QMessageBox.critical(self, "Error", "Client file (tcp_client) not found.")
                self.log_area.append("Error: Client not found.")

    def stop_server(self):
        if self.server:
            self.server.stop()
            self.server_thread.join()
            self.server_thread = None
            self.log_area.append("Server stopped.")

        if self.client_process:
            self.client_process.terminate()
            self.client_process = None
            self.log_area.append("C++ client stopped.")

    def send_message(self):
        message = self.input_field.text()
        if message:
            self.log_area.append(f"Client sends: {message}")
            try:
                # Send message through C++ client
                response = subprocess.check_output(
                    ["./client/client", message], universal_newlines=True
                )
                self.log_area.append(f"Server response: {response}")
            except Exception as e:
                self.log_area.append(f"Error: {e}")
            self.input_field.clear()

    def open_logs(self):
        log_dir = "logs"
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Log File", log_dir, "Log Files (*.log);;All Files (*)", options=options)
        if file_name:
            self.log_area.append(f"Opened log file: {file_name}")
            with open(file_name, 'r') as file:
                content = file.read()
                self.log_area.append(content)