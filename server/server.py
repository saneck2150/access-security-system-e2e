import os
import socket
import threading
import logging
import sqlite3
import configparser

# Create logs directory if it doesn't exist
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Logging configuration
log_file = os.path.join(LOG_DIR, "server.log")
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Read configuration from file
config = configparser.ConfigParser()
config.read('server_config.ini')

HOST = config.get('SERVER', 'HOST', fallback='127.0.0.1')
PORT = config.getint('SERVER', 'PORT', fallback=8888)
MAX_CONNECTIONS = config.getint('SERVER', 'MAX_CONNECTIONS', fallback=5)

DATABASE_PATH = os.path.join(LOG_DIR, "access_control.db")

class TCPServer:
    def __init__(self, host: str, port: int, max_connections: int):
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []
        self.running = False

    def start(self):
        """Start the server and accept incoming connections."""
        self.running = True
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_connections)
            logging.info(f"Server started on {self.host}:{self.port}")
            print(f"Server started on {self.host}:{self.port}")

            while self.running:
                self.server_socket.settimeout(1.0)  # Timeout to allow shutdown
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logging.info(f"New connection from {client_address}")
                    print(f"New connection from {client_address}")
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                    client_thread.start()
                    self.clients.append(client_thread)
                except socket.timeout:
                    continue
        except Exception as e:
            logging.error(f"Server error: {e}")
        finally:
            self.server_socket.close()
            logging.info("Server stopped")

    def handle_client(self, client_socket):
        """Handle incoming client request and check ID in database."""
        try:
            while True:
                data = client_socket.recv(1024).decode('utf-8').strip()
                if not data:
                    break
                
                logging.info(f"Received ID: {data}")
                print(f"Received ID: {data}")
                
                if self.check_access(data):
                    response = "Access Granted"
                else:
                    response = "Access Denied"

                logging.info(f"Response: {response}")
                client_socket.sendall(response.encode('utf-8'))
        except Exception as e:
            logging.error(f"Client handling error: {e}")
        finally:
            client_socket.close()
            logging.info("Connection closed")

    def check_access(self, employee_id):
        """Check if the ID exists in the database."""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM employees WHERE employee_id = ?", (employee_id,))
            result = cursor.fetchone()
            conn.close()

            if result:
                logging.info(f"ID {employee_id} found in database: Access Granted")
                return True
            else:
                logging.info(f"ID {employee_id} not found in database: Access Denied")
                return False
        except Exception as e:
            logging.error(f"Database error: {e}")
            return False

    def stop(self):
        """Stop the server gracefully."""
        self.running = False
        for client in self.clients:
            client.join()
        self.server_socket.close()
        logging.info("Server shut down")
        print("Server shut down")

if __name__ == "__main__":
    server = TCPServer(HOST, PORT, MAX_CONNECTIONS)
    server.start()
