import sqlite3

# Create or connect to the database
conn = sqlite3.connect("logs/access_control.db")
cursor = conn.cursor()

# Create a table for storing identification codes
cursor.execute('''
CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id TEXT UNIQUE NOT NULL
)
''')

# Insert some test employee IDs
test_ids = [("12345",), ("67890",), ("ABCDE",)]

cursor.executemany("INSERT OR IGNORE INTO employees (employee_id) VALUES (?)", test_ids)

conn.commit()
conn.close()

print("Database initialized successfully.")
