import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
""")

cursor.execute("INSERT INTO users VALUES (NULL, 'admin', 'admin123')")
cursor.execute("INSERT INTO users VALUES (NULL, 'test', 'test123')")

conn.commit()
conn.close()

print("Database initialized.")
