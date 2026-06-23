import sqlite3

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER,
            type TEXT UNIQUE NOT NULL,
            grade TEXT NOT NULL,
            photo BLOB,
            comments TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Run this once to create the DB
if __name__ == '__main__':
    init_db()
