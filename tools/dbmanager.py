import sqlite3

def init_Db(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            mac TEXT NOT NULL,
            vendor TEXT,
            day_n_hour TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            mac TEXT PRIMARY KEY,
            description TEXT
        )
    ''')

    conn.commit()
    return conn  


def isner_Scan_Record(conn, ip, mac, vendor, day_n_hour):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_records WHERE ip = ?", (ip,))
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO scan_records (ip, mac, vendor, day_n_hour) VALUES (?, ?, ?, ?)", 
                       (ip, mac, vendor, day_n_hour))
        conn.commit()
    cursor.close()

