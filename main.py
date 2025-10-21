from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import os, sqlite3, datetime, requests

app = Flask(__name__)
load_dotenv()

# Admin creds
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "RAHUL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "KNOX")

# APIs
VEHICLE_API = os.getenv("VEHICLE_API")
NUMBER_API = os.getenv("NUMBER_API")
AADHAAR_API = os.getenv("AADHAAR_API")

# Database helper
def db():
    conn = sqlite3.connect("database.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB if not exists
with db() as conn:
    conn.execute("""CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pin TEXT UNIQUE,
        limit_count INTEGER DEFAULT 10,
        used_today INTEGER DEFAULT 0,
        expiry TEXT
    )""")
    conn.commit()

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/api/search', methods=['POST'])
def search():
    data = request.json
    lookup_type = data.get('type')
    number = data.get('number')
    pin = data.get('pin')

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM keys WHERE pin=?", (pin,))
    key = cur.fetchone()

    if not key:
        return jsonify({"error": "Invalid PIN"}), 401

    if key['expiry']:
        expiry = datetime.datetime.fromisoformat(key['expiry'])
        if datetime.datetime.now() > expiry:
            return jsonify({"error": "PIN expired"}), 403

    if key['used_today'] >= key['limit_count']:
        return jsonify({"error": "Daily limit reached"}), 403

    if lookup_type == "vehicle":
        api = VEHICLE_API.format(number)
    elif lookup_type == "number":
        api = NUMBER_API.format(number)
    elif lookup_type == "aadhaar":
        api = AADHAAR_API.format(number)
    else:
        return jsonify({"error": "Invalid type"}), 400

    try:
        r = requests.get(api)
        result = r.json()
    except Exception as e:
        return jsonify({"error": "API fetch failed", "details": str(e)}), 500

    cur.execute("UPDATE keys SET used_today = used_today + 1 WHERE pin=?", (pin,))
    conn.commit()

    return jsonify(result)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        data = request.json
        if data.get('username') == ADMIN_USERNAME and data.get('password') == ADMIN_PASSWORD:
            conn = db()
            rows = conn.execute("SELECT * FROM keys").fetchall()
            return jsonify([dict(r) for r in rows])
        return jsonify({"error": "Invalid credentials"}), 401
    return render_template('admin.html')

@app.route('/admin/add', methods=['POST'])
def add_key():
    data = request.json
    if data.get('username') != ADMIN_USERNAME or data.get('password') != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401
    pin = data.get('pin')
    limit_count = data.get('limit', 10)
    expiry = data.get('expiry')
    conn = db()
    try:
        conn.execute("INSERT INTO keys (pin, limit_count, expiry) VALUES (?, ?, ?)", (pin, limit_count, expiry))
        conn.commit()
        return jsonify({"success": True, "message": "Key added"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "PIN already exists"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
