#!/usr/bin/env python3
import os
import sqlite3
import datetime
import json
import requests
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from dotenv import load_dotenv

# --- Initialization ---
load_dotenv()
app = Flask(__name__, static_folder="static", template_folder="templates")

# SECRET_KEY for sessions
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24).hex())

# --- Security headers ---
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- Feature flags and admin config ---
ENABLE_ADMIN_PANEL = True 
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "RAHUL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "KNOX")

# --- Production configuration ---
if os.getenv("ENVIRONMENT") == "production":
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# --- External API endpoints (set these in .env) ---
VEHICLE_API = os.getenv("VEHICLE_API", "")
NUMBER_API = os.getenv("NUMBER_API", "")
AADHAAR_API = os.getenv("AADHAAR_API", "")

# --- Environment-provided API keys (JSON) ---
API_KEYS_JSON = os.getenv("API_KEYS", "[]")

# --- Database Setup ---
DB_FILE = os.getenv("DB_FILE", "database.db")

def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get existing columns
    cursor.execute("PRAGMA table_info(keys)")
    columns = [row[1] for row in cursor.fetchall()]

    # Create table if it doesn't exist (with all new columns)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pin TEXT UNIQUE NOT NULL,
        limit_count INTEGER DEFAULT 10,
        used_today INTEGER DEFAULT 0,
        expiry TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        device_id TEXT,
        allow_phone INTEGER DEFAULT 1,
        allow_vehicle INTEGER DEFAULT 1,
        allow_aadhaar INTEGER DEFAULT 1
    )
    """)
    
    # --- Add new columns if they don't exist (for migration) ---
    if 'device_id' not in columns:
        cursor.execute("ALTER TABLE keys ADD COLUMN device_id TEXT")
    if 'allow_phone' not in columns:
        cursor.execute("ALTER TABLE keys ADD COLUMN allow_phone INTEGER DEFAULT 1")
    if 'allow_vehicle' not in columns:
        cursor.execute("ALTER TABLE keys ADD COLUMN allow_vehicle INTEGER DEFAULT 1")
    if 'allow_aadhaar' not in columns:
        cursor.execute("ALTER TABLE keys ADD COLUMN allow_aadhaar INTEGER DEFAULT 1")
    
    conn.commit()
    conn.close()

def seed_keys_from_env():
    try:
        items = json.loads(API_KEYS_JSON)
        if not isinstance(items, list):
            print("API_KEYS must be a JSON array. Skipping seeding.")
            return
    except Exception as e:
        print("Failed to parse API_KEYS JSON:", e)
        return

    conn = get_db_connection()
    for entry in items:
        pin = entry.get("pin")
        limit = entry.get("limit_count", entry.get("limit", 10))
        expiry = entry.get("expiry")
        if not pin:
            continue
        try:
            # Insert or ignore duplicates
            conn.execute("INSERT OR IGNORE INTO keys (pin, limit_count, expiry) VALUES (?, ?, ?)", (pin, limit, expiry))
        except Exception as e:
            print("Failed to insert key from env:", pin, e)
    conn.commit()
    conn.close()

# Initialize DB + seed from env
initialize_database()
seed_keys_from_env()

# --- Main Routes ---
@app.route('/')
def home():
    return render_template("index.html")

@app.route('/api/search', methods=['POST'])
def search():
    data = request.json or {}
    lookup_type = data.get('type')
    number = data.get('number')
    pin = data.get('pin')
    device_id = data.get('deviceId') # Get new deviceId

    if not all([lookup_type, number, pin, device_id]):
        return jsonify({"error": "Missing required fields."}), 400

    conn = get_db_connection()
    key = conn.execute("SELECT * FROM keys WHERE pin = ?", (pin,)).fetchone()

    if not key:
        conn.close()
        return jsonify({"error": "Invalid API Key"}), 401

    if key['expiry']:
        expiry_date = datetime.datetime.fromisoformat(key['expiry']).date()
        if datetime.date.today() > expiry_date:
            conn.close()
            return jsonify({"error": "API Key has expired."}), 403

    if key['used_today'] >= key['limit_count']:
        conn.close()
        return jsonify({"error": "Daily search limit reached for this key."}), 403

    # --- NEW: Device Lock Check ---
    if not key['device_id']:
        # First time use, lock this key to this device
        conn.execute("UPDATE keys SET device_id = ? WHERE pin = ?", (device_id, pin))
        conn.commit()
    elif key['device_id'] != device_id:
        conn.close()
        return jsonify({"error": "API Key is locked to another device."}), 403

    # --- NEW: Permission Check ---
    if lookup_type == "phone" and not key['allow_phone']:
        conn.close()
        return jsonify({"error": "This key does not have permission for Phone searches."}), 403
    if lookup_type == "vehicle" and not key['allow_vehicle']:
        conn.close()
        return jsonify({"error": "This key does not have permission for Vehicle searches."}), 403
    if lookup_type == "aadhaar" and not key['allow_aadhaar']:
        conn.close()
        return jsonify({"error": "This key does not have permission for Aadhaar searches."}), 403

    api_url = ""
    if lookup_type == "phone":
        if not NUMBER_API:
            conn.close()
            return jsonify({"error": "Number API not configured."}), 500
        api_url = NUMBER_API.format(number)
    elif lookup_type == "vehicle":
        if not VEHICLE_API:
            conn.close()
            return jsonify({"error": "Vehicle API not configured."}), 500
        api_url = VEHICLE_API.format(number)
    elif lookup_type == "aadhaar":
        if not AADHAAR_API:
            conn.close()
            return jsonify({"error": "Aadhaar API not configured."}), 500
        api_url = AADHAAR_API.format(number)
    else:
        conn.close()
        return jsonify({"error": "Invalid lookup type"}), 400

    try:
        response = requests.get(api_url, timeout=15)
        response.raise_for_status()
        api_data = response.json()
    except Exception as e:
        conn.close()
        return jsonify({"error": "Failed to fetch data from external API.", "details": str(e)}), 502

    conn.execute("UPDATE keys SET used_today = used_today + 1 WHERE pin = ?", (pin,))
    conn.commit()

    key_info = {
        "searches_left": key['limit_count'] - key['used_today'] - 1,
        "expiry_date": key['expiry'] or "Never"
    }
    conn.close()

    final_response = {
        **(api_data if isinstance(api_data, dict) else {"result": api_data}),
        "status": "success",
        "key_status": key_info,
        "dev": "RAHUL SHARMA"
    }
    return jsonify(final_response)

# --- Admin routes ---
if ENABLE_ADMIN_PANEL:
    def admin_required(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('is_admin'):
                if request.is_json:
                    return jsonify({"success": False, "error": "Unauthorized"}), 401
                return redirect(url_for('admin_page'))
            return f(*args, **kwargs)
        return decorated_function

    @app.route('/admin')
    def admin_page():
        return render_template("admin.html")

    @app.route('/admin/login', methods=['POST'])
    def admin_login():
        data = request.get_json(silent=True) or {}
        username = data.get('username')
        password = data.get('password')
            
        if not username or not password:
            return jsonify({"success": False, "error": "Username and password are required"}), 400
            
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['is_admin'] = True
            conn = get_db_connection()
            keys_rows = conn.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
            conn.close()
            keys_list = [dict(row) for row in keys_rows]
            return jsonify({"success": True, "keys": keys_list})
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    @app.route('/admin/keys', methods=['GET'])
    @admin_required
    def admin_get_keys():
        conn = get_db_connection()
        keys_rows = conn.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
        conn.close()
        keys_list = [dict(row) for row in keys_rows]
        return jsonify({"success": True, "keys": keys_list})

    @app.route('/admin/add', methods=['POST'])
    @admin_required
    def add_key():
        data = request.json or {}
        pin = data.get('pin')
        limit = data.get('limit', 10)
        expiry = data.get('expiry')
        
        # Get new permissions, default to 1 (true)
        allow_phone = 1 if data.get('allow_phone', True) else 0
        allow_vehicle = 1 if data.get('allow_vehicle', True) else 0
        allow_aadhaar = 1 if data.get('allow_aadhaar', True) else 0

        if not pin:
            return jsonify({"success": False, "error": "PIN cannot be empty."}), 400
        try:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO keys (pin, limit_count, expiry, allow_phone, allow_vehicle, allow_aadhaar) VALUES (?, ?, ?, ?, ?, ?)",
                (pin, limit, expiry, allow_phone, allow_vehicle, allow_aadhaar)
            )
            conn.commit()
            conn.close()
            return jsonify({"success": True})
        except sqlite3.IntegrityError:
            return jsonify({"success": False, "error": "This PIN already exists."}), 409

    @app.route('/admin/delete', methods=['POST'])
    @admin_required
    def delete_key():
        data = request.json or {}
        key_id = data.get('id')
        if not key_id:
            return jsonify({"success": False, "error": "Key ID is required."}), 400
        conn = get_db_connection()
        conn.execute("DELETE FROM keys WHERE id = ?", (key_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    
    # --- NEW ROUTE: To reset device lock ---
    @app.route('/admin/reset_device', methods=['POST'])
    @admin_required
    def reset_device():
        data = request.json or {}
        key_id = data.get('id')
        if not key_id:
            return jsonify({"success": False, "error": "Key ID is required."}), 400
        try:
            conn = get_db_connection()
            conn.execute("UPDATE keys SET device_id = NULL WHERE id = ?", (key_id,))
            conn.commit()
            conn.close()
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/logout', methods=['POST'])
    def admin_logout():
        session.pop('is_admin', None)
        return jsonify({"success": True})

# --- Run ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)), debug=True)
