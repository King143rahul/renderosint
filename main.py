#!/usr/bin/env python3
import os
import datetime
import json
import requests
import pymongo
import random
import string
import re
from pymongo.errors import DuplicateKeyError
from requests.exceptions import JSONDecodeError, ConnectTimeout, ReadTimeout
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, abort
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from user_agent import generate_user_agent
from bson import ObjectId

# --- Initialization ---
load_dotenv()
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24).hex())
# --- NEW: Explicit check for secret key ---
if not app.secret_key:
    raise ValueError("CRITICAL: SECRET_KEY environment variable is not set or generated.")
# --- END NEW ---
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Make session permanent (lasts longer)
# app.config['SESSION_PERMANENT'] = True
# app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=30)


# --- Security headers ---
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- Admin config ---
ENABLE_ADMIN_PANEL = True
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "RAHUL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "KNOX")

# --- External API endpoints ---
VEHICLE_API_1 = os.getenv("VEHICLE_API_1", "")
PHONE_API_1 = os.getenv("PHONE_API_1", "")
PHONE_API_2 = os.getenv("PHONE_API_2", "")
PHONE_API_3 = os.getenv("PHONE_API_3", "")
VEHICLE_API_2 = os.getenv("VEHICLE_API_2", "")
AADHAAR_API = os.getenv("AADHAAR_API", "")
AADHAAR_FAMILY_API = os.getenv("AADHAAR_FAMILY_API", "")
INSTA_API = os.getenv("INSTA_API", "")
# ----------------------------------------------------------------- #


# --- Database Setup (MongoDB) ---
DB_CLIENT = None
KEYS_COLLECTION = None
SEARCH_HISTORY_COLLECTION = None
USERS_COLLECTION = None
CONFIG_COLLECTION = None

def get_db_collections():
    global DB_CLIENT, KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION, USERS_COLLECTION, CONFIG_COLLECTION
    if all([KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION, USERS_COLLECTION, CONFIG_COLLECTION]):
        return
    MONGO_URI = os.getenv("MONGO_URI")
    if not MONGO_URI:
        print("CRITICAL: MONGO_URI environment variable is not set.")
        return
    try:
        if DB_CLIENT is None:
            DB_CLIENT = pymongo.MongoClient(MONGO_URI, appName="knoxV4") # Kept V4 name
        db = DB_CLIENT.osint_db
        KEYS_COLLECTION = db.keys
        KEYS_COLLECTION.create_index("pin", unique=True)
        SEARCH_HISTORY_COLLECTION = db.history
        SEARCH_HISTORY_COLLECTION.create_index([("pin", 1), ("timestamp", -1)])
        USERS_COLLECTION = db.users
        USERS_COLLECTION.create_index("phone", unique=True)
        CONFIG_COLLECTION = db.config
        CONFIG_COLLECTION.create_index("config_id", unique=True)
        print("Successfully connected to MongoDB and all collections.")
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION, USERS_COLLECTION, CONFIG_COLLECTION = (None, None, None, None)

get_db_collections()

# --- Helper Functions (Scraper, API calls, Logging) ---
def get_details_from_vahanx(rc_number: str) -> dict:
    try:
        ua = generate_user_agent()
        headers = {"User-Agent": ua}
        url = f"https://vahanx.in/rc-search/{rc_number.strip().upper()}"
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        data_labels = ["Owner Name", "Father's Name", "Owner Serial No", "Model Name", "Maker Model", "Vehicle Class", "Fuel Type", "Fuel Norms", "Registration Date", "Insurance Company", "Insurance No", "Insurance Expiry", "Insurance Upto", "Fitness Upto", "Tax Upto", "PUC No", "PUC Upto", "Financier Name", "Registered RTO", "Address", "City Name", "Phone"]
        data = {label: None for label in data_labels}
        for label in data:
            div = soup.find("span", string=label)
            if div:
                parent = div.find_parent("div")
                if parent:
                    value_tag = parent.find("p")
                    if value_tag: data[label] = value_tag.get_text(strip=True)
        return data
    except Exception as e:
        return {"error": f"Vahanx scraper failed: {str(e)}"}

def safe_api_call(url: str, headers: dict, timeout=15) -> dict:
    if not url: return {"error": "API endpoint not configured."}
    try:
        response = requests.get(url, timeout=timeout, headers=headers)
        response.raise_for_status()
        response_text = response.text
        return response.json()
    except JSONDecodeError: return {"error": f"API Invalid JSON: {response_text[:100]}..."}
    except (ConnectTimeout, ReadTimeout): return {"error": "API timed out."}
    except requests.exceptions.RequestException as e: return {"error": f"Network error: {e}"}
    except Exception as e: return {"error": f"Unknown error: {e}"}

def log_search(pin: str, lookup_type: str, number: str, device_id: str):
    if SEARCH_HISTORY_COLLECTION is None: return
    try:
        log_entry = {"pin": pin, "lookup_type": lookup_type, "query": number, "device_id": device_id, "timestamp": datetime.datetime.now(datetime.timezone.utc)}
        SEARCH_HISTORY_COLLECTION.insert_one(log_entry)
    except Exception as e: print(f"Failed to log search for {pin}: {e}")

# ----------------------------------------------------------------- #
# --- Main App Routes ---
# ----------------------------------------------------------------- #
@app.route('/')
def home():
    user_info = None
    if 'user_phone' in session: user_info = {"name": session.get('user_name'), "phone": session.get('user_phone')}
    return render_template("index.html", user_info=user_info)

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if 'user_phone' in session: return redirect(url_for('home'))
    if request.method == 'POST':
        name, phone = request.form.get('name', '').strip(), request.form.get('phone', '').strip()
        if not name or not phone or not phone.isdigit() or len(phone) < 10:
            return render_template("user_login.html", error="Valid name & 10-digit phone required.")
        if USERS_COLLECTION is None: return render_template("user_login.html", error="DB connection error.")
        user = USERS_COLLECTION.find_one({"phone": phone})
        if user and user.get('is_banned', False): return render_template("user_login.html", error="Account suspended.")
        try:
            USERS_COLLECTION.update_one({"phone": phone},
                {"$set": {"name": name, "last_login": datetime.datetime.now(datetime.timezone.utc), "is_banned": False},
                 "$setOnInsert": {"first_login": datetime.datetime.now(datetime.timezone.utc)}}, upsert=True)
            session['user_phone'], session['user_name'] = phone, name
            session.permanent = True; app.permanent_session_lifetime = datetime.timedelta(days=30)
            return redirect(url_for('home'))
        except Exception as e: print(f"User login error: {e}"); return render_template("user_login.html", error="An error occurred.")
    return render_template("user_login.html")

@app.route('/logout')
def user_logout():
    session.pop('user_phone', None); session.pop('user_name', None); return redirect(url_for('home'))

@app.route('/search/<service_type>')
def search_page(service_type):
    page_config = { "phone": {"title": "Phone Search", "placeholder": "Enter Phone Number", "icon_class": "fas fa-mobile-alt"}, "vehicle": {"title": "Vehicle Search", "placeholder": "Enter Vehicle Number", "icon_class": "fas fa-car"}, "aadhaar": {"title": "Aadhaar Info", "placeholder": "Enter Aadhaar Number", "icon_class": "fas fa-id-card"}, "family": {"title": "Aadhaar to Family", "placeholder": "Enter Aadhaar Number", "icon_class": "fas fa-users"}, "insta": {"title": "Instagram Info", "placeholder": "Enter Instagram Username", "icon_class": "fab fa-instagram"} }
    config = page_config.get(service_type);
    if not config: return abort(404)
    return render_template("search_page.html", **config, service_type=service_type)

@app.route('/api/config')
def get_public_config():
    if CONFIG_COLLECTION is None: return jsonify({"note": None})
    config = CONFIG_COLLECTION.find_one({"config_id": "global_config"}); return jsonify({"note": config.get("global_note") if config else None})

@app.route('/api/search', methods=['POST'])
def search():
    if KEYS_COLLECTION is None: return jsonify({"error": "DB connection error."}), 500
    data = request.json or {}
    lookup_type, pin, device_id = data.get('type'), data.get('pin'), data.get('deviceId')
    number_raw = data.get('number', '').strip(); number = re.sub(r'\s+', '', number_raw).lstrip('+91')
    if not all([lookup_type, number, pin, device_id]): return jsonify({"error": "Missing fields."}), 400
    if lookup_type == "phone" and (not number.isdigit() or len(number) != 10): return jsonify({"error": "Phone must be 10 digits."}), 400

    key = KEYS_COLLECTION.find_one({"pin": pin})
    if not key: return jsonify({"error": "Invalid API Key"}), 401
    if key.get('expiry'):
        try:
            if datetime.date.today() > datetime.datetime.fromisoformat(key['expiry']).date(): return jsonify({"error": "Key expired."}), 403
        except ValueError: pass
    if key.get('used_today', 0) >= key.get('limit_count', 10): return jsonify({"error": "Daily limit reached."}), 403

    device_limit = key.get('device_limit', 1); device_ids = key.get('device_ids', [])
    if device_id not in device_ids:
        if len(device_ids) < device_limit: KEYS_COLLECTION.update_one({"pin": pin}, {"$push": {"device_ids": device_id}})
        else: return jsonify({"error": f"Device limit ({device_limit}) reached."}), 403

    permission_map = {"phone": "allow_phone", "vehicle": "allow_vehicle", "aadhaar": "allow_aadhaar", "family": "allow_family", "insta": "allow_insta"}
    if not key.get(permission_map.get(lookup_type)): return jsonify({"error": f"Permission denied for {lookup_type}."}), 403

    headers = {'User-Agent': generate_user_agent()}; api_data = {}
    try:
        if lookup_type == "phone":
            api_data['result_1'] = safe_api_call(PHONE_API_1.format(number), headers); api_data['result_2'] = safe_api_call(PHONE_API_2.format(number), headers); api_data['result_3'] = safe_api_call(PHONE_API_3.format(number), headers)
        elif lookup_type == "vehicle":
            api_data['result_1'] = safe_api_call(VEHICLE_API_1.format(number), headers); api_data['result_2'] = safe_api_call(VEHICLE_API_2.format(number), headers); api_data['result_3'] = get_details_from_vahanx(number)
        elif lookup_type == "aadhaar": api_data = safe_api_call(AADHAAR_API.format(number), headers)
        elif lookup_type == "family": api_data = safe_api_call(AADHAAR_FAMILY_API.format(number), headers)
        elif lookup_type == "insta": api_data = safe_api_call(INSTA_API.format(number), headers)
        else: return jsonify({"error": "Invalid lookup type"}), 400
    except Exception as e: return jsonify({"error": f"API fetch error: {e}"}), 502

    KEYS_COLLECTION.update_one({"pin": pin}, {"$inc": {"used_today": 1}}); log_search(pin, lookup_type, number, device_id)
    key_info = {"searches_left": key.get('limit_count', 10) - key.get('used_today', 0) - 1, "expiry_date": key.get('expiry') or "Never"}
    final_response = {**(api_data if isinstance(api_data, dict) else {"result": api_data}), "status": "success", "key_status": key_info, "dev": "RAHUL SHARMA"}
    return jsonify(final_response)

# ----------------------------------------------------------------- #
# --- Admin Panel Routes (Keeping V4 features, No user link) ---
# ----------------------------------------------------------------- #
if ENABLE_ADMIN_PANEL:
    def admin_required(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('is_admin'): return jsonify({"success": False, "error": "Unauthorized"}), 401
            return f(*args, **kwargs)
        return decorated_function

    def make_serializable(doc):
        for k, v in doc.items():
            if isinstance(v, ObjectId): doc[k] = str(v)
            if isinstance(v, datetime.datetime): doc[k] = v.isoformat()
        return doc

    @app.route('/admin')
    def admin_page(): return render_template("admin.html") # Render without checking session here

    @app.route('/admin/login', methods=['POST'])
    def admin_login():
        data = request.get_json(silent=True) or {}
        if data.get('username') == ADMIN_USERNAME and data.get('password') == ADMIN_PASSWORD:
            session['is_admin'] = True; session.permanent = True # Make admin session permanent
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    @app.route('/admin/logout', methods=['POST'])
    def admin_logout():
        session.pop('is_admin', None); return jsonify({"success": True})

    @app.route('/admin/check_session', methods=['GET'])
    def check_admin_session():
        # Simple endpoint for frontend to check if session is still valid
        if session.get('is_admin'):
            return jsonify({"success": True, "is_admin": True})
        else:
            return jsonify({"success": True, "is_admin": False})


    @app.route('/admin/dashboard_stats', methods=['GET'])
    @admin_required
    def admin_dashboard_stats():
        if not all([KEYS_COLLECTION, USERS_COLLECTION, SEARCH_HISTORY_COLLECTION]): return jsonify({"success": False, "error": "DB error."}), 500
        try:
            total_searches = sum(k.get('used_today', 0) for k in KEYS_COLLECTION.find({}, {"used_today": 1}))
            active = KEYS_COLLECTION.count_documents({"$or": [{"expiry": {"$gte": datetime.date.today().isoformat()}}, {"expiry": None}]})
            top_keys = list(KEYS_COLLECTION.find({}, {"pin": 1, "used_today": 1, "_id": 0}).sort("used_today", -1).limit(5))
            total_u = USERS_COLLECTION.count_documents({})
            ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
            popular = list(SEARCH_HISTORY_COLLECTION.aggregate([{"$match": {"timestamp": {"$gte": ago}}}, {"$group": {"_id": "$lookup_type", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}]))
            recent = [make_serializable(s) for s in SEARCH_HISTORY_COLLECTION.find().sort("timestamp", -1).limit(10)]
            stats = {"total_searches_today": total_searches, "active_keys": active, "total_users": total_u, "top_5_keys": top_keys, "popular_services": popular, "recent_searches": recent}
            return jsonify({"success": True, "stats": stats})
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/api_health', methods=['GET'])
    @admin_required
    def admin_api_health():
        apis = [{"name": n, "url": u, "query": q} for n, u, q in [
            ("Phone 1", PHONE_API_1, "1234567890"), ("Phone 2", PHONE_API_2, "1234567890"), ("Phone 3", PHONE_API_3, "1234567890"),
            ("Vehicle 1", VEHICLE_API_1, "DL1CAB1234"), ("Vehicle 2", VEHICLE_API_2, "DL1CAB1234"), ("Aadhaar", AADHAAR_API, "123456789012"),
            ("Aadhaar Family", AADHAAR_FAMILY_API, "123456789012"), ("Instagram", INSTA_API, "dummyuser")]]
        results, headers = [], {'User-Agent': generate_user_agent()}
        for api in apis:
            if not api["url"]: results.append({"name": api["name"], "status": "N/A", "message": "Missing URL"}); continue
            res = safe_api_call(api["url"].format(api["query"]), headers, timeout=5)
            status = "OK" if "error" not in res else "Failed"; msg = res.get("error", "Success")
            results.append({"name": api["name"], "status": status, "message": msg})
        return jsonify({"success": True, "results": results})

    @app.route('/admin/keys', methods=['GET'])
    @admin_required
    def admin_get_keys():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "DB error."}), 500
        try:
            keys = [make_serializable(k) for k in KEYS_COLLECTION.find().sort("created_at", -1)]
            for row in keys: row['id'] = row['pin'] # Keep for frontend ID
            return jsonify({"success": True, "keys": keys})
        except Exception as e: print(f"Error /admin/keys: {e}"); return jsonify({"success": False, "error": f"Internal error: {e}"}), 500

    @app.route('/admin/add', methods=['POST'])
    @admin_required
    def add_key():
        data = request.json or {}; pin = data.get('pin')
        if not pin: return jsonify({"success": False, "error": "PIN required."}), 400
        perms = data.get('permissions', [])
        key_doc = {"pin": pin, "limit_count": int(data.get('limit', 10)), "expiry": data.get('expiry') or None, "device_limit": int(data.get('device_limit', 1)), "device_ids": [],
                   "allow_phone": 1 if "phone" in perms else 0, "allow_vehicle": 1 if "vehicle" in perms else 0, "allow_aadhaar": 1 if "aadhaar" in perms else 0,
                   "allow_family": 1 if "family" in perms else 0, "allow_insta": 1 if "insta" in perms else 0, "used_today": 0, "created_at": datetime.datetime.now(datetime.timezone.utc)}
        try: KEYS_COLLECTION.insert_one(key_doc); return jsonify({"success": True})
        except DuplicateKeyError: return jsonify({"success": False, "error": "PIN exists."}), 409
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/batch_add', methods=['POST'])
    @admin_required
    def batch_add_keys():
        data = request.json or {}; count = int(data.get('count', 0)); prefix = data.get('prefix', '')
        if not 1 <= count <= 100: return jsonify({"success": False, "error": "Count 1-100."}), 400
        perms = data.get('permissions', [])
        base = {"limit_count": int(data.get('limit', 10)), "expiry": data.get('expiry') or None, "device_limit": int(data.get('device_limit', 1)), "device_ids": [],
                "allow_phone": 1 if "phone" in perms else 0, "allow_vehicle": 1 if "vehicle" in perms else 0, "allow_aadhaar": 1 if "aadhaar" in perms else 0,
                "allow_family": 1 if "family" in perms else 0, "allow_insta": 1 if "insta" in perms else 0, "used_today": 0, "created_at": datetime.datetime.now(datetime.timezone.utc)}
        keys = []
        for _ in range(count): r = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8)); d = base.copy(); d["pin"] = f"{prefix}{r}"; keys.append(d)
        try: result = KEYS_COLLECTION.insert_many(keys, ordered=False); return jsonify({"success": True, "message": f"Created {len(result.inserted_ids)} keys."})
        except pymongo.errors.BulkWriteError as b: return jsonify({"success": True, "message": f"Created {b.details['nInserted']}. {count - b.details['nInserted']} duplicates failed."})
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/update', methods=['POST'])
    @admin_required
    def update_key():
        data, pin = request.json or {}, data.get('pin');
        if not pin: return jsonify({"success": False, "error": "PIN required."}), 400
        up = {"$set": {}}; perms = data.get('permissions')
        if 'limit' in data: up["$set"]["limit_count"] = int(data['limit'])
        if 'expiry' in data: up["$set"]["expiry"] = data['expiry'] or None
        if 'device_limit' in data: up["$set"]["device_limit"] = int(data['device_limit'])
        if perms is not None:
            up["$set"].update({k: 1 if v in perms else 0 for v, k in zip(["phone", "vehicle", "aadhaar", "family", "insta"], ["allow_phone", "allow_vehicle", "allow_aadhaar", "allow_family", "allow_insta"])})
        if not up["$set"]: return jsonify({"success": False, "error": "No fields to update."}), 400
        try:
            r = KEYS_COLLECTION.update_one({"pin": pin}, up)
            if r.matched_count == 0: return jsonify({"success": False, "error": "Key not found."}), 404
            return jsonify({"success": True})
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/delete', methods=['POST'])
    @admin_required
    def delete_key():
        pin = (request.json or {}).get('id');
        if not pin: return jsonify({"success": False, "error": "PIN required."}), 400
        try:
            r = KEYS_COLLECTION.delete_one({"pin": pin})
            if r.deleted_count == 0: return jsonify({"success": False, "error": "Key not found."}), 404
            if SEARCH_HISTORY_COLLECTION: SEARCH_HISTORY_COLLECTION.delete_many({"pin": pin})
            return jsonify({"success": True})
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/reset_device', methods=['POST'])
    @admin_required
    def reset_device():
        pin = (request.json or {}).get('id');
        if not pin: return jsonify({"success": False, "error": "PIN required."}), 400
        try: r = KEYS_COLLECTION.update_one({"pin": pin}, {"$set": {"device_ids": []}}); return jsonify({"success": True}) if r.matched_count > 0 else jsonify({"success": False, "error": "Key not found."}), 404
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/reset_usage', methods=['POST'])
    @admin_required
    def reset_usage():
        pin = (request.json or {}).get('id');
        if not pin: return jsonify({"success": False, "error": "PIN required."}), 400
        try: r = KEYS_COLLECTION.update_one({"pin": pin}, {"$set": {"used_today": 0}}); return jsonify({"success": True}) if r.matched_count > 0 else jsonify({"success": False, "error": "Key not found."}), 404
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/history', methods=['GET'])
    @admin_required
    def get_history():
        pin = request.args.get('pin');
        if not pin: return jsonify({"success": False, "error": "PIN required."}), 400
        try: rows = [make_serializable(h) for h in SEARCH_HISTORY_COLLECTION.find({"pin": pin}).sort("timestamp", -1).limit(100)]; return jsonify({"success": True, "history": rows})
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/users', methods=['GET'])
    @admin_required
    def admin_get_users():
        try: q = {}; s = request.args.get('search');
            if s: q = {"$or": [{"name": {"$regex": s, "$options": "i"}}, {"phone": {"$regex": s, "$options": "i"}}]}
            rows = [make_serializable(u) for u in USERS_COLLECTION.find(q).sort("last_login", -1)]; return jsonify({"success": True, "users": rows})
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/ban_user', methods=['POST'])
    @admin_required
    def admin_ban_user():
        d, p, b = request.json or {}, d.get('phone'), bool(d.get('ban_status', False))
        if not p: return jsonify({"success": False, "error": "Phone required."}), 400
        try: r = USERS_COLLECTION.update_one({"phone": p}, {"$set": {"is_banned": b}}); return jsonify({"success": True, "message": f"User {'banned' if b else 'unbanned'}."}) if r.matched_count > 0 else jsonify({"success": False, "error": "User not found."}), 404
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/note', methods=['GET', 'POST'])
    @admin_required
    def admin_global_note():
        try:
            if request.method == 'POST':
                n = (request.json or {}).get('note', '')
                CONFIG_COLLECTION.update_one({"config_id": "global_config"}, {"$set": {"global_note": n}}, upsert=True)
                return jsonify({"success": True, "message": "Note updated."})
            c = CONFIG_COLLECTION.find_one({"config_id": "global_config"}); return jsonify({"success": True, "note": c.get("global_note", "") if c else ""})
        except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

# --- Run ---
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    if not os.getenv("MONGO_URI"): print("Warning: MONGO_URI not set.")
    app.run(host='0.0.0.0', port=port, debug=False)
