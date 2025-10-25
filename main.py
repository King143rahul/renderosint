#!/usr/bin/env python3
import os
import datetime
import json
import requests
import pymongo
import random
import string
import re  # Import regex module
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
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=30)

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
            DB_CLIENT = pymongo.MongoClient(MONGO_URI, appName="knoxV5")
        db = DB_CLIENT.osint_db 
        KEYS_COLLECTION = db.keys 
        KEYS_COLLECTION.create_index("pin", unique=True)
        KEYS_COLLECTION.create_index("linked_user_phone")
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
    if not url:
        return {"error": "API endpoint not configured."}
    try:
        response = requests.get(url, timeout=timeout, headers=headers)
        response.raise_for_status()
        response_text = response.text
        return response.json()
    except JSONDecodeError:
        return {"error": f"API did not return valid JSON. Response: {response_text[:100]}..."}
    except (ConnectTimeout, ReadTimeout):
        return {"error": "API call timed out."}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unknown error: {str(e)}"}

def log_search(pin: str, lookup_type: str, number: str, device_id: str):
    if SEARCH_HISTORY_COLLECTION is None: return
    try:
        log_entry = {"pin": pin, "lookup_type": lookup_type, "query": number, "device_id": device_id, "timestamp": datetime.datetime.now(datetime.timezone.utc)}
        SEARCH_HISTORY_COLLECTION.insert_one(log_entry)
    except Exception as e:
        print(f"Failed to log search for pin {pin}: {e}")
        
def user_login_required(f):
    """Decorator to require user login for a route."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_phone' not in session:
            return redirect(url_for('user_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------- #
# --- Main App Routes (Homepage, Login, Logout, Search) ---
# ----------------------------------------------------------------- #
@app.route('/')
def home():
    user_info = None
    if 'user_phone' in session:
        user_info = {"name": session.get('user_name'), "phone": session.get('user_phone')}
    return render_template("index.html", user_info=user_info)

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if 'user_phone' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        if not name or not phone or not phone.isdigit() or len(phone) < 10:
            return render_template("user_login.html", error="Please enter a valid name and 10-digit phone number.")
        if USERS_COLLECTION is None:
            return render_template("user_login.html", error="Database connection error. Please try again later.")
        
        user = USERS_COLLECTION.find_one({"phone": phone})
        if user and user.get('is_banned', False):
            return render_template("user_login.html", error="This account has been suspended. Please contact support.")
            
        try:
            USERS_COLLECTION.update_one(
                {"phone": phone},
                {"$set": {"name": name, "last_login": datetime.datetime.now(datetime.timezone.utc), "is_banned": False},
                 "$setOnInsert": {"first_login": datetime.datetime.now(datetime.timezone.utc)}},
                upsert=True
            )
            session['user_phone'] = phone
            session['user_name'] = name
            return redirect(url_for('home'))
        except Exception as e:
            print(f"User login error: {e}")
            return render_template("user_login.html", error="An error occurred. Please try again.")
    return render_template("user_login.html")

@app.route('/logout')
def user_logout():
    session.pop('user_phone', None)
    session.pop('user_name', None)
    return redirect(url_for('home'))

@app.route('/search/<service_type>')
def search_page(service_type):
    page_config = {
        "phone": {"title": "Phone Search", "placeholder": "Enter Phone Number", "icon_class": "fas fa-mobile-alt"},
        "vehicle": {"title": "Vehicle Search", "placeholder": "Enter Vehicle Number", "icon_class": "fas fa-car"},
        "aadhaar": {"title": "Aadhaar Info", "placeholder": "Enter Aadhaar Number", "icon_class": "fas fa-id-card"},
        "family": {"title": "Aadhaar to Family", "placeholder": "Enter Aadhaar Number", "icon_class": "fas fa-users"},
        "insta": {"title": "Instagram Info", "placeholder": "Enter Instagram Username", "icon_class": "fab fa-instagram"}
    }
    config = page_config.get(service_type)
    if not config: return abort(404)
    return render_template("search_page.html", **config, service_type=service_type)

@app.route('/api/config')
def get_public_config():
    if CONFIG_COLLECTION is None: return jsonify({"note": None})
    config = CONFIG_COLLECTION.find_one({"config_id": "global_config"})
    return jsonify({"note": config.get("global_note") if config else None})

@app.route('/api/search', methods=['POST'])
def search():
    if KEYS_COLLECTION is None: return jsonify({"error": "Database connection is not established."}), 500
    data = request.json or {}
    lookup_type, pin, device_id = data.get('type'), data.get('pin'), data.get('deviceId')
    
    # --- UPDATED: Phone Number Cleaning ---
    number_raw = data.get('number', '').strip()
    # Remove all spaces and leading +91
    number = re.sub(r'\s+', '', number_raw).lstrip('+91')
    # --- END UPDATE ---
    
    if not all([lookup_type, number, pin, device_id]):
        return jsonify({"error": "Missing required fields."}), 400

    # --- UPDATED: Phone Number Validation ---
    if lookup_type == "phone":
        if not number.isdigit() or len(number) != 10:
            return jsonify({"error": "Phone number must be exactly 10 digits."}), 400
    # --- END UPDATE ---

    key = KEYS_COLLECTION.find_one({"pin": pin})
    if not key: return jsonify({"error": "Invalid API Key"}), 401
    if key.get('expiry'):
        try:
            if datetime.date.today() > datetime.datetime.fromisoformat(key['expiry']).date():
                return jsonify({"error": "API Key has expired."}), 403
        except ValueError: pass
    if key.get('used_today', 0) >= key.get('limit_count', 10):
        return jsonify({"error": "Daily search limit reached for this key."}), 403

    device_limit = key.get('device_limit', 1)
    device_ids = key.get('device_ids', [])
    if device_id not in device_ids:
        if len(device_ids) < device_limit:
            KEYS_COLLECTION.update_one({"pin": pin}, {"$push": {"device_ids": device_id}})
        else:
            return jsonify({"error": f"Device limit ({device_limit}) reached for this key."}), 403

    permission_map = {"phone": "allow_phone", "vehicle": "allow_vehicle", "aadhaar": "allow_aadhaar", "family": "allow_family", "insta": "allow_insta"}
    if not key.get(permission_map.get(lookup_type)):
        return jsonify({"error": f"This key does not have permission for {lookup_type.title()} searches."}), 403

    headers = {'User-Agent': generate_user_agent()}
    api_data = {}
    try:
        if lookup_type == "phone":
            api_data['result_1'] = safe_api_call(PHONE_API_1.format(number), headers)
            api_data['result_2'] = safe_api_call(PHONE_API_2.format(number), headers)
            api_data['result_3'] = safe_api_call(PHONE_API_3.format(number), headers)
        elif lookup_type == "vehicle":
            api_data['result_1'] = safe_api_call(VEHICLE_API_1.format(number), headers)
            api_data['result_2'] = safe_api_call(VEHICLE_API_2.format(number), headers)
            api_data['result_3'] = get_details_from_vahanx(number)
        elif lookup_type == "aadhaar":
            api_data = safe_api_call(AADHAAR_API.format(number), headers)
        elif lookup_type == "family":
            api_data = safe_api_call(AADHAAR_FAMILY_API.format(number), headers)
        elif lookup_type == "insta":
            api_data = safe_api_call(INSTA_API.format(number), headers)
        else:
            return jsonify({"error": "Invalid lookup type"}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to fetch data. Detail: {str(e)}"}), 502
    
    KEYS_COLLECTION.update_one({"pin": pin}, {"$inc": {"used_today": 1}})
    log_search(pin, lookup_type, number, device_id)
    key_info = {"searches_left": key.get('limit_count', 10) - key.get('used_today', 0) - 1, "expiry_date": key.get('expiry') or "Never"}
    final_response = {**(api_data if isinstance(api_data, dict) else {"result": api_data}), "status": "success", "key_status": key_info, "dev": "RAHUL SHARMA"}
    return jsonify(final_response)

# ----------------------------------------------------------------- #
# --- User Account Routes (Unchanged) ---
# ----------------------------------------------------------------- #
@app.route('/account')
@user_login_required
def user_account():
    user_phone = session.get('user_phone')
    user_name = session.get('user_name')
    key_info = None
    
    if KEYS_COLLECTION:
        key_info = KEYS_COLLECTION.find_one({"linked_user_phone": user_phone})
        if key_info:
            key_info['_id'] = str(key_info['_id'])
            
    return render_template("account.html", user_name=user_name, user_phone=user_phone, key_info=key_info)

@app.route('/api/account/link_key', methods=['POST'])
@user_login_required
def api_link_key():
    user_phone = session.get('user_phone')
    pin = (request.json or {}).get('pin')
    if not pin: return jsonify({"success": False, "error": "PIN is required."}), 400
    if not KEYS_COLLECTION: return jsonify({"success": False, "error": "Database error."}), 500
        
    key = KEYS_COLLECTION.find_one({"pin": pin})
    if not key: return jsonify({"success": False, "error": "Invalid API Key."}), 404
    if key.get('linked_user_phone'):
        return jsonify({"success": False, "error": "This key is already linked to another account."}), 409
        
    try:
        KEYS_COLLECTION.update_one({"linked_user_phone": user_phone}, {"$unset": {"linked_user_phone": ""}})
        KEYS_COLLECTION.update_one({"pin": pin}, {"$set": {"linked_user_phone": user_phone}})
        return jsonify({"success": True, "message": "Key linked successfully."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/account/unlink_key', methods=['POST'])
@user_login_required
def api_unlink_key():
    user_phone = session.get('user_phone')
    if not KEYS_COLLECTION: return jsonify({"success": False, "error": "Database error."}), 500
    try:
        result = KEYS_COLLECTION.update_one({"linked_user_phone": user_phone}, {"$unset": {"linked_user_phone": ""}})
        if result.matched_count == 0: return jsonify({"success": False, "error": "No key was linked."}), 404
        return jsonify({"success": True, "message": "Key unlinked successfully."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/account/remove_device', methods=['POST'])
@user_login_required
def api_remove_device():
    user_phone = session.get('user_phone')
    device_id = (request.json or {}).get('device_id')
    if not device_id: return jsonify({"success": False, "error": "Device ID is required."}), 400
    if not KEYS_COLLECTION: return jsonify({"success": False, "error": "Database error."}), 500
    try:
        result = KEYS_COLLECTION.update_one({"linked_user_phone": user_phone}, {"$pull": {"device_ids": device_id}})
        if result.matched_count == 0: return jsonify({"success": False, "error": "Could not find your linked key."}), 404
        if result.modified_count == 0: return jsonify({"success": False, "error": "Device not found."}), 404
        return jsonify({"success": True, "message": "Device removed."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/account/change_pin', methods=['POST'])
@user_login_required
def api_change_pin():
    user_phone = session.get('user_phone')
    new_pin = (request.json or {}).get('new_pin', '').strip()
    
    if not new_pin or len(new_pin) < 4:
        return jsonify({"success": False, "error": "New PIN must be at least 4 characters."}), 400
    if not KEYS_COLLECTION or not SEARCH_HISTORY_COLLECTION:
        return jsonify({"success": False, "error": "Database error."}), 500
    try:
        if KEYS_COLLECTION.find_one({"pin": new_pin}):
            return jsonify({"success": False, "error": "This PIN is already in use."}), 409
        current_key = KEYS_COLLECTION.find_one({"linked_user_phone": user_phone})
        if not current_key:
            return jsonify({"success": False, "error": "You do not have a key linked."}), 404
        old_pin = current_key['pin']
        KEYS_COLLECTION.update_one({"_id": current_key['_id']}, {"$set": {"pin": new_pin}})
        SEARCH_HISTORY_COLLECTION.update_many({"pin": old_pin}, {"$set": {"pin": new_pin}})
        return jsonify({"success": True, "message": "Your PIN has been updated."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ----------------------------------------------------------------- #
# --- Admin Panel Routes (Updated) ---
# ----------------------------------------------------------------- #
if ENABLE_ADMIN_PANEL:
    def admin_required(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('is_admin'):
                return jsonify({"success": False, "error": "Unauthorized"}), 401
            return f(*args, **kwargs)
        return decorated_function

    def make_serializable(doc):
        for key, val in doc.items():
            if isinstance(val, ObjectId): doc[key] = str(val)
            if isinstance(val, datetime.datetime): doc[key] = val.isoformat()
        return doc

    @app.route('/admin')
    @admin_required
    def admin_page(): return render_template("admin.html")

    @app.route('/admin/login', methods=['POST'])
    def admin_login():
        data = request.get_json(silent=True) or {}
        if data.get('username') == ADMIN_USERNAME and data.get('password') == ADMIN_PASSWORD:
            session['is_admin'] = True
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    @app.route('/admin/logout', methods=['POST'])
    def admin_logout():
        session.pop('is_admin', None)
        return jsonify({"success": True})

    @app.route('/admin/dashboard_stats', methods=['GET'])
    @admin_required
    def admin_dashboard_stats():
        if not all([KEYS_COLLECTION, USERS_COLLECTION, SEARCH_HISTORY_COLLECTION]):
            return jsonify({"success": False, "error": "Database not configured."}), 500
        try:
            total_searches_today = sum(k.get('used_today', 0) for k in KEYS_COLLECTION.find({}, {"used_today": 1}))
            today_str = datetime.date.today().isoformat()
            active_keys = KEYS_COLLECTION.count_documents({"$or": [{"expiry": {"$gte": today_str}}, {"expiry": None}]})
            top_5_keys = list(KEYS_COLLECTION.find({}, {"pin": 1, "used_today": 1, "_id": 0}).sort("used_today", -1).limit(5))
            total_users = USERS_COLLECTION.count_documents({})
            seven_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
            popular_services = list(SEARCH_HISTORY_COLLECTION.aggregate([
                {"$match": {"timestamp": {"$gte": seven_days_ago}}},
                {"$group": {"_id": "$lookup_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]))
            recent_searches = [make_serializable(s) for s in SEARCH_HISTORY_COLLECTION.find().sort("timestamp", -1).limit(10)]
            stats = {"total_searches_today": total_searches_today, "active_keys": active_keys, "total_users": total_users, "top_5_keys": top_5_keys, "popular_services": popular_services, "recent_searches": recent_searches}
            return jsonify({"success": True, "stats": stats})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/api_health', methods=['GET'])
    @admin_required
    def admin_api_health():
        apis_to_check = [
            {"name": "Phone 1 (Byekam)", "url": PHONE_API_1, "query": "1234567890"},
            {"name": "Phone 2 (Demon)", "url": PHONE_API_2, "query": "1234567890"},
            {"name": "Phone 3 (Ox)", "url": PHONE_API_3, "query": "1234567890"},
            {"name": "Vehicle 1 (Byekam)", "url": VEHICLE_API_1, "query": "DL1CAB1234"},
            {"name": "Vehicle 2 (Hazex)", "url": VEHICLE_API_2, "query": "DL1CAB1234"},
            {"name": "Aadhaar (Ox)", "url": AADHAAR_API, "query": "123456789012"},
            {"name": "Aadhaar Family (Ox)", "url": AADHAAR_FAMILY_API, "query": "123456789012"},
            {"name": "Instagram", "url": INSTA_API, "query": "dummyuser"}
        ]
        results = []
        headers = {'User-Agent': generate_user_agent()}
        for api in apis_to_check:
            if not api["url"]:
                results.append({"name": api["name"], "status": "Not Configured", "message": "URL is not set"})
                continue
            res = safe_api_call(api["url"].format(api["query"]), headers, timeout=5)
            if "error" in res:
                results.append({"name": api["name"], "status": "Failed", "message": res["error"]})
            else:
                results.append({"name": api["name"], "status": "OK", "message": "Success"})
        return jsonify({"success": True, "results": results})

    # --- UPDATED: /admin/keys to fix server crash ---
    @app.route('/admin/keys', methods=['GET'])
    @admin_required
    def admin_get_keys():
        if KEYS_COLLECTION is None or USERS_COLLECTION is None:
            return jsonify({"success": False, "error": "Database not configured."}), 500
        try:
            keys_rows = [make_serializable(k) for k in KEYS_COLLECTION.find().sort("created_at", -1)]
            
            # --- BUG FIX: Build user cache safely ---
            user_phones = [k.get('linked_user_phone') for k in keys_rows if k.get('linked_user_phone')]
            user_cache = {}
            if user_phones:
                # Fetch all linked users in one query
                linked_users = USERS_COLLECTION.find({"phone": {"$in": user_phones}}, {"name": 1, "phone": 1})
                user_cache = {u['phone']: u.get('name', 'N/A') for u in linked_users}

            for row in keys_rows:
                row['id'] = row['pin']
                user_phone = row.get('linked_user_phone')
                if user_phone:
                    # Safely get from cache, default to 'N/A' if user was deleted
                    row['linked_user_name'] = user_cache.get(user_phone, 'N/A')
            # --- End of bug fix ---
            
            return jsonify({"success": True, "keys": keys_rows})
        except Exception as e:
            print(f"Error in /admin/keys: {e}") # Log the error
            return jsonify({"success": False, "error": f"An internal error occurred: {e}"}), 500
    # --- END OF UPDATE ---

    @app.route('/admin/add', methods=['POST'])
    @admin_required
    def add_key():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        data = request.json or {}
        pin = data.get('pin')
        if not pin: return jsonify({"success": False, "error": "PIN cannot be empty."}), 400
        key_doc = {
            "pin": pin, "limit_count": int(data.get('limit', 10)), "expiry": data.get('expiry') or None,
            "device_limit": int(data.get('device_limit', 1)), "device_ids": [],
            "allow_phone": 1 if "phone" in data.get('permissions', []) else 0,
            "allow_vehicle": 1 if "vehicle" in data.get('permissions', []) else 0,
            "allow_aadhaar": 1 if "aadhaar" in data.get('permissions', []) else 0,
            "allow_family": 1 if "family" in data.get('permissions', []) else 0,
            "allow_insta": 1 if "insta" in data.get('permissions', []) else 0,
            "used_today": 0, "created_at": datetime.datetime.now(datetime.timezone.utc)
        }
        try:
            KEYS_COLLECTION.insert_one(key_doc)
            return jsonify({"success": True})
        except DuplicateKeyError:
            return jsonify({"success": False, "error": "This PIN already exists."}), 409
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/batch_add', methods=['POST'])
    @admin_required
    def batch_add_keys():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        data = request.json or {}
        count = int(data.get('count', 0))
        prefix = data.get('prefix', '')
        if not 1 <= count <= 100:
            return jsonify({"success": False, "error": "Count must be between 1 and 100."}), 400
        base_doc = {
            "limit_count": int(data.get('limit', 10)), "expiry": data.get('expiry') or None,
            "device_limit": int(data.get('device_limit', 1)), "device_ids": [],
            "allow_phone": 1 if "phone" in data.get('permissions', []) else 0,
            "allow_vehicle": 1 if "vehicle" in data.get('permissions', []) else 0,
            "allow_aadhaar": 1 if "aadhaar" in data.get('permissions', []) else 0,
            "allow_family": 1 if "family" in data.get('permissions', []) else 0,
            "allow_insta": 1 if "insta" in data.get('permissions', []) else 0,
            "used_today": 0, "created_at": datetime.datetime.now(datetime.timezone.utc)
        }
        keys_to_insert = []
        for _ in range(count):
            random_pin = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            key_doc = base_doc.copy(); key_doc["pin"] = f"{prefix}{random_pin}"; keys_to_insert.append(key_doc)
        try:
            result = KEYS_COLLECTION.insert_many(keys_to_insert, ordered=False)
            return jsonify({"success": True, "message": f"Successfully created {len(result.inserted_ids)} keys."})
        except pymongo.errors.BulkWriteError as bwe:
            return jsonify({"success": True, "message": f"Created {bwe.details['nInserted']} keys. {count - bwe.details['nInserted']} duplicates failed."})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/update', methods=['POST'])
    @admin_required
    def update_key():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        data, pin = request.json or {}, data.get('pin')
        if not pin: return jsonify({"success": False, "error": "PIN is required."}), 400
        update_doc = {"$set": {}}
        if 'limit' in data: update_doc["$set"]["limit_count"] = int(data['limit'])
        if 'expiry' in data: update_doc["$set"]["expiry"] = data['expiry'] or None
        if 'device_limit' in data: update_doc["$set"]["device_limit"] = int(data['device_limit'])
        if 'permissions' in data:
            perms = data['permissions']
            update_doc["$set"].update({
                "allow_phone": 1 if "phone" in perms else 0, "allow_vehicle": 1 if "vehicle" in perms else 0,
                "allow_aadhaar": 1 if "aadhaar" in perms else 0, "allow_family": 1 if "family" in perms else 0,
                "allow_insta": 1 if "insta" in perms else 0
            })
        if not update_doc["$set"]: return jsonify({"success": False, "error": "No valid fields to update."}), 400
        try:
            result = KEYS_COLLECTION.update_one({"pin": pin}, update_doc)
            if result.matched_count == 0: return jsonify({"success": False, "error": "Key not found."}), 404
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/delete', methods=['POST'])
    @admin_required
    def delete_key():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        key_pin = (request.json or {}).get('id')
        if not key_pin: return jsonify({"success": False, "error": "Key PIN is required."}), 400
        try:
            result = KEYS_COLLECTION.delete_one({"pin": key_pin})
            if result.deleted_count == 0: return jsonify({"success": False, "error": "Key not found."}), 404
            if SEARCH_HISTORY_COLLECTION: SEARCH_HISTORY_COLLECTION.delete_many({"pin": key_pin})
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    
    @app.route('/admin/reset_device', methods=['POST'])
    @admin_required
    def reset_device():
        key_pin = (request.json or {}).get('id')
        if not key_pin: return jsonify({"success": False, "error": "Key PIN is required."}), 400
        try:
            result = KEYS_COLLECTION.update_one({"pin": key_pin}, {"$set": {"device_ids": []}})
            if result.matched_count == 0: return jsonify({"success": False, "error": "Key not found."}), 404
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    
    @app.route('/admin/reset_usage', methods=['POST'])
    @admin_required
    def reset_usage():
        key_pin = (request.json or {}).get('id')
        if not key_pin: return jsonify({"success": False, "error": "Key PIN is required."}), 400
        try:
            result = KEYS_COLLECTION.update_one({"pin": key_pin}, {"$set": {"used_today": 0}})
            if result.matched_count == 0: return jsonify({"success": False, "error": "Key not found."}), 404
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/history', methods=['GET'])
    @admin_required
    def get_history():
        key_pin = request.args.get('pin')
        if not key_pin: return jsonify({"success": False, "error": "Key PIN is required."}), 400
        try:
            history_rows = [make_serializable(h) for h in SEARCH_HISTORY_COLLECTION.find({"pin": key_pin}).sort("timestamp", -1).limit(100)]
            return jsonify({"success": True, "history": history_rows})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/users', methods=['GET'])
    @admin_required
    def admin_get_users():
        try:
            query = {}
            search = request.args.get('search')
            if search:
                query = {"$or": [{"name": {"$regex": search, "$options": "i"}}, {"phone": {"$regex": search, "$options": "i"}}]}
            users_rows = [make_serializable(u) for u in USERS_COLLECTION.find(query).sort("last_login", -1)]
            return jsonify({"success": True, "users": users_rows})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/ban_user', methods=['POST'])
    @admin_required
    def admin_ban_user():
        data, phone, ban_status = request.json or {}, data.get('phone'), bool(data.get('ban_status', False))
        if not phone: return jsonify({"success": False, "error": "Phone number is required."}), 400
        try:
            result = USERS_COLLECTION.update_one({"phone": phone}, {"$set": {"is_banned": ban_status}})
            if result.matched_count == 0: return jsonify({"success": False, "error": "User not found."}), 404
            return jsonify({"success": True, "message": f"User {'banned' if ban_status else 'unbanned'}."})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/note', methods=['GET', 'POST'])
    @admin_required
    def admin_global_note():
        try:
            if request.method == 'POST':
                note = (request.json or {}).get('note', '')
                CONFIG_COLLECTION.update_one({"config_id": "global_config"}, {"$set": {"global_note": note}}, upsert=True)
                return jsonify({"success": True, "message": "Note updated."})
            config = CONFIG_COLLECTION.find_one({"config_id": "global_config"})
            return jsonify({"success": True, "note": config.get("global_note", "") if config else ""})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

# --- Run ---
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    if not os.getenv("MONGO_URI"):
        print("Warning: MONGO_URI not set. App will not connect to DB.")
    app.run(host='0.0.0.0', port=port, debug=False)
