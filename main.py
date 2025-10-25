#!/usr/bin/env python3
import os
import datetime
import json
import requests
import pymongo
from pymongo.errors import DuplicateKeyError
from requests.exceptions import JSONDecodeError
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, abort
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from user_agent import generate_user_agent

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

# --- External API endpoints ---
VEHICLE_API_1 = os.getenv("VEHICLE_API_1", os.getenv("VEHICLE_API", ""))
PHONE_API_1 = os.getenv("PHONE_API_1", os.getenv("NUMBER_API", ""))
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
USERS_COLLECTION = None # --- NEW: For user logins ---
CONFIG_COLLECTION = None # --- NEW: For global settings ---

def get_db_collections():
    """Establishes a connection to MongoDB and returns all collections."""
    global DB_CLIENT, KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION, USERS_COLLECTION, CONFIG_COLLECTION
    
    if all([KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION, USERS_COLLECTION, CONFIG_COLLECTION]):
        return

    MONGO_URI = os.getenv("MONGO_URI")
    if not MONGO_URI:
        print("CRITICAL: MONGO_URI environment variable is not set.")
        return

    try:
        if DB_CLIENT is None:
            DB_CLIENT = pymongo.MongoClient(MONGO_URI, appName="knoxV3")
        
        db = DB_CLIENT.osint_db 
        
        KEYS_COLLECTION = db.keys 
        KEYS_COLLECTION.create_index("pin", unique=True)
        
        SEARCH_HISTORY_COLLECTION = db.history
        SEARCH_HISTORY_COLLECTION.create_index([("pin", 1), ("timestamp", -1)])
        
        # --- NEW: User Collection ---
        USERS_COLLECTION = db.users
        USERS_COLLECTION.create_index("phone", unique=True)
        
        # --- NEW: Config Collection ---
        CONFIG_COLLECTION = db.config
        CONFIG_COLLECTION.create_index("config_id", unique=True)
        
        print("Successfully connected to MongoDB and all collections.")
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        # Set all to None on failure
        KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION, USERS_COLLECTION, CONFIG_COLLECTION = (None, None, None, None)

# Initialize collections on startup
get_db_collections()

# --- Vahanx Scraper (Unchanged) ---
def get_details_from_vahanx(rc_number: str) -> dict:
    print(f"[Info] Querying vahanx.in scraper for {rc_number}...")
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
                    if value_tag:
                        data[label] = value_tag.get_text(strip=True)
        return data
    except Exception as e:
        print(f"Vahanx scraper failed: {e}")
        return {"error": f"Vahanx scraper failed: {str(e)}"}

# --- Safe API Call Helper (Unchanged) ---
def safe_api_call(url: str, headers: dict) -> dict:
    if not url:
        return {"error": "API endpoint not configured."}
    try:
        response = requests.get(url, timeout=15, headers=headers)
        response.raise_for_status()
        response_text = response.text
        return response.json()
    except JSONDecodeError:
        error_msg = f"API did not return valid JSON. Response: {response_text[:200]}..."
        return {"error": error_msg}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unknown error: {str(e)}"}

# --- Log Search Helper (Unchanged) ---
def log_search(pin: str, lookup_type: str, number: str, device_id: str):
    if SEARCH_HISTORY_COLLECTION is None: return
    try:
        log_entry = {"pin": pin, "lookup_type": lookup_type, "query": number, "device_id": device_id, "timestamp": datetime.datetime.now(datetime.timezone.utc)}
        SEARCH_HISTORY_COLLECTION.insert_one(log_entry)
    except Exception as e:
        print(f"Failed to log search for pin {pin}: {e}")

# ----------------------------------------------------------------- #
# --- Main App Routes (Homepage, Login, Logout) ---
# ----------------------------------------------------------------- #

@app.route('/')
def home():
    """
    Renders the new homepage.
    Checks session for user login info.
    """
    user_info = None
    if 'user_phone' in session:
        user_info = {
            "name": session.get('user_name'),
            "phone": session.get('user_phone')
        }
    return render_template("index.html", user_info=user_info)

# --- NEW: User Login Routes ---
@app.route('/login', methods=['GET', 'POST'])
def user_login():
    """
    GET: Shows the user login page.
    POST: Logs the user in, stores info in DB and session.
    """
    if 'user_phone' in session:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()

        if not name or not phone or not phone.isdigit() or len(phone) < 10:
            return render_template("user_login.html", error="Please enter a valid name and 10-digit phone number.")
            
        if USERS_COLLECTION is None:
            return render_template("user_login.html", error="Database connection error. Please try again later.")
            
        try:
            # Store/update user info
            USERS_COLLECTION.update_one(
                {"phone": phone},
                {
                    "$set": {"name": name, "last_login": datetime.datetime.now(datetime.timezone.utc)},
                    "$setOnInsert": {"first_login": datetime.datetime.now(datetime.timezone.utc)}
                },
                upsert=True
            )
            
            # Set session
            session['user_phone'] = phone
            session['user_name'] = name
            session.permanent = True # Make session last
            
            return redirect(url_for('home'))
            
        except Exception as e:
            print(f"User login error: {e}")
            return render_template("user_login.html", error="An error occurred. Please try again.")

    return render_template("user_login.html")

@app.route('/logout')
def user_logout():
    """
    Logs the user out by clearing the session.
    """
    session.pop('user_phone', None)
    session.pop('user_name', None)
    return redirect(url_for('home'))

# --- Search Page Route (Unchanged) ---
@app.route('/search/<service_type>')
def search_page(service_type):
    page_config = {
        "phone": {"title": "Phone Search", "placeholder": "Enter Phone Number (e.g., 9876543210)", "icon_class": "fas fa-mobile-alt"},
        "vehicle": {"title": "Vehicle Search", "placeholder": "Enter Vehicle Number (e.g., DL01AA1234)", "icon_class": "fas fa-car"},
        "aadhaar": {"title": "Aadhaar Info", "placeholder": "Enter Aadhaar Number (e.g., 123456789012)", "icon_class": "fas fa-id-card"},
        "family": {"title": "Aadhaar to Family", "placeholder": "Enter Aadhaar Number to find family", "icon_class": "fas fa-users"},
        "insta": {"title": "Instagram Info", "placeholder": "Enter Instagram Username", "icon_class": "fab fa-instagram"}
    }
    config = page_config.get(service_type)
    if not config: return abort(404)
    return render_template("search_page.html", **config, service_type=service_type)

# ----------------------------------------------------------------- #
# --- Main API Routes (/api/search, /api/config) ---
# ----------------------------------------------------------------- #

# --- NEW: Public config route for global note ---
@app.route('/api/config')
def get_public_config():
    """
    Returns public configuration, like the admin-set global note.
    """
    if CONFIG_COLLECTION is None:
        return jsonify({"note": None})
        
    config = CONFIG_COLLECTION.find_one({"config_id": "global_config"})
    if config:
        return jsonify({"note": config.get("global_note")})
    return jsonify({"note": None})


@app.route('/api/search', methods=['POST'])
def search():
    if KEYS_COLLECTION is None:
        return jsonify({"error": "Database connection is not established."}), 500

    data = request.json or {}
    lookup_type = data.get('type')
    number = data.get('number', '').strip()
    pin = data.get('pin')
    device_id = data.get('deviceId')

    if not all([lookup_type, number, pin, device_id]):
        return jsonify({"error": "Missing required fields."}), 400

    key = KEYS_COLLECTION.find_one({"pin": pin})

    # --- Key Validation (Expiry, Limit) ---
    if not key:
        return jsonify({"error": "Invalid API Key"}), 401
    if key.get('expiry'):
        try:
            expiry_date = datetime.datetime.fromisoformat(key['expiry']).date()
            if datetime.date.today() > expiry_date:
                return jsonify({"error": "API Key has expired."}), 403
        except ValueError: pass
    if key.get('used_today', 0) >= key.get('limit_count', 10):
        return jsonify({"error": "Daily search limit reached for this key."}), 403

    # --- NEW: Device Limit Logic ---
    device_limit = key.get('device_limit', 1) # Default to 1 device
    device_ids = key.get('device_ids', [])     # Get list of bound devices
    
    if device_id not in device_ids:
        # Device is not bound, check if there's space
        if len(device_ids) < device_limit:
            # Space available, bind this new device
            KEYS_COLLECTION.update_one(
                {"pin": pin},
                {"$push": {"device_ids": device_id}}
            )
        else:
            # No space, reject
            return jsonify({"error": f"Device limit ({device_limit}) reached for this key."}), 403
    # --- END: Device Limit Logic ---

    # --- Permission checks ---
    permission_map = {"phone": "allow_phone", "vehicle": "allow_vehicle", "aadhaar": "allow_aadhaar", "family": "allow_family", "insta": "allow_insta"}
    perm_key = permission_map.get(lookup_type)
    if not perm_key or not key.get(perm_key):
        return jsonify({"error": f"This key does not have permission for {lookup_type.title()} searches."}), 403

    # --- API Calls ---
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
        return jsonify({"error": f"Failed to fetch data from external API/scraper. Detail: {str(e)}"}), 502
    
    # --- Increment usage and log search ---
    KEYS_COLLECTION.update_one({"pin": pin}, {"$inc": {"used_today": 1}})
    log_search(pin, lookup_type, number, device_id)

    key_info = {
        "searches_left": key.get('limit_count', 10) - key.get('used_today', 0) - 1,
        "expiry_date": key.get('expiry') or "Never"
    }
    
    final_response = {
        **(api_data if isinstance(api_data, dict) else {"result": api_data}),
        "status": "success",
        "key_status": key_info,
        "dev": "RAHUL SHARMA" # As requested
    }
    return jsonify(final_response)


# ----------------------------------------------------------------- #
# --- Admin Panel Routes ---
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

    @app.route('/admin')
    def admin_page():
        return render_template("admin.html")

    @app.route('/admin/login', methods=['POST'])
    def admin_login():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        data = request.get_json(silent=True) or {}
        username, password = data.get('username'), data.get('password')
        if not username or not password:
            return jsonify({"success": False, "error": "Username and password are required"}), 400
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['is_admin'] = True
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    @app.route('/admin/logout', methods=['POST'])
    def admin_logout():
        session.pop('is_admin', None)
        return jsonify({"success": True})

    @app.route('/admin/keys', methods=['GET'])
    @admin_required
    def admin_get_keys():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        try:
            keys_rows = list(KEYS_COLLECTION.find().sort("created_at", pymongo.DESCENDING))
            for row in keys_rows:
                row['_id'] = str(row['_id']) 
                row['id'] = row['pin'] # For frontend
            return jsonify({"success": True, "keys": keys_rows})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/add', methods=['POST'])
    @admin_required
    def add_key():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        data = request.json or {}
        pin = data.get('pin')
        if not pin: return jsonify({"success": False, "error": "PIN cannot be empty."}), 400
        
        limit = data.get('limit', 10)
        expiry = data.get('expiry')
        permissions = data.get('permissions', [])
        device_limit = data.get('device_limit', 1) # --- NEW ---

        key_doc = {
            "pin": pin,
            "limit_count": int(limit),
            "expiry": expiry if expiry else None,
            "device_limit": int(device_limit), # --- NEW ---
            "device_ids": [], # --- NEW ---
            "allow_phone": 1 if "phone" in permissions else 0,
            "allow_vehicle": 1 if "vehicle" in permissions else 0,
            "allow_aadhaar": 1 if "aadhaar" in permissions else 0,
            "allow_family": 1 if "family" in permissions else 0,
            "allow_insta": 1 if "insta" in permissions else 0,
            "used_today": 0,
            "created_at": datetime.datetime.now(datetime.timezone.utc)
        }
        try:
            KEYS_COLLECTION.insert_one(key_doc)
            return jsonify({"success": True})
        except DuplicateKeyError:
            return jsonify({"success": False, "error": "This PIN already exists."}), 409
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/update', methods=['POST'])
    @admin_required
    def update_key():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        data = request.json or {}
        pin = data.get('pin')
        if not pin: return jsonify({"success": False, "error": "PIN is required."}), 400
        
        update_doc = {"$set": {}}
        if 'limit' in data: update_doc["$set"]["limit_count"] = int(data['limit'])
        if 'expiry' in data: update_doc["$set"]["expiry"] = data['expiry'] if data['expiry'] else None
        if 'device_limit' in data: update_doc["$set"]["device_limit"] = int(data['device_limit']) # --- NEW ---
            
        if 'permissions' in data:
            perms = data['permissions']
            update_doc["$set"]["allow_phone"] = 1 if "phone" in perms else 0
            update_doc["$set"]["allow_vehicle"] = 1 if "vehicle" in perms else 0
            update_doc["$set"]["allow_aadhaar"] = 1 if "aadhaar" in perms else 0
            update_doc["$set"]["allow_family"] = 1 if "family" in perms else 0
            update_doc["$set"]["allow_insta"] = 1 if "insta" in perms else 0

        if not update_doc["$set"]:
            return jsonify({"success": False, "error": "No valid fields to update."}), 400
            
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
            if SEARCH_HISTORY_COLLECTION:
                SEARCH_HISTORY_COLLECTION.delete_many({"pin": key_pin})
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    
    @app.route('/admin/reset_device', methods=['POST'])
    @admin_required
    def reset_device():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        key_pin = (request.json or {}).get('id')
        if not key_pin: return jsonify({"success": False, "error": "Key PIN is required."}), 400
        try:
            # --- UPDATED: Set device_ids to empty array ---
            result = KEYS_COLLECTION.update_one({"pin": key_pin}, {"$set": {"device_ids": []}})
            if result.matched_count == 0: return jsonify({"success": False, "error": "Key not found."}), 404
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/history', methods=['GET'])
    @admin_required
    def get_history():
        if SEARCH_HISTORY_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        key_pin = request.args.get('pin')
        if not key_pin: return jsonify({"success": False, "error": "Key PIN is required."}), 400
        try:
            history_rows = list(SEARCH_HISTORY_COLLECTION.find({"pin": key_pin}).sort("timestamp", pymongo.DESCENDING).limit(100))
            for row in history_rows:
                row['_id'] = str(row['_id'])
                if 'timestamp' in row: row['timestamp'] = row['timestamp'].isoformat()
            return jsonify({"success": True, "history": history_rows})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # --- NEW: Admin route for Global Note ---
    @app.route('/admin/note', methods=['GET', 'POST'])
    @admin_required
    def admin_global_note():
        if CONFIG_COLLECTION is None:
            return jsonify({"success": False, "error": "Database not configured."}), 500
            
        try:
            if request.method == 'POST':
                note = (request.json or {}).get('note', '')
                CONFIG_COLLECTION.update_one(
                    {"config_id": "global_config"},
                    {"$set": {"global_note": note}},
                    upsert=True
                )
                return jsonify({"success": True, "message": "Note updated."})
            
            # GET request
            config = CONFIG_COLLECTION.find_one({"config_id": "global_config"})
            note = config.get("global_note", "") if config else ""
            return jsonify({"success": True, "note": note})
            
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # --- NEW: Admin route for User List ---
    @app.route('/admin/users', methods=['GET'])
    @admin_required
    def admin_get_users():
        if USERS_COLLECTION is None:
            return jsonify({"success": False, "error": "Database not configured."}), 500
            
        try:
            users_rows = list(USERS_COLLECTION.find().sort("last_login", pymongo.DESCENDING))
            for row in users_rows:
                row['_id'] = str(row['_id'])
                if 'last_login' in row: row['last_login'] = row['last_login'].isoformat()
                if 'first_login' in row: row['first_login'] = row['first_login'].isoformat()
            return jsonify({"success": True, "users": users_rows})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

# --- Run ---
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    if not os.getenv("MONGO_URI"):
        print("Warning: MONGO_URI not set. App will not connect to DB.")
    app.run(host='0.0.0.0', port=port, debug=False)
