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
from user_agent import generate_user_agent # --- Used for all requests now ---

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

# ----------------------------------------------------------------- #
# --- NEW: All External API endpoints ---
# ----------------------------------------------------------------- #
# Old APIs (renamed)
VEHICLE_API_1 = os.getenv("VEHICLE_API_1", os.getenv("VEHICLE_API", "")) # Backwards compatible
PHONE_API_1 = os.getenv("PHONE_API_1", os.getenv("NUMBER_API", ""))     # Backwards compatible

# New Phone APIs
PHONE_API_2 = os.getenv("PHONE_API_2", "") # https://demon.taitanx.workers.dev/?mobile={}
PHONE_API_3 = os.getenv("PHONE_API_3", "") # https://ox.taitaninfo.workers.dev/?mobile={}

# New Vehicle API
VEHICLE_API_2 = os.getenv("VEHICLE_API_2", "") # https://api2.hazex.sbs/rc-info?number={}

# Updated/New Aadhaar APIs
AADHAAR_API = os.getenv("AADHAAR_API", "")       # https://ox.taitaninfo.workers.dev/?aadhar={}
AADHAAR_FAMILY_API = os.getenv("AADHAAR_FAMILY_API", "") # https://ox.taitaninfo.workers.dev/?family={}

# New Insta API
INSTA_API = os.getenv("INSTA_API", "") # https://nixonsmm.s77134867.workers.dev/api/insta/{}
# ----------------------------------------------------------------- #


# --- Database Setup (MongoDB) ---
DB_CLIENT = None
KEYS_COLLECTION = None
SEARCH_HISTORY_COLLECTION = None # --- NEW: For logging searches ---

def get_db_collection():
    """Establishes a connection to MongoDB and returns collections."""
    global DB_CLIENT, KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION
    
    if KEYS_COLLECTION is not None and SEARCH_HISTORY_COLLECTION is not None:
        return KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION

    MONGO_URI = os.getenv("MONGO_URI")
    if not MONGO_URI:
        print("CRITICAL: MONGO_URI environment variable is not set.")
        return None, None

    try:
        if DB_CLIENT is None:
            DB_CLIENT = pymongo.MongoClient(MONGO_URI, appName="knoxV2")
        
        db = DB_CLIENT.osint_db 
        
        # Keys Collection
        KEYS_COLLECTION = db.keys 
        KEYS_COLLECTION.create_index("pin", unique=True)
        
        # --- NEW: History Collection ---
        SEARCH_HISTORY_COLLECTION = db.history
        SEARCH_HISTORY_COLLECTION.create_index([("pin", 1), ("timestamp", -1)])
        SEARCH_HISTORY_COLLECTION.create_index("timestamp")
        
        print("Successfully connected to MongoDB and collections.")
        return KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        return None, None

# Initialize collections on startup
KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION = get_db_collection()


# ----------------------------------------------------------------- #
# --- Vahanx Scraper (Unchanged) ---
# ----------------------------------------------------------------- #
def get_details_from_vahanx(rc_number: str) -> dict:
    print(f"[Info] Querying vahanx.in scraper for {rc_number}...")
    try:
        ua = generate_user_agent()
        headers = {"User-Agent": ua}
        url = f"https://vahanx.in/rc-search/{rc_number.strip().upper()}"

        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        data_labels = [
            "Owner Name", "Father's Name", "Owner Serial No", "Model Name", "Maker Model",
            "Vehicle Class", "Fuel Type", "Fuel Norms", "Registration Date",
            "Insurance Company", "Insurance No", "Insurance Expiry", "Insurance Upto",
            "Fitness Upto", "Tax Upto", "PUC No", "PUC Upto",
            "Financier Name", "Registered RTO", "Address", "City Name", "Phone"
        ]
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

# ----------------------------------------------------------------- #
# --- NEW: Helper function for safe API calls ---
# ----------------------------------------------------------------- #
def safe_api_call(url: str, headers: dict) -> dict:
    """
    Performs a safe GET request, returning JSON or an error dict.
    """
    if not url:
        return {"error": "API endpoint not configured."}
    
    try:
        response = requests.get(url, timeout=15, headers=headers)
        response.raise_for_status()
        response_text = response.text
        return response.json()
    except JSONDecodeError:
        error_msg = f"API did not return valid JSON. Response: {response_text[:200]}..."
        print(f"[Error] {error_msg} from {url}")
        return {"error": error_msg}
    except requests.exceptions.RequestException as e:
        error_msg = f"Network error: {str(e)}"
        print(f"[Error] {error_msg} from {url}")
        return {"error": error_msg}
    except Exception as e:
        error_msg = f"Unknown error: {str(e)}"
        print(f"[Error] {error_msg} from {url}")
        return {"error": error_msg}

# ----------------------------------------------------------------- #
# --- NEW: Helper function for logging searches ---
# ----------------------------------------------------------------- #
def log_search(pin: str, lookup_type: str, number: str, device_id: str):
    """
    Logs a successful search to the history collection.
    """
    if SEARCH_HISTORY_COLLECTION is None:
        return

    try:
        log_entry = {
            "pin": pin,
            "lookup_type": lookup_type,
            "query": number,
            "device_id": device_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc)
        }
        SEARCH_HISTORY_COLLECTION.insert_one(log_entry)
    except Exception as e:
        print(f"Failed to log search for pin {pin}: {e}")


# ----------------------------------------------------------------- #
# --- Main Routes (Updated) ---
# ----------------------------------------------------------------- #

@app.route('/')
def home():
    """
    Renders the new homepage with service selection.
    """
    return render_template("index.html")

# --- NEW: Routes for each search page ---
@app.route('/search/<service_type>')
def search_page(service_type):
    """
    Renders the reusable search page for a specific service.
    """
    page_config = {
        "phone": {
            "title": "Phone Search",
            "placeholder": "Enter Phone Number (e.g., 9876543210)",
            "icon_class": "fas fa-mobile-alt"
        },
        "vehicle": {
            "title": "Vehicle Search",
            "placeholder": "Enter Vehicle Number (e.g., DL01AA1234)",
            "icon_class": "fas fa-car"
        },
        "aadhaar": {
            "title": "Aadhaar Info",
            "placeholder": "Enter Aadhaar Number (e.g., 123456789012)",
            "icon_class": "fas fa-id-card"
        },
        "family": {
            "title": "Aadhaar to Family",
            "placeholder": "Enter Aadhaar Number to find family",
            "icon_class": "fas fa-users"
        },
        "insta": {
            "title": "Instagram Info",
            "placeholder": "Enter Instagram Username",
            "icon_class": "fab fa-instagram"
        }
    }
    
    config = page_config.get(service_type)
    
    if not config:
        return abort(404)
        
    return render_template(
        "search_page.html",
        title=config["title"],
        placeholder=config["placeholder"],
        icon_class=config["icon_class"],
        service_type=service_type
    )


# --- HEAVILY UPDATED: API Search Route ---
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

    # --- Key Validation (Existing Logic) ---
    if not key:
        return jsonify({"error": "Invalid API Key"}), 401
    if key.get('expiry'):
        try:
            expiry_date = datetime.datetime.fromisoformat(key['expiry']).date()
            if datetime.date.today() > expiry_date:
                return jsonify({"error": "API Key has expired."}), 403
        except ValueError:
            pass # Ignore invalid date format
    if key.get('used_today', 0) >= key.get('limit_count', 10):
        return jsonify({"error": "Daily search limit reached for this key."}), 403
    if not key.get('device_id'):
        KEYS_COLLECTION.update_one(
            {"pin": pin, "device_id": None},
            {"$set": {"device_id": device_id}}
        )
        key = KEYS_COLLECTION.find_one({"pin": pin}) # Re-fetch key
    if key.get('device_id') != device_id:
        return jsonify({"error": "API Key is locked to another device."}), 403

    # --- NEW: Permission checks for all types ---
    permission_map = {
        "phone": "allow_phone",
        "vehicle": "allow_vehicle",
        "aadhaar": "allow_aadhaar",
        "family": "allow_family", # New
        "insta": "allow_insta"    # New
    }
    perm_key = permission_map.get(lookup_type)
    if not perm_key or not key.get(perm_key):
        return jsonify({"error": f"This key does not have permission for {lookup_type.title()} searches."}), 403

    # --- NEW: Standard headers for all API calls ---
    headers = {'User-Agent': generate_user_agent()}
    
    api_data = {}

    try:
        # --- UPDATED: Phone Search (3 APIs) ---
        if lookup_type == "phone":
            api_data['result_1'] = safe_api_call(PHONE_API_1.format(number), headers)
            api_data['result_2'] = safe_api_call(PHONE_API_2.format(number), headers)
            api_data['result_3'] = safe_api_call(PHONE_API_3.format(number), headers)

        # --- UPDATED: Vehicle Search (2 APIs + 1 Scraper) ---
        elif lookup_type == "vehicle":
            api_data['result_1'] = safe_api_call(VEHICLE_API_1.format(number), headers)
            api_data['result_2'] = safe_api_call(VEHICLE_API_2.format(number), headers)
            api_data['result_3'] = get_details_from_vahanx(number) # Scraper

        # --- UPDATED: Aadhaar Search (1 New API) ---
        elif lookup_type == "aadhaar":
            api_data = safe_api_call(AADHAAR_API.format(number), headers)

        # --- NEW: Aadhaar to Family Search ---
        elif lookup_type == "family":
            api_data = safe_api_call(AADHAAR_FAMILY_API.format(number), headers)
            
        # --- NEW: Insta to Info Search ---
        elif lookup_type == "insta":
            api_data = safe_api_call(INSTA_API.format(number), headers)

        else:
            return jsonify({"error": "Invalid lookup type"}), 400

    except Exception as e:
        return jsonify({"error": f"Failed to fetch data from external API/scraper. Detail: {str(e)}"}), 502
    
    # --- Increment usage and log search (Moved to end) ---
    KEYS_COLLECTION.update_one(
        {"pin": pin},
        {"$inc": {"used_today": 1}}
    )
    
    # --- NEW: Log the search ---
    log_search(pin, lookup_type, number, device_id)

    key_info = {
        "searches_left": key.get('limit_count', 10) - key.get('used_today', 0) - 1,
        "expiry_date": key.get('expiry') or "Never"
    }

    # --- UPDATED: Final response structure ---
    # Merge api_data (which could be a single dict or dict of dicts)
    # with status, key_status, and dev info.
    final_response = {
        **(api_data if isinstance(api_data, dict) else {"result": api_data}),
        "status": "success",
        "key_status": key_info,
        "dev": "RAHUL SHARMA" # As requested
    }
    return jsonify(final_response)


# ----------------------------------------------------------------- #
# --- Admin routes (Rewritten for MongoDB + New Features) ---
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
        if KEYS_COLLECTION is None:
            return jsonify({"success": False, "error": "Database not configured."}), 500

        data = request.get_json(silent=True) or {}
        username = data.get('username')
        password = data.get('password')
            
        if not username or not password:
            return jsonify({"success": False, "error": "Username and password are required"}), 400
            
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['is_admin'] = True
            # No need to send keys on login, admin.html JS will call /admin/keys
            return jsonify({"success": True})
        
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    @app.route('/admin/keys', methods=['GET'])
    @admin_required
    def admin_get_keys():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        
        try:
            keys_rows = list(KEYS_COLLECTION.find().sort("created_at", pymongo.DESCENDING))
            keys_list = []
            for row in keys_rows:
                row['_id'] = str(row['_id']) 
                row['id'] = row['pin'] # For frontend compatibility
                keys_list.append(row)
            return jsonify({"success": True, "keys": keys_list})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/add', methods=['POST'])
    @admin_required
    def add_key():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500

        data = request.json or {}
        pin = data.get('pin')
        limit = data.get('limit', 10)
        expiry = data.get('expiry')
        
        # --- NEW: Handle list of permissions ---
        permissions = data.get('permissions', []) # Expects a list like ["phone", "vehicle"]

        if not pin:
            return jsonify({"success": False, "error": "PIN cannot be empty."}), 400
        if not isinstance(limit, int) or limit < 0:
            limit = 10

        key_doc = {
            "pin": pin,
            "limit_count": limit,
            "expiry": expiry if expiry else None,
            "allow_phone": 1 if "phone" in permissions else 0,
            "allow_vehicle": 1 if "vehicle" in permissions else 0,
            "allow_aadhaar": 1 if "aadhaar" in permissions else 0,
            "allow_family": 1 if "family" in permissions else 0,
            "allow_insta": 1 if "insta" in permissions else 0,
            "used_today": 0,
            "device_id": None,
            "created_at": datetime.datetime.now(datetime.timezone.utc)
        }
        
        try:
            KEYS_COLLECTION.insert_one(key_doc)
            return jsonify({"success": True})
        except DuplicateKeyError:
            return jsonify({"success": False, "error": "This PIN already exists."}), 409
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
            
    # --- NEW: Route to update an existing key ---
    @app.route('/admin/update', methods=['POST'])
    @admin_required
    def update_key():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500

        data = request.json or {}
        pin = data.get('pin') # The key to update
        
        limit = data.get('limit')
        expiry = data.get('expiry')
        permissions = data.get('permissions') # List of strings

        if not pin:
            return jsonify({"success": False, "error": "PIN is required."}), 400
        
        update_doc = {"$set": {}}
        
        if isinstance(limit, int) and limit >= 0:
            update_doc["$set"]["limit_count"] = limit
            
        if expiry is not None: # Allow setting expiry to null/empty string
            update_doc["$set"]["expiry"] = expiry if expiry else None
            
        if isinstance(permissions, list):
            update_doc["$set"]["allow_phone"] = 1 if "phone" in permissions else 0
            update_doc["$set"]["allow_vehicle"] = 1 if "vehicle" in permissions else 0
            update_doc["$set"]["allow_aadhaar"] = 1 if "aadhaar" in permissions else 0
            update_doc["$set"]["allow_family"] = 1 if "family" in permissions else 0
            update_doc["$set"]["allow_insta"] = 1 if "insta" in permissions else 0

        if not update_doc["$set"]:
            return jsonify({"success": False, "error": "No valid fields to update."}), 400
            
        try:
            result = KEYS_COLLECTION.update_one({"pin": pin}, update_doc)
            if result.matched_count == 0:
                return jsonify({"success": False, "error": "Key not found."}), 404
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/delete', methods=['POST'])
    @admin_required
    def delete_key():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        
        # --- BUG FIX: Key is 'id', which holds the 'pin' (string or int) ---
        key_pin = (request.json or {}).get('id') 
        if not key_pin:
            return jsonify({"success": False, "error": "Key PIN is required."}), 400
        
        try:
            # The PIN is the 'id' from the frontend, no parseInt needed
            result = KEYS_COLLECTION.delete_one({"pin": key_pin})
            if result.deleted_count == 0:
                return jsonify({"success": False, "error": "Key not found."}), 404
            
            # --- NEW: Also delete search history for this key ---
            if SEARCH_HISTORY_COLLECTION is not None:
                SEARCH_HISTORY_COLLECTION.delete_many({"pin": key_pin})
                
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    
    @app.route('/admin/reset_device', methods=['POST'])
    @admin_required
    def reset_device():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500

        # --- BUG FIX: Key is 'id', which holds the 'pin' (string or int) ---
        key_pin = (request.json or {}).get('id')
        if not key_pin:
            return jsonify({"success": False, "error": "Key PIN is required."}), 400
        
        try:
            result = KEYS_COLLECTION.update_one(
                {"pin": key_pin},
                {"$set": {"device_id": None}}
            )
            if result.matched_count == 0:
                return jsonify({"success": False, "error": "Key not found."}), 404
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # --- NEW: Route to get search history for a key ---
    @app.route('/admin/history', methods=['GET'])
    @admin_required
    def get_history():
        if SEARCH_HISTORY_COLLECTION is None:
            return jsonify({"success": False, "error": "Database not configured."}), 500
        
        key_pin = request.args.get('pin')
        if not key_pin:
            return jsonify({"success": False, "error": "Key PIN is required."}), 400
            
        try:
            history_rows = list(SEARCH_HISTORY_COLLECTION.find(
                {"pin": key_pin}
            ).sort("timestamp", pymongo.DESCENDING).limit(100))
            
            # Convert ObjectId to string for JSON serialization
            history_list = []
            for row in history_rows:
                row['_id'] = str(row['_id'])
                if 'timestamp' in row:
                    row['timestamp'] = row['timestamp'].isoformat()
                history_list.append(row)
                
            return jsonify({"success": True, "history": history_list})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/admin/logout', methods=['POST'])
    def admin_logout():
        session.pop('is_admin', None)
        return jsonify({"success": True})

# --- Run ---
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    if not os.getenv("MONGO_URI"):
        print("Warning: MONGO_URI not set. App will not connect to DB.")
    # Set debug=False for production
    app.run(host='0.0.0.0', port=port, debug=False)
