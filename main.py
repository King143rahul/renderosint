#!/usr/bin/env python3
import os
import datetime
import json
import requests
import pymongo
import random
import string
from pymongo.errors import DuplicateKeyError
from requests.exceptions import JSONDecodeError, ConnectTimeout, ReadTimeout
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, abort
from dotenv import load_dotenv

from bson import ObjectId

# --- Initialization ---
load_dotenv()
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "fallback-dev-key-change-in-prod")
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = True # Force secure cookies (requires HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
# --- External API Support (User Defined) ---
PHONE_API_DEVIL_URL = os.getenv("DEVIL_PHONE_API", "")
VEHICLE_API_BASIC_URL = os.getenv("VEHICLE_BASIC_API", "")
VEHICLE_API_FULL_URL = os.getenv("VEHICLE_FULL_API", "")
AADHAAR_INFO_API_URL = os.getenv("AADHAAR_INFO_API", "")
AADHAAR_FAMILY_API_URL = os.getenv("AADHAAR_FAMILY_API", "")
GST_API_URL = os.getenv("GST_API_URL", "")

# ----------------------------------------------------------------- #


# --- Database Setup (MongoDB) ---
DB_CLIENT = None
KEYS_COLLECTION = None
SEARCH_HISTORY_COLLECTION = None
USERS_COLLECTION = None
CONFIG_COLLECTION = None

# New Data Collections
PHONES_COLLECTION = None
VEHICLES_COLLECTION = None
AADHAAR_COLLECTION = None
FAMILIES_COLLECTION = None
GSTS_COLLECTION = None

PLANS_COLLECTION = None
PURCHASE_REQUESTS_COLLECTION = None

def get_db_collections():
    global DB_CLIENT, KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION, USERS_COLLECTION, CONFIG_COLLECTION
    global PHONES_COLLECTION, VEHICLES_COLLECTION, AADHAAR_COLLECTION, FAMILIES_COLLECTION, GSTS_COLLECTION
    
    if all([KEYS_COLLECTION, SEARCH_HISTORY_COLLECTION, USERS_COLLECTION, CONFIG_COLLECTION, PHONES_COLLECTION, VEHICLES_COLLECTION, AADHAAR_COLLECTION, FAMILIES_COLLECTION, GSTS_COLLECTION]):
        return
    MONGO_URI = os.getenv("MONGO_URI")
    if not MONGO_URI:
        print("CRITICAL: MONGO_URI environment variable is not set.")
        return
    try:
        if DB_CLIENT is None:
            DB_CLIENT = pymongo.MongoClient(MONGO_URI, appName="knoxV4") # Updated appName
        db = DB_CLIENT.osint_db
        KEYS_COLLECTION = db.keys
        KEYS_COLLECTION.create_index("pin", unique=True)
        SEARCH_HISTORY_COLLECTION = db.history
        SEARCH_HISTORY_COLLECTION.create_index([("pin", 1), ("timestamp", -1)])
        USERS_COLLECTION = db.users
        USERS_COLLECTION.create_index("phone", unique=True)
        CONFIG_COLLECTION = db.config
        CONFIG_COLLECTION.create_index("config_id", unique=True)
        
        # Initialize Data Collections
        PHONES_COLLECTION = db.phones
        VEHICLES_COLLECTION = db.vehicles
        AADHAAR_COLLECTION = db.aadhaar
        FAMILIES_COLLECTION = db.families
        GSTS_COLLECTION = db.gsts

        
        # Initialize Plans and Requests Collections
        global PLANS_COLLECTION, PURCHASE_REQUESTS_COLLECTION
        PLANS_COLLECTION = db.plans
        PURCHASE_REQUESTS_COLLECTION = db.purchase_requests
        
        print("Successfully connected to MongoDB and all collections.")
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        KEYS_COLLECTION = None

get_db_collections()

# --- Helper Functions (Scraper, API calls, Logging) ---


def safe_api_call(url: str, headers: dict, timeout=15) -> dict:
    # Deprecated for most services, keeping for legacy/external specific calls if needed
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

# --- Generic MongoDB Search Helper ---
def search_mongo(collection, query_field, value):
    """Searches a MongoDB collection for a document."""
    if collection is None:
        return {"error": "Database not initialized for this service."}
    try:
        # Flexible search: try exact match first
        query = {query_field: value}
        doc = collection.find_one(query)
        
        # If no result, try case-insensitive regex if applicable
        if not doc and isinstance(value, str):
             doc = collection.find_one({query_field: {"$regex": f"^{value}$", "$options": "i"}})
             
        if doc:
            return make_serializable(doc)
        return {"error": "No records found.", "status": "Not Found"}
    except Exception as e:
        return {"error": f"Database error: {str(e)}"}

def log_search(pin: str, lookup_type: str, number: str, device_id: str):
    if SEARCH_HISTORY_COLLECTION is None: return
    try:
        log_entry = {"pin": pin, "lookup_type": lookup_type, "query": number, "device_id": device_id, "timestamp": datetime.datetime.now(datetime.timezone.utc)}
        SEARCH_HISTORY_COLLECTION.insert_one(log_entry)
    except Exception as e:
        print(f"Failed to log search: {e}")

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
        
        # --- NEW: Check if user is banned ---
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
            session.permanent = True
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
        "gst": {"title": "GST Info", "placeholder": "Enter GST Number", "icon_class": "fas fa-file-invoice-dollar"},

    }
    config = page_config.get(service_type)
    if not config: return abort(404)
    return render_template("search_page.html", **config, service_type=service_type)

@app.route('/api/config')
def get_public_config():
    if CONFIG_COLLECTION is None: return jsonify({"note": None})
    config = CONFIG_COLLECTION.find_one({"config_id": "global_config"})
    return jsonify({"note": config.get("global_note") if config else None})

# --- External API Support ---
PHONE_API_DEVIL_URL = os.getenv("DEVIL_PHONE_API", "")

def fetch_devil_phone_data(number):
    """Fetches phone data from Devil Hosting API"""
    if not PHONE_API_DEVIL_URL:
        return None
        
    try:
        url = f"{PHONE_API_DEVIL_URL}{number}"
        res = requests.get(url, timeout=10)
        data = res.json()
        
        if not data.get('status') or not data.get('results'):
            return None
            
        # Normalize Data
        normalized_results = []
        for item in data['results']:
            normalized_results.append({
                "mobile": item.get('mobile'),
                "name": item.get('name'),
                "father_name": item.get('fname'),
                "address": item.get('address'),
                "alt_mobile": item.get('alt'),
                "circle": item.get('circle'),
                "id_number": item.get('id'),
                "email": item.get('email')
            })
            
        return {"results": normalized_results}
    except Exception as e:
        print(f"Devil API Error: {e}")
        return None

# --- Vehicle API Support ---


def fetch_vehicle_basic(rc_number):
    try:
        # Check if the URL already has the number appended (if user put placeholder in env)
        # But for simplicity, we assume env var ends with = and we simple append, or formatting.
        # Adjusted to be safe: formatting logic
        url = f"{VEHICLE_API_BASIC_URL}{rc_number}"
        res = requests.get(url, timeout=15)
        return res.json()
    except Exception as e:
        print(f"Vehicle Basic API Error: {e}")
        return None

def fetch_vehicle_full(rc_number):
    try:
        url = f"{VEHICLE_API_FULL_URL}{rc_number}"
        print(f"DEBUG: Fetching Vehicle Full from {url}")
        res = requests.get(url, timeout=20)
        print(f"DEBUG: Vehicle API Status: {res.status_code}")
        try:
            return res.json()
        except:
             print(f"DEBUG: Vehicle Invalid JSON: {res.text[:100]}")
             return None
    except Exception as e:
        print(f"Vehicle Full API Error: {e}")
        return None

# --- New API Support (Aadhaar/GST) ---
AADHAAR_INFO_API_URL = os.getenv("AADHAAR_INFO_API", "")
AADHAAR_FAMILY_API_URL = os.getenv("AADHAAR_FAMILY_API", "")
GST_API_URL = os.getenv("GST_API_URL", "")

def fetch_aadhaar_info(number):
    if not AADHAAR_INFO_API_URL: 
        print("DEBUG: Aadhaar Info API URL is not set.")
        return None
    if "api.example.com" in AADHAAR_INFO_API_URL:
        print("DEBUG: Using placeholder URL for Aadhaar API. Please configure .env.")
        return {"error": "API not configured (Placeholder URL detected)"}

    try:
        url = f"{AADHAAR_INFO_API_URL}{number}"
        print(f"DEBUG: Fetching Aadhaar Info from {url}")
        
        # Add User-Agent to prevent 403/Blocking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        res = requests.get(url, headers=headers, timeout=15)
        
        print(f"DEBUG: Aadhaar API Status: {res.status_code}")
        print(f"DEBUG: Aadhaar Raw Response: {res.text[:1000]}")
        
        try:
            data = res.json()
        except:
             print(f"DEBUG: Invalid JSON response: {res.text[:100]}")
             return None

        # Robust Parsing
        results = []
        
        # Case 1: Nested {"results": {"records": [...]}} (User provided structure)
        if isinstance(data, dict) and isinstance(data.get('results'), dict) and data['results'].get('records'):
             results = data['results']['records']
        # Case 2: Standard {"results": [...]}
        elif isinstance(data, dict) and isinstance(data.get('results'), list):
             results = data['results']
        # Case 3: Direct list [...]
        elif isinstance(data, list):
             results = data
        # Case 4: Wrapped data {"data": ...}
        elif isinstance(data, dict) and data.get('data'):
             if isinstance(data['data'], list): results = data['data']
             else: results = [data['data']]
        # Case 5: Single Object (if not error)
        elif isinstance(data, dict) and not data.get('error') and data.get('status') != False:
             # Check if it has 'mobile' or 'aadhaar_number' to be sure it's a record
             if data.get('mobile') or data.get('aadhaar_number'):
                results = [data]
        
        normalized = []
        for item in results:
             if not isinstance(item, dict): continue
             # Remove raw/branding fields if any
             clean_item = {k: v for k, v in item.items() if k not in ['status', 'branding', 'source', 'error', 'success', '_source']}
             if clean_item: # Only add if not empty
                normalized.append(clean_item)
             
        print(f"DEBUG: Parsed {len(normalized)} records.")
        return {"results": normalized} if normalized else None
    except Exception as e:
        print(f"Aadhaar Info API Error: {e}")
        return None

def fetch_aadhaar_family(number):
    if not AADHAAR_FAMILY_API_URL: return None
    try:
        url = f"{AADHAAR_FAMILY_API_URL}{number}"
        res = requests.get(url, timeout=15)
        data = res.json()
        return data
    except Exception as e:
        print(f"Aadhaar Family API Error: {e}")
        return None

def fetch_gst_details(number):
    if not GST_API_URL: return None
    try:
        url = f"{GST_API_URL}{number}"
        res = requests.get(url, timeout=15)
        data = res.json()
        return data
    except Exception as e:
        print(f"GST API Error: {e}")
        return None

@app.route('/api/search', methods=['POST'])
def search():
    data = request.json or {}
    lookup_type = data.get('type')
    number = data.get('number', '').strip()
    pin = data.get('pin')
    device_id = data.get('deviceId')
    
    if not all([lookup_type, number, pin, device_id]):
        return jsonify({"error": "Missing required fields."}), 400

    # --- Database Check ---
    if KEYS_COLLECTION is None:
        return jsonify({"error": "Database not connected. Please check configuration."}), 500

    # Key Validation
    key = KEYS_COLLECTION.find_one({"pin": pin})
    if not key: return jsonify({"error": "Invalid API Key"}), 401
    
    if key.get('expiry'):
        try:
            if datetime.date.today() > datetime.datetime.fromisoformat(key['expiry']).date():
                return jsonify({"error": "API Key has expired."}), 403
        except ValueError: pass
    
    today_start = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    searches_today = SEARCH_HISTORY_COLLECTION.count_documents({
        "pin": pin,
        "timestamp": {"$gte": today_start}
    })
    
    if searches_today >= key.get('limit_count', 10):
        return jsonify({"error": "Daily search limit reached for this key."}), 403

    device_limit = key.get('device_limit', 1)
    device_ids = key.get('device_ids', [])
    if device_id not in device_ids:
        if len(device_ids) < device_limit:
            KEYS_COLLECTION.update_one({"pin": pin}, {"$push": {"device_ids": device_id}})
        else:
            return jsonify({"error": f"Device limit ({device_limit}) reached for this key."}), 403

    # Permission check (UPDATED: removed insta, upi, pincode, ip, imei, pksim, ifsc)
    permission_map = {
        "phone": "allow_phone", "vehicle": "allow_vehicle", "aadhaar": "allow_aadhaar",
        "family": "allow_family", 
        "gst": "allow_gst"
    }
    
    perm_key = permission_map.get(lookup_type)
    if perm_key and not key.get(perm_key):
        return jsonify({"error": f"This key does not have permission for {lookup_type.title()} searches."}), 403
        
    if not perm_key:
         return jsonify({"error": "Invalid service type requested."}), 400

    # --- Search Logic replaced with MongoDB Calls ---
    api_data = {}
    try:
        if lookup_type == "phone":
            # 1. Search MongoDB 'phones' collection first
            res = search_mongo(PHONES_COLLECTION, "mobile", number)
            
            if "error" not in res:
                 api_data = {
                    "owner": res.get("name", "Unknown"),
                    "results": [res],
                    "_meta": {"search_term": number, "source": "Internal DB"}
                 }
            else:
                 # 2. Fallback to Devil API
                 devil_data = fetch_devil_phone_data(number)
                 if devil_data:
                     # Check if we have a name to show as 'Owner'
                     owner_name = "Unknown"
                     if devil_data['results']:
                         owner_name = devil_data['results'][0].get('name', 'Unknown')
                         
                     api_data = {
                         "owner": owner_name,
                         "results": devil_data['results'],
                         "_meta": {"search_term": number, "source": "Live API"}
                     }
                 else:
                     # 3. Last resort - return the mongo error
                     api_data = res

        elif lookup_type == "vehicle":
            # 1. Try Basic API first (Primary Source)
            basic_data = fetch_vehicle_basic(number)
            if basic_data and basic_data.get('status') and basic_data.get('data'):
                 api_data = {
                     "result": basic_data['data'],
                     "_meta": {"search_term": number, "source": "Vehicle API", "can_enrich": True}
                 }
            else:
                # 2. Fallback to MongoDB 'vehicles' collection
                res = search_mongo(VEHICLES_COLLECTION, "rc_number", number)
                if "error" in res:
                     api_data = {"error": "No records found.", "status": "Not Found"}
                else:
                     api_data = {"result": res}

        elif lookup_type == "aadhaar":
            res = search_mongo(AADHAAR_COLLECTION, "aadhaar_number", number)
            if "error" in res:
                # Fallback to API
                api_res = fetch_aadhaar_info(number)
                api_data = api_res if api_res else res
            else:
                api_data = res
            
        elif lookup_type == "family":
            res = search_mongo(FAMILIES_COLLECTION, "aadhaar_number", number)
            if "error" in res:
                api_res = fetch_aadhaar_family(number)
                api_data = api_res if api_res else res
            else:
                api_data = res

        elif lookup_type == "gst":
            res = search_mongo(GSTS_COLLECTION, "gstin", number)
            if "error" in res:
                 api_res = fetch_gst_details(number)
                 api_data = api_res if api_res else res
            else:
                 api_data = res
            

            
        else:
            return jsonify({"error": "Invalid lookup type"}), 400

    except Exception as e:
        return jsonify({"error": f"Search failed: {str(e)}"}), 500
    
    # We log the search *after* the API call
    log_search(pin, lookup_type, number, device_id)
    # This update is redundant if you don't have a reset script, but we'll leave it
    # in case you add one. The check above is the important fix.
    KEYS_COLLECTION.update_one({"pin": pin}, {"$inc": {"used_today": 1}})
    
    key_info = {"searches_left": key.get('limit_count', 10) - (searches_today + 1), "expiry_date": key.get('expiry') or "Never"}
    final_response = {**(api_data if isinstance(api_data, dict) else {"result": api_data}), "status": "success", "key_status": key_info, "dev": "RAHUL SHARMA"}
    return jsonify(final_response)

@app.route('/api/vehicle_full', methods=['POST'])
def api_vehicle_full():
    data = request.json or {}
    pin = data.get('pin')
    rc_number = data.get('rc_number')
    device_id = data.get('device_id') or "unknown"
    
    if not pin or not rc_number:
        return jsonify({"error": "PIN and RC Number required"}), 400
        
    # verify PIN
    if KEYS_COLLECTION is None: return jsonify({"error": "DB Error"}), 500
    key = KEYS_COLLECTION.find_one({"pin": pin})
    if not key: return jsonify({"error": "Invalid API Key"}), 401
    
    # Check expiry
    if key.get('expiry'):
        if datetime.datetime.now().strftime("%Y-%m-%d") > key['expiry']:
             return jsonify({"error": "API Key Expired"}), 403
             
    # Check Limit
    today_start = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    searches_today = SEARCH_HISTORY_COLLECTION.count_documents({"pin": pin, "timestamp": {"$gte": today_start}})
    
    if searches_today >= key.get('limit_count', 10):
        return jsonify({"error": "Daily limit exceeded"}), 429

    # Fetch Data
    print(f"DEBUG: Calling fetch_vehicle_full for {rc_number}")
    api_res = fetch_vehicle_full(rc_number)
    print(f"DEBUG: Raw API Result: {str(api_res)[:200]}")
    
    if not api_res:
         return jsonify({"error": "Failed to fetch details"}), 500
         
    # Unwrap data if api returns {status: true, data: {...}}
    # The user's API returns data inside a 'data' key.
    clean_data = api_res
    if isinstance(api_res, dict) and 'data' in api_res and isinstance(api_res['data'], dict):
        clean_data = api_res['data']
        print(f"DEBUG: Unwrapped Data: {str(clean_data)[:200]}")
         
    # Log usage
    log_search(pin, "vehicle-full", rc_number, device_id)
    KEYS_COLLECTION.update_one({"pin": pin}, {"$inc": {"used_today": 1}})
    
    return jsonify({"success": True, "data": clean_data})

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

    def make_serializable(doc):
        """Converts MongoDB docs (with ObjectId, datetime) to JSON-safe dict."""
        for key, val in doc.items():
            if isinstance(val, ObjectId):
                doc[key] = str(val)
            if isinstance(val, datetime.datetime):
                doc[key] = val.isoformat()
        return doc

    @app.route('/admin')
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

    # --- !! UPDATED: Dashboard Stats API ---
    @app.route('/admin/dashboard_stats', methods=['GET'])
    @admin_required
    def admin_dashboard_stats():
        # --- Mock Data Fallback if DB is missing ---
        if not all([KEYS_COLLECTION, USERS_COLLECTION, SEARCH_HISTORY_COLLECTION]):
            import random
            mock_stats = {
                "total_searches_today": random.randint(100, 500),
                "active_keys": random.randint(10, 50),
                "total_users": random.randint(50, 200),
                "top_5_keys": [{"pin": f"DEMO-{i}", "used_today": random.randint(10, 50)} for i in range(1, 6)],
                "popular_services": [{"_id": s, "count": random.randint(20, 100)} for s in ["Phone", "Vehicle", "Aadhaar", "Instagram"]],
                "recent_searches": [
                    {"timestamp": datetime.datetime.now().isoformat(), "pin": "DEMO-KEY", "lookup_type": "phone", "query": "9876543210"}
                    for _ in range(5)
                ],
                "is_mock": True
            }
            return jsonify({"success": True, "stats": mock_stats})
            
        try:
            today_start = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            seven_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
            today_str = datetime.date.today().isoformat()

            # 1. Total Searches Today (from history)
            total_searches_today = SEARCH_HISTORY_COLLECTION.count_documents({"timestamp": {"$gte": today_start}})
            
            # 2. Active Keys (from keys)
            active_keys = KEYS_COLLECTION.count_documents({
                "$or": [{"expiry": {"$gte": today_str}}, {"expiry": None}]
            })
            
            # 3. Top 5 Keys (from history)
            top_keys_pipeline = [
                {"$match": {"timestamp": {"$gte": today_start}}},
                {"$group": {"_id": "$pin", "used_today": {"$sum": 1}}},
                {"$sort": {"used_today": -1}},
                {"$limit": 5},
                {"$project": {"pin": "$_id", "used_today": 1, "_id": 0}}
            ]
            top_5_keys = list(SEARCH_HISTORY_COLLECTION.aggregate(top_keys_pipeline))
            
            # 4. User Stats
            total_users = USERS_COLLECTION.count_documents({})
            
            # 5. History Stats
            popular_services_pipeline = [
                {"$match": {"timestamp": {"$gte": seven_days_ago}}},
                {"$group": {"_id": "$lookup_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]
            popular_services = list(SEARCH_HISTORY_COLLECTION.aggregate(popular_services_pipeline))
            
            recent_searches = [make_serializable(s) for s in SEARCH_HISTORY_COLLECTION.find().sort("timestamp", -1).limit(10)]
            
            stats = {
                "total_searches_today": total_searches_today,
                "active_keys": active_keys,
                "total_users": total_users,
                "top_5_keys": top_5_keys,
                "popular_services": popular_services,
                "recent_searches": recent_searches,
                "is_mock": False
            }
            return jsonify({"success": True, "stats": stats})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    # --- !! END OF UPDATE !! ---

    # --- NEW: API Health Check API ---
    @app.route('/admin/api_health', methods=['GET'])
    @admin_required
    def admin_api_health():
        apis_to_check = [
            {"name": "Phone API 1 (Byekam)", "url": PHONE_API_1, "query": "1234567890"},
            {"name": "Phone API 2 (Demon)", "url": PHONE_API_2, "query": "1234567890"},
            {"name": "Phone API 3 (Ox)", "url": PHONE_API_3, "query": "1234567890"},
            {"name": "Vehicle API 1 (Byekam)", "url": VEHICLE_API_1, "query": "DL1CAB1234"},
            {"name": "Vehicle API 2 (Hazex)", "url": VEHICLE_API_2, "query": "DL1CAB1234"},
            {"name": "Aadhaar API (Ox)", "url": AADHAAR_API, "query": "123456789012"},
            {"name": "Aadhaar Family (Ox)", "url": AADHAAR_FAMILY_API, "query": "123456789012"},
            {"name": "GST API", "url": GST_API, "query": "27AACCT6843P1Z5"},
            {"name": "IP API", "url": IP_API, "query": "8.8.8.8"},
            {"name": "IMEI API", "url": IMEI_API, "query": "353535053535350"},
            {"name": "PK SIM API", "url": PK_SIM_API, "query": "3001234567"},
            {"name": "IFSC API", "url": IFSC_API, "query": "SBIN0000691"}
        ]
        results = []
        headers = {'User-Agent': generate_user_agent()}
        for api in apis_to_check:
            # For internal MongoDB features, we can just check if collection is initialized
            if "url" not in api: 
                 # This block is just for structure compatibility if we added non-URL checks
                 continue

            if not api["url"]:
                results.append({"name": api["name"], "status": "Not Configured", "message": "URL is not set in .env"})
                continue
            
            test_url = api["url"].format(api["query"])
            res = safe_api_call(test_url, headers, timeout=5)
            
            if "error" in res:
                results.append({"name": api["name"], "status": "Failed", "message": res["error"]})
            else:
                results.append({"name": api["name"], "status": "OK", "message": "Success"})
        return jsonify({"success": True, "results": results})

    # --- Key Management ---
    @app.route('/admin/keys', methods=['GET'])
    @admin_required
    def admin_get_keys():
        if KEYS_COLLECTION is None or SEARCH_HISTORY_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        try:
            keys_rows = [make_serializable(k) for k in KEYS_COLLECTION.find().sort("created_at", -1)]
            # --- !! FIX for keys created before stats fix !! ---
            # We will query the history for each key's usage today
            today_start = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            usage_pipeline = [
                {"$match": {"timestamp": {"$gte": today_start}}},
                {"$group": {"_id": "$pin", "count": {"$sum": 1}}}
            ]
            daily_usage_map = {item['_id']: item['count'] for item in SEARCH_HISTORY_COLLECTION.aggregate(usage_pipeline)}
            
            for row in keys_rows:
                row['id'] = row['pin']
                # Update the 'used_today' from our accurate map
                row['used_today'] = daily_usage_map.get(row['pin'], 0)
            # --- !! END OF FIX !! ---
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
        
        permissions = data.get('permissions', [])
        key_doc = {
            "pin": pin,
            "limit_count": int(data.get('limit', 10)),
            "expiry": data.get('expiry') if data.get('expiry') else None,
            "device_limit": int(data.get('device_limit', 1)),
            "device_ids": [],
            "allow_phone": 1 if "phone" in permissions else 0,
            "allow_vehicle": 1 if "vehicle" in permissions else 0,
            "allow_aadhaar": 1 if "aadhaar" in permissions else 0,
            "allow_family": 1 if "family" in permissions else 0,
            "allow_gst": 1 if "gst" in permissions else 0,
            "used_today": 0, # This field is no longer authoritative, but we keep it
            "created_at": datetime.datetime.now(datetime.timezone.utc)
        }
        try:
            KEYS_COLLECTION.insert_one(key_doc)
            return jsonify({"success": True})
        except DuplicateKeyError:
            return jsonify({"success": False, "error": "This PIN already exists."}), 409
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # --- NEW: Batch Key Generation API ---
    @app.route('/admin/batch_add', methods=['POST'])
    @admin_required
    def batch_add_keys():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        data = request.json or {}
        count = int(data.get('count', 0))
        prefix = data.get('prefix', '')
        if count <= 0 or count > 100:
            return jsonify({"success": False, "error": "Count must be between 1 and 100."}), 400
        
        permissions = data.get('permissions', [])
        base_doc = {
            "limit_count": int(data.get('limit', 10)),
            "expiry": data.get('expiry') if data.get('expiry') else None,
            "device_limit": int(data.get('device_limit', 1)),
            "device_ids": [],
            "allow_phone": 1 if "phone" in permissions else 0,
            "allow_vehicle": 1 if "vehicle" in permissions else 0,
            "allow_aadhaar": 1 if "aadhaar" in permissions else 0,
            "allow_family": 1 if "family" in permissions else 0,
            "allow_gst": 1 if "gst" in permissions else 0,
            "used_today": 0,
            "created_at": datetime.datetime.now(datetime.timezone.utc)
        }
        
        keys_to_insert = []
        for _ in range(count):
            random_pin = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            key_doc = base_doc.copy()
            key_doc["pin"] = f"{prefix}{random_pin}"
            keys_to_insert.append(key_doc)
            
        try:
            KEYS_COLLECTION.insert_many(keys_to_insert, ordered=False)
            return jsonify({"success": True, "message": f"Successfully created {count} keys."})
        except pymongo.errors.BulkWriteError as bwe:
            success_count = bwe.details['nInserted']
            failed_count = count - success_count
            return jsonify({"success": True, "message": f"Successfully created {success_count} keys. {failed_count} duplicates failed."})
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
        if 'device_limit' in data: update_doc["$set"]["device_limit"] = int(data['device_limit'])
        if 'permissions' in data:
            perms = data['permissions']
            update_doc["$set"]["allow_phone"] = 1 if "phone" in perms else 0
            update_doc["$set"]["allow_vehicle"] = 1 if "vehicle" in perms else 0
            update_doc["$set"]["allow_aadhaar"] = 1 if "aadhaar" in perms else 0
            update_doc["$set"]["allow_family"] = 1 if "family" in perms else 0
            update_doc["$set"]["allow_gst"] = 1 if "gst" in perms else 0
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
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        key_pin = (request.json or {}).get('id')
        if not key_pin: return jsonify({"success": False, "error": "Key PIN is required."}), 400
        try:
            result = KEYS_COLLECTION.update_one({"pin": key_pin}, {"$set": {"device_ids": []}})
            if result.matched_count == 0: return jsonify({"success": False, "error": "Key not found."}), 404
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    
    # --- NEW: Reset Usage API ---
    @app.route('/admin/reset_usage', methods=['POST'])
    @admin_required
    def reset_usage():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        key_pin = (request.json or {}).get('id')
        if not key_pin: return jsonify({"success": False, "error": "Key PIN is required."}), 400
        try:
            # This will reset the old field
            KEYS_COLLECTION.update_one({"pin": key_pin}, {"$set": {"used_today": 0}})
            # And we will also clear the history for them for today
            today_start = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            SEARCH_HISTORY_COLLECTION.delete_many({
                "pin": key_pin,
                "timestamp": {"$gte": today_start}
            })
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
            history_rows = [make_serializable(h) for h in SEARCH_HISTORY_COLLECTION.find({"pin": key_pin}).sort("timestamp", -1).limit(100)]
            return jsonify({"success": True, "history": history_rows})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # --- User Management ---
    @app.route('/admin/users', methods=['GET'])
    @admin_required
    def admin_get_users():
        if USERS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        try:
            query = {}
            search = request.args.get('search')
            if search:
                query = {"$or": [
                    {"name": {"$regex": search, "$options": "i"}},
                    {"phone": {"$regex": search, "$options": "i"}}
                ]}
            users_rows = [make_serializable(u) for u in USERS_COLLECTION.find(query).sort("last_login", -1)]
            return jsonify({"success": True, "users": users_rows})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # --- NEW: Ban User API ---
    @app.route('/admin/ban_user', methods=['POST'])
    @admin_required
    def admin_ban_user():
        if USERS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        data = request.json or {}
        phone = data.get('phone')
        ban_status = bool(data.get('ban_status', False))
        if not phone: return jsonify({"success": False, "error": "Phone number is required."}), 400
        try:
            result = USERS_COLLECTION.update_one({"phone": phone}, {"$set": {"is_banned": ban_status}})
            if result.matched_count == 0: return jsonify({"success": False, "error": "User not found."}), 404
            return jsonify({"success": True, "message": f"User {'banned' if ban_status else 'unbanned'}."})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # --- Settings Management ---
    @app.route('/admin/note', methods=['GET', 'POST'])
    @admin_required
    def admin_global_note():
        if CONFIG_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        try:
            if request.method == 'POST':
                note = (request.json or {}).get('note', '')
                CONFIG_COLLECTION.update_one({"config_id": "global_config"}, {"$set": {"global_note": note}}, upsert=True)
                return jsonify({"success": True, "message": "Note updated."})
            config = CONFIG_COLLECTION.find_one({"config_id": "global_config"})
            return jsonify({"success": True, "note": config.get("global_note", "") if config else ""})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

# --- Plans & Purchase API ---

@app.route('/api/public/plans', methods=['GET'])
def get_public_plans():
    try:
        if PLANS_COLLECTION is None:
            return jsonify({"error": "Database error"}), 500
        plans = list(PLANS_COLLECTION.find({}, {"_id": 1, "name": 1, "price": 1, "searches": 1, "days": 1}))
        for p in plans:
            p['_id'] = str(p['_id'])
        return jsonify(plans)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/buy', methods=['POST'])
def buy_key():
    try:
        data = request.json
        utr = data.get('utr')
        whatsapp = data.get('whatsapp')
        email = data.get('email')
        plan_id = data.get('plan_id')
        
        if not utr or not whatsapp or not plan_id:
            return jsonify({"error": "Missing required fields"}), 400
            
        if PURCHASE_REQUESTS_COLLECTION is None:
            return jsonify({"error": "Database error"}), 500

        # Check for duplicate UTR
        if PURCHASE_REQUESTS_COLLECTION.find_one({"utr": utr}):
             return jsonify({"error": "UTR already submitted"}), 400
             
        plan = PLANS_COLLECTION.find_one({"_id": ObjectId(plan_id)})
        if not plan:
            return jsonify({"error": "Invalid Plan"}), 400
            
        req = {
            "utr": utr,
            "whatsapp": whatsapp,
            "email": email,
            "plan_id": plan_id,
            "plan_name": plan['name'],
            "amount": plan['price'],
            "status": "pending",
            "timestamp": datetime.datetime.utcnow()
        }
        
        PURCHASE_REQUESTS_COLLECTION.insert_one(req)
        return jsonify({"success": True, "message": "Request submitted successfully. Admin will verify and contact you."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Admin Plan & Request APIs ---

@app.route('/admin/plans', methods=['GET', 'POST', 'DELETE', 'PUT'])
def admin_plans():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 401
        
    if request.method == 'GET':
        if PLANS_COLLECTION is None: return jsonify({"error": "Database error"}), 500
        plans = list(PLANS_COLLECTION.find())
        for p in plans: p['_id'] = str(p['_id'])
        return jsonify(plans)

    if request.method == 'PUT':
        data = request.json or {}
        plan_id = data.get('id')
        if not plan_id: return jsonify({"success": False, "error": "Plan ID required"}), 400
        
        update_fields = {}
        if 'name' in data: update_fields['name'] = data['name']
        if 'price' in data: update_fields['price'] = int(data['price'])
        if 'searches' in data: update_fields['searches'] = int(data['searches'])
        if 'days' in data: update_fields['days'] = int(data['days'])
        if 'device_limit' in data: update_fields['device_limit'] = int(data['device_limit'])
        
        if not update_fields: return jsonify({"success": False, "error": "No fields to update"}), 400
        
        PLANS_COLLECTION.update_one({"_id": ObjectId(plan_id)}, {"$set": update_fields})
        return jsonify({"success": True})
        
    if request.method == 'POST':
        data = request.json
        if not data.get('name') or not data.get('price'):
            return jsonify({"error": "Name and Price required"}), 400
            
        plan = {
            "name": data['name'],
            "price": float(data['price']),
            "searches": int(data.get('searches', 100)),
            "days": int(data.get('days', 30)),
            "devices": int(data.get('devices', 1))
        }
        PLANS_COLLECTION.insert_one(plan)
        return jsonify({"success": True})
        
    if request.method == 'DELETE':
        plan_id = request.args.get('id')
        if not plan_id:
            data = request.json or {}
            plan_id = data.get('id')
        
        if not plan_id:
            return jsonify({"success": False, "error": "Plan ID required"}), 400
            
        PLANS_COLLECTION.delete_one({"_id": ObjectId(plan_id)})
        return jsonify({"success": True})

@app.route('/admin/requests', methods=['GET'])
def admin_requests():
    if not session.get('is_admin'): return jsonify({"error": "Unauthorized"}), 401
    if PURCHASE_REQUESTS_COLLECTION is None: return jsonify({"error": "Database error"}), 500
    reqs = list(PURCHASE_REQUESTS_COLLECTION.find().sort("timestamp", -1))
    for r in reqs: r['_id'] = str(r['_id'])
    return jsonify(reqs)

@app.route('/admin/requests/action', methods=['POST'])
def request_action():
    if not session.get('is_admin'): return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    req_id = data.get('id')
    action = data.get('action')
    
    if action == 'reject':
        PURCHASE_REQUESTS_COLLECTION.update_one({"_id": ObjectId(req_id)}, {"$set": {"status": "rejected"}})
        return jsonify({"success": True})
        
    elif action == 'approve':
        req = PURCHASE_REQUESTS_COLLECTION.find_one({"_id": ObjectId(req_id)})
        if not req: return jsonify({"error": "Request not found"})
        
        # Generate Key
        plan = PLANS_COLLECTION.find_one({"_id": ObjectId(req['plan_id'])})
        searches = plan['searches'] if plan else 100
        days = plan['days'] if plan else 30
        
        new_pin = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        expiry = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).strftime("%Y-%m-%d")
        
        new_key = {
            "pin": new_pin,
            "searches_left": searches,
            "expiry_date": expiry,
            "devices_allowed": plan.get('devices', 1) if plan else 1,
            "current_devices": [],
            "created_at": datetime.datetime.utcnow(),
            "note": f"Generated for Request {req['utr']}",
            # Permissions (Enable All for paid keys by default, or configurable)
            "allow_phone": True, "allow_vehicle": True, "allow_aadhaar": True, "allow_family": True,
            "allow_gst": True
        }
        
        KEYS_COLLECTION.insert_one(new_key)
        PURCHASE_REQUESTS_COLLECTION.update_one({"_id": ObjectId(req_id)}, {"$set": {"status": "approved", "generated_key": new_pin}})
        return jsonify({"success": True, "key": new_pin})
        
    return jsonify({"error": "Invalid Action"})

# --- Run ---
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    if not os.getenv("MONGO_URI"):
        print("Warning: MONGO_URI not set. App will not connect to DB.")
    app.run(host='0.0.0.0', port=port, debug=False)
