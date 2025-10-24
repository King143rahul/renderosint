#!/usr/bin/env python3
import os
import datetime
import json
import requests
import pymongo
from pymongo.errors import DuplicateKeyError
from requests.exceptions import JSONDecodeError
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from dotenv import load_dotenv
from bs4 import BeautifulSoup  # --- NEW IMPORT ---

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

# --- External API endpoints (set these in .env) ---
VEHICLE_API = os.getenv("VEHICLE_API", "")
NUMBER_API = os.getenv("NUMBER_API", "")
AADHAAR_API = os.getenv("AADHAAR_API", "")

# --- Database Setup (MongoDB) ---
DB_CLIENT = None
KEYS_COLLECTION = None

def get_db_collection():
    """Establishes a connection to MongoDB and returns the 'keys' collection."""
    global DB_CLIENT, KEYS_COLLECTION
    
    if KEYS_COLLECTION is not None:
        return KEYS_COLLECTION

    MONGO_URI = os.getenv("MONGO_URI")
    if not MONGO_URI:
        raise ValueError("MONGO_URI environment variable is not set.")

    try:
        # Use the "knox" appName from your connection string
        DB_CLIENT = pymongo.MongoClient(MONGO_URI, appName="knox")
        db = DB_CLIENT.osint_db 
        KEYS_COLLECTION = db.keys 
        
        KEYS_COLLECTION.create_index("pin", unique=True)
        
        print("Successfully connected to MongoDB.")
        return KEYS_COLLECTION
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        return None

KEYS_COLLECTION = get_db_collection()


# ----------------------------------------------------------------- #
# --- NEW FUNCTION: Scraper logic from vehicleInfo.py ---
# ----------------------------------------------------------------- #
def get_details_from_vahanx(rc_number: str) -> dict:
    """
    Fetches vehicle details by scraping vahanx.in.
    This code is from your vehicleInfo.py file.
    """
    print(f"[Info] Querying vahanx.in scraper for {rc_number}...")
    rc = rc_number.strip().upper()
    url = f"https://vahanx.in/rc-search/{rc}"

    headers = {
        "Host": "vahanx.in",
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Referer": "https://vahanx.in/rc-search",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
    except requests.exceptions.RequestException as e:
        return {"error": f"Vahanx scraper network error: {e}"}
    except Exception as e:
        return {"error": f"Vahanx scraper failed: {e}"}

    def get_value(label):
        try:
            div = soup.find("span", string=label).find_parent("div")
            return div.find("p").get_text(strip=True)
        except AttributeError:
            return None

    data = {
        "Owner Name": get_value("Owner Name"),
        "Father's Name": get_value("Father's Name"),
        "Owner Serial No": get_value("Owner Serial No"),
        "Model Name": get_value("Model Name"),
        "Maker Model": get_value("Maker Model"),
        "Vehicle Class": get_value("Vehicle Class"),
        "Fuel Type": get_value("Fuel Type"),
        "Fuel Norms": get_value("Fuel Norms"),
        "Registration Date": get_value("Registration Date"),
        "Insurance Company": get_value("Insurance Company"),
        "Insurance No": get_value("Insurance No"),
        "Insurance Expiry": get_value("Insurance Expiry"),
        "Insurance Upto": get_value("Insurance Upto"),
        "Fitness Upto": get_value("Fitness Upto"),
        "Tax Upto": get_value("Tax Upto"),
        "PUC No": get_value("PUC No"),
        "PUC Upto": get_value("PUC Upto"),
        "Financier Name": get_value("Financier Name"),
        "Registered RTO": get_value("Registered RTO"),
        "Address": get_value("Address"),
        "City Name": get_value("City Name"),
        "Phone": get_value("Phone")
    }
    # Filter out None values for a cleaner response
    return {k: v for k, v in data.items() if v is not None}


# --- Main Routes ---
@app.route('/')
def home():
    return render_template("index.html")

@app.route('/api/search', methods=['POST'])
def search():
    if KEYS_COLLECTION is None:
        return jsonify({"error": "Database connection is not established."}), 500

    data = request.json or {}
    lookup_type = data.get('type')
    number = data.get('number')
    pin = data.get('pin')
    device_id = data.get('deviceId')

    if not all([lookup_type, number, pin, device_id]):
        return jsonify({"error": "Missing required fields."}), 400

    key = KEYS_COLLECTION.find_one({"pin": pin})

    if not key:
        return jsonify({"error": "Invalid API Key"}), 401

    if key.get('expiry'):
        expiry_date = datetime.datetime.fromisoformat(key['expiry']).date()
        if datetime.date.today() > expiry_date:
            return jsonify({"error": "API Key has expired."}), 403

    if key.get('used_today', 0) >= key.get('limit_count', 10):
        return jsonify({"error": "Daily search limit reached for this key."}), 403

    if not key.get('device_id'):
        KEYS_COLLECTION.update_one(
            {"pin": pin, "device_id": None},
            {"$set": {"device_id": device_id}}
        )
        key = KEYS_COLLECTION.find_one({"pin": pin})

    if key.get('device_id') != device_id:
        return jsonify({"error": "API Key is locked to another device."}), 403

    if lookup_type == "phone" and not key.get('allow_phone'):
        return jsonify({"error": "This key does not have permission for Phone searches."}), 403
    if lookup_type == "vehicle" and not key.get('allow_vehicle'):
        return jsonify({"error": "This key does not have permission for Vehicle searches."}), 403
    if lookup_type == "aadhaar" and not key.get('allow_aadhaar'):
        return jsonify({"error": "This key does not have permission for Aadhaar searches."}), 403

    # This header is used by both API and scraper
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
    
    # ----------------------------------------------------------------- #
    # --- MODIFIED SECTION: This block is updated to handle all types ---
    # ----------------------------------------------------------------- #
    api_data = {}
    response_text_for_error = ""

    try:
        if lookup_type == "phone":
            if not NUMBER_API:
                return jsonify({"error": "Number API not configured."}), 500
            api_url = NUMBER_API.format(number)
            response = requests.get(api_url, timeout=15, headers=headers)
            response.raise_for_status() 
            response_text_for_error = response.text
            api_data = response.json() 

        elif lookup_type == "vehicle":
            if not VEHICLE_API:
                return jsonify({"error": "Vehicle API not configured."}), 500
            
            # --- 1. Call Byekam API (Original Logic) ---
            print(f"[Info] Querying Byekam API for {number}...")
            api_url = VEHICLE_API.format(number)
            response = requests.get(api_url, timeout=15, headers=headers)
            response.raise_for_status()
            response_text_for_error = response.text
            # Store result in a nested dictionary
            api_data["byekam_source"] = response.json()

            # --- 2. Call Vahanx Scraper (New Logic) ---
            # We call this *after* the first API
            vahanx_data = get_details_from_vahanx(number)
            # Store result in another nested dictionary
            api_data["vahanx_source"] = vahanx_data

        elif lookup_type == "aadhaar":
            if not AADHAAR_API:
                return jsonify({"error": "Aadhaar API not configured."}), 500
            api_url = AADHAAR_API.format(number)
            response = requests.get(api_url, timeout=15, headers=headers)
            response.raise_for_status() 
            response_text_for_error = response.text
            api_data = response.json() 

        else:
            return jsonify({"error": "Invalid lookup type"}), 400

    except JSONDecodeError as json_err:
        error_message = f"API did not return valid JSON. Response: {response_text_for_error[:200]}..." 
        return jsonify({"error": error_message}), 502
    except Exception as e:
        # This will catch failures from requests OR the vahanx scraper
        return jsonify({"error": f"Failed to fetch data from external API/scraper. Detail: {str(e)}"}), 502
    
    # --- This part remains the same ---
    KEYS_COLLECTION.update_one(
        {"pin": pin},
        {"$inc": {"used_today": 1}}
    )

    key_info = {
        "searches_left": key.get('limit_count', 10) - key.get('used_today', 0) - 1,
        "expiry_date": key.get('expiry') or "Never"
    }

    final_response = {
        **(api_data if isinstance(api_data, dict) else {"result": api_data}),
        "status": "success",
        "key_status": key_info,
        "dev": "RAHUL SHARMA"
    }
    return jsonify(final_response)

# --- Admin routes (Rewritten for MongoDB) ---
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
            
            keys_rows = list(KEYS_COLLECTION.find().sort("created_at", pymongo.DESCENDING))
            
            # ** THIS IS THE FIX **
            keys_list = []
            for row in keys_rows:
                row['_id'] = str(row['_id']) 
                row['id'] = row['pin'] 
                keys_list.append(row) # <-- THIS LINE WAS MISSING
            
            return jsonify({"success": True, "keys": keys_list})
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    @app.route('/admin/keys', methods=['GET'])
    @admin_required
    def admin_get_keys():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        
        keys_rows = list(KEYS_COLLECTION.find().sort("created_at", pymongo.DESCENDING))

        # ** THIS IS THE FIX **
        keys_list = []
        for row in keys_rows:
            row['_id'] = str(row['_id'])
            row['id'] = row['pin'] 
            keys_list.append(row) # <-- THIS LINE WAS MISSING
        
        return jsonify({"success": True, "keys": keys_list})

    @app.route('/admin/add', methods=['POST'])
    @admin_required
    def add_key():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500

        data = request.json or {}
        pin = data.get('pin')
        limit = data.get('limit', 10)
        expiry = data.get('expiry')
        key_type = data.get('key_type', 'universal')
        
        if not pin:
            return jsonify({"success": False, "error": "PIN cannot be empty."}), 400

        key_doc = {
            "pin": pin,
            "limit_count": limit,
            "expiry": expiry,
            "allow_phone": 1 if key_type in ['universal', 'phone'] else 0,
            "allow_vehicle": 1 if key_type in ['universal', 'vehicle'] else 0,
            "allow_aadhaar": 1 if key_type in ['universal', 'aadhaar'] else 0,
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

    @app.route('/admin/delete', methods=['POST'])
    @admin_required
    def delete_key():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500
        
        key_pin = (request.json or {}).get('id') 
        if not key_pin:
            return jsonify({"success": False, "error": "Key PIN is required."}), 400
        
        try:
            result = KEYS_COLLECTION.delete_one({"pin": key_pin})
            if result.deleted_count == 0:
                return jsonify({"success": False, "error": "Key not found."}), 404
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    
    @app.route('/admin/reset_device', methods=['POST'])
    @admin_required
    def reset_device():
        if KEYS_COLLECTION is None: return jsonify({"success": False, "error": "Database not configured."}), 500

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

    @app.route('/admin/logout', methods=['POST'])
    def admin_logout():
        session.pop('is_admin', None)
        return jsonify({"success": True})

# --- Run ---
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    if not os.getenv("MONGO_URI"):
        print("Warning: MONGO_URI not set. App will not connect to DB.")
    app.run(host='0.0.0.0', port=port, debug=False)
