import requests
import time

BASE_URL = "http://127.0.0.1:5000"
ADMIN_USER = "RAHUL"  # Assuming default/env
ADMIN_PASS = "rahul123" # I need to check .env or main.py for actual defaults if not set

# Helper to print steps
def step(msg): print(f"\n[+] {msg}")

s = requests.Session()

def verify():
    # 1. Login
    step("Logging in as Admin...")
    login_payload = {"username": "RAHUL", "password": "password"} # Checking main.py for hardcoded or env
    # Wait, main.py uses os.getenv with defaults. 
    # Let's check main.py content from previous views or assume default. 
    # In main.py: 
    # ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "RAHUL")
    # ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "rahul@123") 
    
    # I'll try the default first. Use .env if it fails.
    login_payload = {"username": "RAHUL", "password": "KNOX"}
    
    r = s.post(f"{BASE_URL}/admin/login", json=login_payload)
    if r.status_code != 200 or not r.json().get('success'):
        print(f"Login failed: {r.text}")
        return
    print("Login successful.")

    # 2. Create Plan
    step("Creating Test Plan...")
    plan_data = {
        "name": "Verification Plan",
        "price": 100,
        "searches": 50,
        "days": 7
    }
    r = s.post(f"{BASE_URL}/admin/plans", json=plan_data)
    if not r.json().get('success'):
        print(f"Create Plan failed: {r.text}")
        return
    print("Plan created.")

    # 3. Fetch Public Plans
    step("Fetching Public Plans...")
    r = requests.get(f"{BASE_URL}/api/public/plans") # New session (User)
    plans = r.json()
    test_plan = next((p for p in plans if p['name'] == "Verification Plan"), None)
    if not test_plan:
        print("Plan not found in public API.")
        return
    print(f"Found Plan: {test_plan['_id']}")
    plan_id = test_plan['_id']

    # 4. Buy Request
    step("Submitting Buy Request...")
    buy_payload = {
        "plan_id": plan_id,
        "utr": f"UTR{int(time.time())}",
        "whatsapp": "1234567890",
        "email": "test@example.com"
    }
    r = requests.post(f"{BASE_URL}/api/buy", json=buy_payload)
    if not r.json().get('success'):
        print(f"Buy Request failed: {r.text}")
        return
    print("Buy Request submitted.")

    # 5. Admin List Requests
    step("Listing Requests as Admin...")
    r = s.get(f"{BASE_URL}/admin/requests")
    requests_list = r.json()
    target_req = next((r for r in requests_list if r['utr'] == buy_payload['utr']), None)
    if not target_req:
        print("Request not found in Admin API.")
        return
    print(f"Found Request: {target_req['_id']} - Status: {target_req['status']}")
    req_id = target_req['_id']

    # 6. Approve Request
    step("Approving Request...")
    approve_payload = {"id": req_id, "action": "approve"}
    r = s.post(f"{BASE_URL}/admin/requests/action", json=approve_payload)
    res = r.json()
    if not res.get('success'):
        print(f"Approval failed: {r.text}")
        return
    print(f"Request Approved. Generated Key: {res.get('key')}")

    # 7. Cleanup
    step("Cleaning up (Deleting Plan)...")
    r = s.delete(f"{BASE_URL}/admin/plans?id={plan_id}")
    if r.json().get('success'):
        print("Plan deleted.")
    else:
        print("Failed to delete plan.")

if __name__ == "__main__":
    try:
        verify()
    except Exception as e:
        print(f"Error: {e}")
