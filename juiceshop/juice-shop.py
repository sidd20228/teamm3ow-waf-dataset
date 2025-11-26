"""
juice_shop_realistic_crawler.py
Generate realistic benign web traffic for a local OWASP Juice Shop instance
for training machine learning models. Now with persistent duplicate detection.

(Same docstring as before)
"""
import requests
import time
import random
import csv
import os
import json
import hashlib
from urllib.parse import urljoin, quote
from faker import Faker
from tqdm import trange
from uuid import uuid4
from datetime import datetime

# ---------- CONFIG ----------
BASE_URL = "http://localhost:3000/"  # Change if needed
NUM_REQUESTS = 10000
CONCURRENT_SESSIONS = 5  # Number of simulated users/sessions
DEFAULT_TIMEOUT = 10
MIN_DELAY = 0.05
MAX_DELAY = 0.25
LOG_CSV = "juice_shop_benign_requests.csv"
VERBOSE = True
PROXY = None  # e.g. "http://127.0.0.1:8080"

# ---------- Helpers ----------
faker = Faker()

def generate_user_credentials():
    """Generates a realistic email, password, and security answer."""
    email = faker.email()
    password = faker.password(length=12, special_chars=True, upper_case=True, lower_case=True, digits=True)
    answer = faker.city()
    return email, password, answer

def generate_search_query():
    """Returns a common product search query."""
    queries = [
        "apple", "banana", "juice", "owasp", "sticker", "shirt",
        "raspberry", "egg", "green", "blue", "orange"
    ]
    return random.choice(queries)

def generate_feedback():
    """Creates a realistic feedback comment and rating."""
    comment = faker.sentence(nb_words=15)
    rating = random.randint(0, 5)
    return comment, rating

# ---------- Traffic Generator ----------
class JuiceShopGenerator:
    def __init__(self, base_url=BASE_URL, sessions=CONCURRENT_SESSIONS):
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.sessions_data = [self._create_new_session() for _ in range(sessions)]
        self.product_ids = []
        self.used_signatures = set()
        self.csv_file = LOG_CSV

        # **MODIFICATION: Added 'signature' column for persistence.**
        self.csv_headers = [
            "_id", "signature", "body_bytes_sent", "ip", "request.method", "request.path",
            "request.protocol", "request_body", "status", "timestamp"
        ]
        
        self._initialize_csv()
        # **MODIFICATION: Load signatures from previous runs.**
        self._load_existing_signatures()

    def _initialize_csv(self):
        """Creates the CSV file and writes the header if it doesn't exist."""
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.csv_headers)
                writer.writeheader()
                if VERBOSE:
                    logger.info(f"Created and initialized CSV log file: {self.csv_file}")

    # **MODIFICATION: New function to load past signatures.**
    def _load_existing_signatures(self):
        """Reads the CSV file to load signatures from previous runs."""
        if not os.path.exists(self.csv_file):
            return # No file, nothing to load
        
        try:
            with open(self.csv_file, "r", newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                # Ensure the 'signature' column exists
                if 'signature' not in reader.fieldnames:
                    if VERBOSE: logger.warning("CSV exists but 'signature' column is missing. Cannot load old requests.")
                    return
                    
                for row in reader:
                    if row.get('signature'):
                        self.used_signatures.add(row['signature'])
            
            if VERBOSE:
                logger.info(f"Loaded {len(self.used_signatures)} existing signatures from {self.csv_file}. These requests will be skipped.")
        except Exception as e:
            if VERBOSE: logger.error(f"Error loading existing signatures: {e}")

    def _create_new_session(self):
        s = requests.Session()
        if PROXY:
            s.proxies.update({"http": PROXY, "https": PROXY})
        s.headers.update({"User-Agent": faker.user_agent()})
        return {"session": s, "email": None, "token": None, "basket_id": None}

    def _log_csv(self, log_data):
        with open(self.csv_file, "a", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.csv_headers)
            writer.writerow(log_data)

    def _register_and_login(self, session_data):
        # This function remains the same
        s = session_data["session"]
        email, password, answer = generate_user_credentials()
        register_payload = {
            "email": email, "password": password, "passwordRepeat": password,
            "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?", "answer": answer}
        }
        try:
            resp_reg = s.post(urljoin(self.base_url, "/api/Users"), json=register_payload, timeout=DEFAULT_TIMEOUT)
            if resp_reg.status_code != 201: return False
        except requests.RequestException: return False
        login_payload = {"email": email, "password": password}
        try:
            resp_login = s.post(urljoin(self.base_url, "/rest/user/login"), json=login_payload, timeout=DEFAULT_TIMEOUT)
            if resp_login.status_code == 200:
                data = resp_login.json().get("authentication", {})
                session_data.update({
                    "email": email,
                    "token": data.get("token"),
                    "basket_id": data.get("bid")
                })
                s.headers.update({"Authorization": f"Bearer {session_data['token']}"})
                if VERBOSE: logger.info(f"Successfully logged in as {email}")
                return True
        except requests.RequestException: pass
        return False

    def _fetch_product_ids(self):
        # This function remains the same
        if not self.sessions_data[0]["token"]: return
        s = self.sessions_data[0]["session"]
        try:
            resp = s.get(urljoin(self.base_url, "/rest/products/search"), params={"q": ""}, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                self.product_ids = [p["id"] for p in resp.json().get("data", [])]
                if VERBOSE: logger.info(f"Fetched {len(self.product_ids)} product IDs.")
        except requests.RequestException as e:
            if VERBOSE: logger.error(f"Failed to fetch product IDs: {e}")

    def _make_api_request(self, session_id, method, endpoint, body=None):
        session_data = self.sessions_data[session_id]
        s = session_data["session"]
        url = urljoin(self.base_url, endpoint)

        sig_components = [method, endpoint, str(sorted(body.items()) if body else "")]
        signature = hashlib.md5("|".join(sig_components).encode()).hexdigest()
        
        if signature in self.used_signatures:
            return None # Skip duplicate
        self.used_signatures.add(signature)

        start_time = datetime.now()
        try:
            resp = s.request(method, url, json=body, timeout=DEFAULT_TIMEOUT)
            
            # **MODIFICATION: 'signature' is now included in the log entry.**
            log_entry = {
                "_id": str(uuid4()),
                "signature": signature,
                "body_bytes_sent": len(resp.content),
                "ip": "127.0.0.1",
                "request.method": method,
                "request.path": endpoint,
                "request.protocol": "HTTP/1.1",
                "request_body": json.dumps(body) if body else "N/A",
                "status": resp.status_code,
                "timestamp": start_time.isoformat()
            }
            self._log_csv(log_entry)
            return resp
        except requests.RequestException as e:
            # If request fails, remove signature so it can be tried again later
            self.used_signatures.remove(signature)
            if VERBOSE: logger.error(f"Request failed for {method} {url}: {e}")
        return None

    def generate_traffic(self, count=NUM_REQUESTS):
        # Main generation loop remains the same
        logger.info("Initializing sessions by registering and logging in users...")
        for i, s_data in enumerate(self.sessions_data):
            if not self._register_and_login(s_data):
                logger.error(f"Could not initialize session {i}. Retrying...")
        self._fetch_product_ids()
        if not self.product_ids:
            logger.error("No product IDs available. Cannot generate realistic traffic.")
            return
            
        logger.info(f"Starting traffic generation for {count} requests...")
        pbar = trange(count, desc="Generating new requests")
        
        generated_count = 0
        while generated_count < count:
            session_id = random.randrange(len(self.sessions_data))
            session_data = self.sessions_data[session_id]
            action = random.choices(["search_products", "view_product", "add_to_basket", "view_basket", "view_challenges"],
                                  weights=[0.35, 0.25, 0.20, 0.10, 0.05], k=1)[0]

            resp = None
            if action == "search_products":
                query = generate_search_query()
                endpoint = f"rest/products/search?q={quote(query)}"
                resp = self._make_api_request(session_id, "GET", endpoint)
            elif action == "view_product":
                prod_id = random.choice(self.product_ids)
                endpoint = f"rest/products/{prod_id}"
                resp = self._make_api_request(session_id, "GET", endpoint)
            elif action == "add_to_basket":
                prod_id = random.choice(self.product_ids)
                basket_id = session_data["basket_id"]
                endpoint = "api/BasketItems/"
                body = {"ProductId": prod_id, "BasketId": str(basket_id), "quantity": 1}
                resp = self._make_api_request(session_id, "POST", endpoint, body)
            # ... (other actions remain the same)
            elif action == "view_basket":
                basket_id = session_data["basket_id"]
                endpoint = f"rest/basket/{basket_id}"
                resp = self._make_api_request(session_id, "GET", endpoint)
            elif action == "submit_feedback":
                comment, rating = generate_feedback()
                endpoint = "api/Feedbacks/"
                body = {"comment": comment, "rating": rating}
                resp = self._make_api_request(session_id, "POST", endpoint, body)
            elif action == "view_challenges":
                endpoint = "api/Challenges/"
                resp = self._make_api_request(session_id, "GET", endpoint)

            if resp is not None:
                generated_count += 1
                pbar.update(1)

            time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
        pbar.close()

# ---------- Main Execution ----------
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    print(f"[*] Juice Shop Benign Traffic Generator - Target: {BASE_URL}")
    generator = JuiceShopGenerator()
    generator.generate_traffic(count=NUM_REQUESTS)
    print(f"[*] Completed. {NUM_REQUESTS} new unique requests have been saved to {LOG_CSV}")