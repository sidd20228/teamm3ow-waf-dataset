"""
webgoat_realistic_crawler.py
Generate realistic benign web traffic for local WebGoat and WebWolf instances
for training machine learning models.
"""
import requests
import time
import random
import csv
import os
import json
import hashlib
from urllib.parse import urljoin
from faker import Faker
from tqdm import trange
from uuid import uuid4
from datetime import datetime
import re

# ---------- CONFIG ----------
WEBGOAT_BASE_URL = "http://localhost:8080/WebGoat/"
WEBWOLF_BASE_URL = "http://localhost:9090/WebWolf/"
NUM_REQUESTS = 10000
CONCURRENT_SESSIONS = 1
LOG_CSV = "webgoat_benign_requests.csv"
VERBOSE = True
PROXY = None
MIN_DELAY = 0.05
MAX_DELAY = 0.25

# ---------- Helpers ----------
faker = Faker()
def generate_benign_creds(): return faker.user_name(), faker.password(length=12)
def generate_benign_review(): return faker.sentence(nb_words=10)
def generate_benign_xml_comment(): return f""


# ---------- Traffic Generator ----------
class WebGoatGenerator:
    def __init__(self):
        self.webgoat_url = WEBGOAT_BASE_URL
        self.webwolf_url = WEBWOLF_BASE_URL
        self.webgoat_session = self._create_new_session()
        self.webwolf_session = self._create_new_session()
        self.used_signatures = set()
        self.csv_file = LOG_CSV
        self.csv_headers = [
            "_id", "signature", "body_bytes_sent", "ip", "request.method", "request.path",
            "request.protocol", "request_body", "status", "timestamp"
        ]
        self._initialize_csv()
        self._load_existing_signatures()

    def _initialize_csv(self):
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.csv_headers)
                writer.writeheader()
                if VERBOSE: logger.info(f"Created CSV log file: {self.csv_file}")
    
    def _load_existing_signatures(self):
        if not os.path.exists(self.csv_file): return
        try:
            with open(self.csv_file, "r", newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                if 'signature' not in reader.fieldnames:
                    if VERBOSE: logger.warning("CSV missing 'signature' column. Cannot load old requests.")
                    return
                for row in reader:
                    if row.get('signature'): self.used_signatures.add(row['signature'])
            if VERBOSE: logger.info(f"Loaded {len(self.used_signatures)} existing signatures from {self.csv_file}.")
        except Exception as e:
            if VERBOSE: logger.error(f"Error loading existing signatures: {e}")

    def _create_new_session(self):
        s = requests.Session()
        if PROXY: s.proxies.update({"http": PROXY, "https": PROXY})
        s.headers.update({"User-Agent": faker.user_agent()})
        return s

    def _log_csv(self, log_data):
        with open(self.csv_file, "a", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.csv_headers)
            writer.writerow(log_data)
    
    # **MODIFICATION: Final login logic mimicking the browser.**
    def _login_webgoat(self):
        """Logs into WebGoat by sending a standard form POST."""
        login_url = urljoin(self.webgoat_url, "login")
        
        try:
            # The session object will handle cookies automatically.
            # We don't need a separate GET request.
            
            login_data = {
                "username": "webgoat",
                "password": "webgoat",
            }
            
            headers = {
                "Referer": login_url,
                # The Content-Type is set automatically by requests for the `data` parameter
            }

            post_resp = self.webgoat_session.post(
                login_url, 
                data=login_data, 
                headers=headers, 
                allow_redirects=True, # This is key: requests will follow the 302 redirect
                timeout=15
            )
            
            # The FINAL page after the redirect should be 200 OK and contain "logout".
            if post_resp.status_code == 200 and "logout" in post_resp.text.lower():
                if VERBOSE: logger.info("Successfully logged into WebGoat.")
                return True
            else:
                if VERBOSE: logger.error(f"WebGoat login failed. Final status: {post_resp.status_code}")
                return False
        except requests.RequestException as e:
            if VERBOSE: logger.error(f"WebGoat login request failed: {e}")
            return False

    def _make_request(self, target, method, endpoint, body=None, content_type='application/json'):
        if target == 'webgoat':
            session = self.webgoat_session
            base_url = self.webgoat_url
        elif target == 'webwolf':
            session = self.webwolf_session
            base_url = self.webwolf_url
        else: return None
        
        url = urljoin(base_url, endpoint)
        body_for_sig = str(sorted(body.items())) if isinstance(body, dict) else str(body)
        sig_components = [method, endpoint, body_for_sig]
        signature = hashlib.md5("|".join(sig_components).encode()).hexdigest()
        
        if signature in self.used_signatures: return None
        self.used_signatures.add(signature)
        
        start_time = datetime.now()
        try:
            # **MODIFICATION: Removed the incorrect X-Requested-With header.**
            headers = { "Referer": base_url }
            if content_type:
                headers['Content-Type'] = content_type

            request_kwargs = {"headers": headers, "timeout": 15}
            if body:
                if content_type == 'application/json': request_kwargs['json'] = body
                else: request_kwargs['data'] = body
                
            resp = session.request(method, url, **request_kwargs)
            
            log_entry = {
                "_id": str(uuid4()), "signature": signature, "body_bytes_sent": len(resp.content),
                "ip": "127.0.0.1", "request.method": method, "request.path": endpoint,
                "request.protocol": "HTTP/1.1", "request_body": body_for_sig, "status": resp.status_code,
                "timestamp": start_time.isoformat()
            }
            self._log_csv(log_entry)
            return resp
        except requests.RequestException as e:
            self.used_signatures.remove(signature)
            if VERBOSE: logger.error(f"Request failed for {method} {url}: {e}")
        return None

    def generate_traffic(self, count=NUM_REQUESTS):
        if not self._login_webgoat():
            logger.error("Cannot proceed without a WebGoat session. Exiting.")
            return
        logger.info(f"Starting traffic generation for {count} requests...")
        pbar = trange(count, desc="Generating new requests")
        generated_count = 0
        while generated_count < count:
            action = random.choices(["register_user", "sqli_lesson", "xss_lesson", "xxe_lesson", "csrf_lesson", "check_webwolf_mail"],
                                  weights=[0.15, 0.25, 0.25, 0.15, 0.15, 0.05], k=1)[0]
            resp = None
            if action == "register_user":
                user, pw = generate_benign_creds()
                endpoint = "register.mvc"
                body = f"username={user}&password={pw}&matchingPassword={pw}&agree=agree"
                resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
            elif action == "sqli_lesson":
                endpoint = "SqlInjection/attack8"
                body = {"name": faker.first_name(), "auth_tan": str(random.randint(100,999))}
                resp = self._make_request('webgoat', "POST", endpoint, body, 'application/json')
            elif action == "xss_lesson":
                endpoint = "CrossSiteScripting/attack1"
                body = f"text_area=Hello, this is a test message from {faker.name()}."
                resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
            elif action == "xxe_lesson":
                endpoint = "service/restxml"
                body = generate_benign_xml_comment()
                resp = self._make_request('webgoat', "POST", endpoint, body, 'application/xml')
            elif action == "csrf_lesson":
                endpoint = "csrf/review"
                body = f"reviewText={generate_benign_review()}&submit=Submit"
                resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
            elif action == "check_webwolf_mail":
                endpoint = "mail"
                resp = self._make_request('webwolf', "GET", endpoint, content_type=None)
            if resp is not None:
                generated_count += 1
                pbar.update(1)
            time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
        pbar.close()
        print(f"[*] Completed. {generated_count} new unique requests were saved to {LOG_CSV}")

# ---------- Main Execution ----------
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    print(f"[*] WebGoat Benign Traffic Generator - Target: {WEBGOAT_BASE_URL}")
    generator = WebGoatGenerator()
    generator.generate_traffic(count=NUM_REQUESTS)
    print(f"[*] Script finished.")  