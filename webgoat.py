# # #!/usr/bin/env python3
# # """
# # webgoat_realistic_crawler.py
# # Generate realistic benign web traffic for local WebGoat and WebWolf instances.
# # Features realistic data generation without placeholder text like "test".
# # """
# # import requests
# # import time
# # import random
# # import csv
# # import os
# # import json
# # import hashlib
# # from urllib.parse import urljoin
# # from faker import Faker
# # from tqdm import trange
# # from uuid import uuid4
# # from datetime import datetime
# # import re

# # # ---------- CONFIG ----------
# # WEBGOAT_BASE_URL = "http://localhost:8080/WebGoat/"
# # WEBWOLF_BASE_URL = "http://localhost:9090/WebWolf/"
# # NUM_REQUESTS = 10000
# # CONCURRENT_SESSIONS = 1
# # LOG_CSV = "webgoat_benign_requests.csv"
# # VERBOSE = True
# # PROXY = None
# # MIN_DELAY = 0.01
# # MAX_DELAY = 0.05

# # # ---------- Helpers (Updated for Realism) ----------
# # faker = Faker()

# # def generate_benign_creds(): 
# #     """Generates realistic username and password."""
# #     return faker.user_name(), faker.password(length=12)

# # def generate_benign_review(): 
# #     """Generates a realistic product review or comment."""
# #     return faker.sentence(nb_words=12)

# # def generate_benign_message():
# #     """Generates a realistic message body."""
# #     return f"Hello, {faker.first_name()}. {faker.sentence()}"

# # def generate_benign_xml_comment(): 
# #     """Generates a safe XML comment with realistic text."""
# #     return f""

# # # ---------- Traffic Generator ----------
# # class WebGoatGenerator:
# #     def __init__(self):
# #         self.webgoat_url = WEBGOAT_BASE_URL
# #         self.webwolf_url = WEBWOLF_BASE_URL
# #         self.webgoat_session = self._create_new_session()
# #         self.webwolf_session = self._create_new_session()
# #         self.used_signatures = set()
# #         self.csv_file = LOG_CSV
# #         self.csv_headers = [
# #             "_id", "signature", "body_bytes_sent", "ip", "request.method", "request.path",
# #             "request.protocol", "request_body", "status", "timestamp"
# #         ]
# #         self._initialize_csv()
# #         self._load_existing_signatures()

# #     def _initialize_csv(self):
# #         if not os.path.exists(self.csv_file):
# #             with open(self.csv_file, "w", newline='', encoding='utf-8') as f:
# #                 writer = csv.DictWriter(f, fieldnames=self.csv_headers)
# #                 writer.writeheader()
# #                 if VERBOSE: logger.info(f"Created CSV log file: {self.csv_file}")
    
# #     def _load_existing_signatures(self):
# #         if not os.path.exists(self.csv_file): return
# #         try:
# #             with open(self.csv_file, "r", newline='', encoding='utf-8') as f:
# #                 reader = csv.DictReader(f)
# #                 if 'signature' not in reader.fieldnames:
# #                     if VERBOSE: logger.warning("CSV missing 'signature' column. Cannot load old requests.")
# #                     return
# #                 for row in reader:
# #                     if row.get('signature'): self.used_signatures.add(row['signature'])
# #             if VERBOSE: logger.info(f"Loaded {len(self.used_signatures)} existing signatures from {self.csv_file}.")
# #         except Exception as e:
# #             if VERBOSE: logger.error(f"Error loading existing signatures: {e}")

# #     def _create_new_session(self):
# #         s = requests.Session()
# #         if PROXY: s.proxies.update({"http": PROXY, "https": PROXY})
# #         s.headers.update({"User-Agent": faker.user_agent()})
# #         return s

# #     def _log_csv(self, log_data):
# #         with open(self.csv_file, "a", newline='', encoding='utf-8') as f:
# #             writer = csv.DictWriter(f, fieldnames=self.csv_headers)
# #             writer.writerow(log_data)
    
# #     def _login_webgoat(self):
# #         login_url = urljoin(self.webgoat_url, "login")
# #         try:
# #             login_data = {
# #                 "username": "webgoat",
# #                 "password": "webgoat",
# #             }
# #             headers = {
# #                 "Referer": login_url,
# #             }
# #             post_resp = self.webgoat_session.post(
# #                 login_url, 
# #                 data=login_data, 
# #                 headers=headers, 
# #                 allow_redirects=True, 
# #                 timeout=15
# #             )
# #             if post_resp.status_code == 200 and "logout" in post_resp.text.lower():
# #                 if VERBOSE: logger.info("Successfully logged into WebGoat.")
# #                 return True
# #             else:
# #                 if VERBOSE: logger.error(f"WebGoat login failed. Final status: {post_resp.status_code}")
# #                 return False
# #         except requests.RequestException as e:
# #             if VERBOSE: logger.error(f"WebGoat login request failed: {e}")
# #             return False

# #     def _make_request(self, target, method, endpoint, body=None, content_type='application/json'):
# #         if target == 'webgoat':
# #             session = self.webgoat_session
# #             base_url = self.webgoat_url
# #         elif target == 'webwolf':
# #             session = self.webwolf_session
# #             base_url = self.webwolf_url
# #         else: return None
        
# #         url = urljoin(base_url, endpoint)
# #         body_for_sig = str(sorted(body.items())) if isinstance(body, dict) else str(body)
# #         sig_components = [method, endpoint, body_for_sig]
# #         signature = hashlib.md5("|".join(sig_components).encode()).hexdigest()
        
# #         if signature in self.used_signatures: return None
# #         self.used_signatures.add(signature)
        
# #         start_time = datetime.now()
# #         try:
# #             headers = { "Referer": base_url }
# #             if content_type:
# #                 headers['Content-Type'] = content_type

# #             request_kwargs = {"headers": headers, "timeout": 15}
# #             if body:
# #                 if content_type == 'application/json': request_kwargs['json'] = body
# #                 else: request_kwargs['data'] = body
                
# #             resp = session.request(method, url, **request_kwargs)
            
# #             log_entry = {
# #                 "_id": str(uuid4()), "signature": signature, "body_bytes_sent": len(resp.content),
# #                 "ip": "127.0.0.1", "request.method": method, "request.path": endpoint,
# #                 "request.protocol": "HTTP/1.1", "request_body": body_for_sig, "status": resp.status_code,
# #                 "timestamp": start_time.isoformat()
# #             }
# #             self._log_csv(log_entry)
# #             return resp
# #         except requests.RequestException as e:
# #             self.used_signatures.remove(signature)
# #             if VERBOSE: logger.error(f"Request failed for {method} {url}: {e}")
# #         return None

# #     def generate_traffic(self, count=NUM_REQUESTS):
# #         if not self._login_webgoat():
# #             logger.error("Cannot proceed without a WebGoat session. Exiting.")
# #             return
# #         logger.info(f"Starting traffic generation for {count} requests...")
# #         pbar = trange(count, desc="Generating new requests")
# #         generated_count = 0
# #         while generated_count < count:
# #             action = random.choices(["register_user", "sqli_lesson", "xss_lesson", "xxe_lesson", "csrf_lesson", "check_webwolf_mail"],
# #                                   weights=[0.15, 0.25, 0.25, 0.15, 0.15, 0.05], k=1)[0]
# #             resp = None
# #             if action == "register_user":
# #                 user, pw = generate_benign_creds()
# #                 endpoint = "register.mvc"
# #                 body = f"username={user}&password={pw}&matchingPassword={pw}&agree=agree"
# #                 resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
# #             elif action == "sqli_lesson":
# #                 endpoint = "SqlInjection/attack8"
# #                 # Realistic name and valid TAN
# #                 body = {"name": faker.name(), "auth_tan": str(random.randint(100,999))}
# #                 # **MODIFICATION: Changed from application/json to application/x-www-form-urlencoded**
# #                 resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
# #             elif action == "xss_lesson":
# #                 endpoint = "CrossSiteScripting/attack1"
# #                 # Realistic message body
# #                 body = f"text_area={generate_benign_message()}"
# #                 resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
# #             elif action == "xxe_lesson":
# #                 endpoint = "service/restxml"
# #                 body = generate_benign_xml_comment()
# #                 resp = self._make_request('webgoat', "POST", endpoint, body, 'application/xml')
# #             elif action == "csrf_lesson":
# #                 endpoint = "csrf/review"
# #                 # Realistic review text
# #                 body = f"reviewText={generate_benign_review()}&submit=Submit"
# #                 resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
# #             elif action == "check_webwolf_mail":
# #                 endpoint = "mail"
# #                 resp = self._make_request('webwolf', "GET", endpoint, content_type=None)
# #             if resp is not None:
# #                 generated_count += 1
# #                 pbar.update(1)
# #             time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
# #         pbar.close()
# #         print(f"[*] Completed. {generated_count} new unique requests were saved to {LOG_CSV}")

# # # ---------- Main Execution ----------
# # if __name__ == "__main__":
# #     import logging
# #     logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# #     logger = logging.getLogger(__name__)

# #     print(f"[*] WebGoat Benign Traffic Generator - Target: {WEBGOAT_BASE_URL}")
# #     generator = WebGoatGenerator()
# #     generator.generate_traffic(count=NUM_REQUESTS)
# #     print(f"[*] Script finished.")

# #!/usr/bin/env python3




# #!/usr/bin/env python3
# """
# webgoat_realistic_crawler_structural.py
# The ULTIMATE ROBUST Benign Traffic Generator.
# Features:
# - Structural Randomization (10+ different sentence patterns).
# - High-Entropy Vocabulary.
# - Human Typo Simulation.
# - Guaranteed Uniqueness.
# """
# import requests
# import time
# import random
# import csv
# import os
# import hashlib
# from urllib.parse import urljoin
# from faker import Faker
# from tqdm import trange
# from uuid import uuid4
# from datetime import datetime

# # ---------- CONFIG ----------
# WEBGOAT_BASE_URL = "http://localhost:8080/WebGoat/"
# WEBWOLF_BASE_URL = "http://localhost:9090/WebWolf/"
# NUM_REQUESTS = 5000 
# CONCURRENT_SESSIONS = 1
# LOG_CSV = "webgoat_benign_requests.csv"
# VERBOSE = True
# PROXY = None
# MIN_DELAY = 0.01
# MAX_DELAY = 0.05
# DEFAULT_TIMEOUT = 30

# # ---------- VOCABULARY BANKS ----------
# faker = Faker()

# WEB_NOUNS = [
#     "login", "dashboard", "profile", "settings", "API", "server", "database", "connection",
#     "firewall", "interface", "checkout", "cart", "payment", "user", "admin", "session",
#     "cookie", "token", "password", "email", "notification", "alert", "report", "analytics",
#     "widget", "sidebar", "header", "footer", "button", "link", "image", "video", "content",
#     "latency", "bandwidth", "protocol", "endpoint", "query", "parameter", "variable"
# ]

# WEB_VERBS = [
#     "click", "submit", "load", "render", "crash", "fail", "succeed", "update", "delete",
#     "create", "view", "edit", "save", "upload", "download", "connect", "disconnect",
#     "timeout", "redirect", "authorize", "authenticate", "validate", "verify"
# ]

# WEB_ADJECTIVES = [
#     "slow", "fast", "secure", "insecure", "broken", "valid", "invalid", "responsive",
#     "unresponsive", "encrypted", "decrypted", "authorized", "unauthorized", "public",
#     "private", "hidden", "visible", "dynamic", "static", "glitchy", "buggy", "clean"
# ]

# ADVERBS = [
#     "quickly", "slowly", "randomly", "consistently", "weirdly", "suddenly", "finally",
#     "actually", "barely", "constantly", "totally", "completely", "partially"
# ]

# # ---------- DYNAMIC CONTENT ENGINE ----------

# def get_word(type_list):
#     """Returns a domain word 50% of the time, or a random dictionary word."""
#     if random.random() > 0.5:
#         return random.choice(type_list)
#     else:
#         if type_list == WEB_VERBS: return faker.word() # Faker doesn't have explicit verb provider
#         if type_list == WEB_ADJECTIVES: return faker.word()
#         return faker.word()

# def inject_typo(text):
#     """Randomly injects typos to simulate human error."""
#     if random.random() > 0.90: # 10% chance of typo
#         char_list = list(text)
#         if len(char_list) < 5: return text
#         idx = random.randint(0, len(char_list)-2)
#         # Swap two characters
#         char_list[idx], char_list[idx+1] = char_list[idx+1], char_list[idx]
#         return "".join(char_list)
#     return text

# def generate_varied_sentence():
#     """
#     Generates a sentence using one of 10 different grammatical structures.
#     This prevents the model from overfitting on a specific phrase like "Regarding the..."
#     """
#     n = get_word(WEB_NOUNS)
#     v = get_word(WEB_VERBS)
#     adj = get_word(WEB_ADJECTIVES)
#     adv = random.choice(ADVERBS)
    
#     structure = random.randint(1, 10)
    
#     if structure == 1:
#         s = f"The {n} is {adv} {adj}."
#     elif structure == 2:
#         s = f"Why does the {n} {v} so {adv}?"
#     elif structure == 3:
#         s = f"I tried to {v} the {n} but it failed."
#     elif structure == 4:
#         s = f"{random.choice(['Honestly', 'Basically', 'Actually'])}, the {n} looks {adj}."
#     elif structure == 5:
#         s = f"Please check the {n}, it seems {adj}."
#     elif structure == 6:
#         s = f"Whenever I {v}, the {n} becomes {adj}."
#     elif structure == 7:
#         s = f"Is the {n} supposed to be {adj}?"
#     elif structure == 8:
#         s = f"Fixed the {adj} {n} issue."
#     elif structure == 9:
#         s = f"Noticed unusual behavior in the {n} module."
#     else:
#         s = f"{n} {v} error." # Short, terse logging style

#     return inject_typo(s)

# def generate_human_message():
#     """Combines 1-3 sentences to form a complete message."""
#     length = random.randint(1, 3)
#     sentences = [generate_varied_sentence() for _ in range(length)]
#     return " ".join(sentences)

# def generate_benign_creds():
#     """Generates diverse username formats."""
#     style = random.randint(1, 3)
#     if style == 1: u = f"{faker.first_name()}{random.randint(10,99)}"
#     elif style == 2: u = f"{faker.word()}.{faker.word()}"
#     else: u = faker.user_name()
#     return u, faker.password(length=12)

# def generate_benign_xml_comment():
#     return f""

# # ---------- Traffic Generator ----------
# class WebGoatGenerator:
#     def __init__(self):
#         self.webgoat_url = WEBGOAT_BASE_URL
#         self.webwolf_url = WEBWOLF_BASE_URL
#         self.webgoat_session = self._create_new_session()
#         self.webwolf_session = self._create_new_session()
#         self.used_signatures = set()
#         self.csv_file = LOG_CSV
#         self.csv_headers = [
#             "_id", "signature", "body_bytes_sent", "ip", "request.method", "request.path",
#             "request.protocol", "request_body", "status", "timestamp"
#         ]
#         self._initialize_csv()
#         self._load_existing_signatures()

#     def _initialize_csv(self):
#         if not os.path.exists(self.csv_file):
#             with open(self.csv_file, "w", newline='', encoding='utf-8') as f:
#                 writer = csv.DictWriter(f, fieldnames=self.csv_headers)
#                 writer.writeheader()
#                 if VERBOSE: logger.info(f"Created CSV log file: {self.csv_file}")
    
#     def _load_existing_signatures(self):
#         if not os.path.exists(self.csv_file): return
#         try:
#             with open(self.csv_file, "r", newline='', encoding='utf-8') as f:
#                 reader = csv.DictReader(f)
#                 if 'signature' not in reader.fieldnames: return
#                 for row in reader:
#                     if row.get('signature'): self.used_signatures.add(row['signature'])
#             if VERBOSE: logger.info(f"Loaded {len(self.used_signatures)} existing signatures.")
#         except Exception: pass

#     def _create_new_session(self):
#         s = requests.Session()
#         if PROXY: s.proxies.update({"http": PROXY, "https": PROXY})
#         s.headers.update({"User-Agent": faker.user_agent()})
#         return s

#     def _log_csv(self, log_data):
#         with open(self.csv_file, "a", newline='', encoding='utf-8') as f:
#             writer = csv.DictWriter(f, fieldnames=self.csv_headers)
#             writer.writerow(log_data)
    
#     def _login_webgoat(self):
#         login_url = urljoin(self.webgoat_url, "login")
#         try:
#             login_data = {"username": "webgoat", "password": "webgoat"}
#             headers = {"Referer": login_url}
#             post_resp = self.webgoat_session.post(
#                 login_url, data=login_data, headers=headers, 
#                 allow_redirects=True, timeout=DEFAULT_TIMEOUT
#             )
#             if post_resp.status_code == 200 and "logout" in post_resp.text.lower():
#                 if VERBOSE: logger.info("Successfully logged into WebGoat.")
#                 return True
#             return False
#         except requests.RequestException:
#             return False

#     def _make_request(self, target, method, endpoint, body=None, content_type='application/json'):
#         if target == 'webgoat':
#             session = self.webgoat_session
#             base_url = self.webgoat_url
#         elif target == 'webwolf':
#             session = self.webwolf_session
#             base_url = self.webwolf_url
#         else: return None
        
#         url = urljoin(base_url, endpoint)
#         body_for_sig = str(sorted(body.items())) if isinstance(body, dict) else str(body)
#         sig_components = [method, endpoint, body_for_sig]
#         signature = hashlib.md5("|".join(sig_components).encode()).hexdigest()
        
#         if signature in self.used_signatures: return None
#         self.used_signatures.add(signature)
        
#         start_time = datetime.now()
#         try:
#             headers = { "Referer": base_url }
#             if content_type:
#                 headers['Content-Type'] = content_type

#             request_kwargs = {"headers": headers, "timeout": DEFAULT_TIMEOUT}
#             if body:
#                 if content_type == 'application/json': request_kwargs['json'] = body
#                 else: request_kwargs['data'] = body
                
#             resp = session.request(method, url, **request_kwargs)
            
#             log_entry = {
#                 "_id": str(uuid4()), "signature": signature, "body_bytes_sent": len(resp.content),
#                 "ip": "127.0.0.1", "request.method": method, "request.path": endpoint,
#                 "request.protocol": "HTTP/1.1", "request_body": body_for_sig, "status": resp.status_code,
#                 "timestamp": start_time.isoformat()
#             }
#             self._log_csv(log_entry)
#             return resp
#         except requests.RequestException:
#             self.used_signatures.remove(signature)
#         return None

#     def generate_traffic(self, count=NUM_REQUESTS):
#         if not self._login_webgoat():
#             logger.error("Cannot proceed without a WebGoat session. Exiting.")
#             return
#         logger.info(f"Starting traffic generation for {count} requests...")
#         pbar = trange(count, desc="Generating new requests")
#         generated_count = 0
        
#         weights = [0.05, 0.27, 0.27, 0.17, 0.17, 0.07]
        
#         while generated_count < count:
#             action = random.choices(["register_user", "sqli_lesson", "xss_lesson", "xxe_lesson", "csrf_lesson", "check_webwolf_mail"],
#                                   weights=weights, k=1)[0]
#             resp = None
#             if action == "register_user":
#                 user, pw = generate_benign_creds()
#                 endpoint = "register.mvc"
#                 body = f"username={user}&password={pw}&matchingPassword={pw}&agree=agree"
#                 resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
#             elif action == "sqli_lesson":
#                 endpoint = "SqlInjection/attack8"
#                 # Using form-urlencoded. Random names.
#                 body = f"name={faker.name()}&auth_tan={random.randint(100,999)}"
#                 resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
#             elif action == "xss_lesson":
#                 endpoint = "CrossSiteScripting/attack1"
#                 # STRUCTURALLY RANDOMIZED MESSAGE
#                 body = f"text_area={generate_human_message()}"
#                 resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
#             elif action == "xxe_lesson":
#                 endpoint = "service/restxml"
#                 body = generate_benign_xml_comment()
#                 resp = self._make_request('webgoat', "POST", endpoint, body, 'application/xml')
#             elif action == "csrf_lesson":
#                 endpoint = "csrf/review"
#                 # STRUCTURALLY RANDOMIZED REVIEW
#                 body = f"reviewText={generate_human_message()}&submit=Submit"
#                 resp = self._make_request('webgoat', "POST", endpoint, body, 'application/x-www-form-urlencoded')
#             elif action == "check_webwolf_mail":
#                 endpoint = "mail"
#                 resp = self._make_request('webwolf', "GET", endpoint, content_type=None)
            
#             if resp is not None:
#                 generated_count += 1
#                 pbar.update(1)
#             time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
#         pbar.close()
#         print(f"[*] Completed. {generated_count} new unique requests were saved to {LOG_CSV}")

# # ---------- Main Execution ----------
# if __name__ == "__main__":
#     import logging
#     logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
#     logger = logging.getLogger(__name__)

#     print(f"[*] WebGoat Benign Traffic Generator - Target: {WEBGOAT_BASE_URL}")
#     generator = WebGoatGenerator()
#     generator.generate_traffic(count=NUM_REQUESTS)
#     print(f"[*] Script finished.")


#!/usr/bin/env python3
"""
webgoat_benign_balanced.py
Generate realistic benign web traffic with a balanced mix of GET (Browsing) and POST (Interaction).
Cleaned to ensure CSV logs do not break across multiple lines.
"""
import requests
import time
import random
import csv
import os
import hashlib
from urllib.parse import urljoin
from faker import Faker
from tqdm import trange
from uuid import uuid4
from datetime import datetime

# ---------- CONFIG ----------
WEBGOAT_BASE_URL = "http://localhost:8080/WebGoat/"
WEBWOLF_BASE_URL = "http://localhost:9090/WebWolf/"
NUM_REQUESTS = 50000 
CONCURRENT_SESSIONS = 1
LOG_CSV = "webgoat_benign_requestas.csv"
VERBOSE = True
PROXY = None
MIN_DELAY = 0.01
MAX_DELAY = 0.05
DEFAULT_TIMEOUT = 30

# ---------- FAKER SETUP ----------
faker = Faker()

# Standard pages to "Browse" (GET requests)
BENIGN_PAGES = [
    "start.mvc",
    "welcome.mvc",
    "lessons",
    "service/lessonmenu.mvc",
    "registration",
    "login",
    "scoreboard",
    "about.mvc"
]

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
                if 'signature' not in reader.fieldnames: return
                for row in reader:
                    if row.get('signature'): self.used_signatures.add(row['signature'])
            if VERBOSE: logger.info(f"Loaded {len(self.used_signatures)} existing signatures.")
        except Exception: pass

    def _create_new_session(self):
        s = requests.Session()
        if PROXY: s.proxies.update({"http": PROXY, "https": PROXY})
        s.headers.update({"User-Agent": faker.user_agent()})
        return s

    def _log_csv(self, log_data):
        with open(self.csv_file, "a", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.csv_headers)
            writer.writerow(log_data)
    
    def _login_webgoat(self):
        login_url = urljoin(self.webgoat_url, "login")
        try:
            login_data = {"username": "webgoat", "password": "webgoat"}
            headers = {"Referer": login_url}
            post_resp = self.webgoat_session.post(
                login_url, data=login_data, headers=headers, 
                allow_redirects=True, timeout=DEFAULT_TIMEOUT
            )
            if post_resp.status_code == 200 and "logout" in post_resp.text.lower():
                if VERBOSE: logger.info("Successfully logged into WebGoat.")
                return True
            return False
        except requests.RequestException:
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
        
        # Calculate signature based on available data
        if method == "GET":
            sig_components = [method, endpoint, str(uuid4())] 
            request_body_str = "N/A"
        else:
            request_body_str = str(sorted(body.items())) if isinstance(body, dict) else str(body)
            sig_components = [method, endpoint, request_body_str]

        signature = hashlib.md5("|".join(sig_components).encode()).hexdigest()
        
        if signature in self.used_signatures: return None
        self.used_signatures.add(signature)
        
        start_time = datetime.now()
        try:
            headers = { "Referer": base_url }
            if content_type:
                headers['Content-Type'] = content_type

            request_kwargs = {"headers": headers, "timeout": DEFAULT_TIMEOUT}
            
            if method == "POST":
                if body:
                    if content_type == 'application/json': request_kwargs['json'] = body
                    else: request_kwargs['data'] = body
                resp = session.request(method, url, **request_kwargs)
            else:
                # GET Request
                resp = session.request(method, url, **request_kwargs)
            
            log_entry = {
                "_id": str(uuid4()), "signature": signature, "body_bytes_sent": len(resp.content),
                "ip": "127.0.0.1", "request.method": method, "request.path": endpoint,
                "request.protocol": "HTTP/1.1", "request_body": request_body_str, "status": resp.status_code,
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
        
        # Updated list of actions including "browse"
        actions = [
            "browse_page",          # GET (New)
            "register_user",        # POST
            "sqli_lesson",          # POST
            "xss_lesson",           # POST
            "xxe_lesson",           # POST
            "csrf_lesson",          # POST
            "check_webwolf_mail"    # GET
        ]
        
        # Weights: roughly 50% GET requests, 50% POST requests
        weights = [0.25, 0.05, 0.20, 0.20, 0.15, 0.10, 0.05]
        
        while generated_count < count:
            action = random.choices(actions, weights=weights, k=1)[0]
            resp = None
            
            if action == "browse_page":
                page = random.choice(BENIGN_PAGES)
                if random.random() > 0.7:
                    page = f"{page}?id={random.randint(1,100)}"
                resp = self._make_request('webgoat', "GET", endpoint=page, content_type=None)

            elif action == "register_user":
                body = f"username={faker.user_name()}{random.randint(10,99)}&password={faker.password()}&matchingPassword={faker.password()}&agree=agree"
                resp = self._make_request('webgoat', "POST", endpoint="register.mvc", body=body, content_type='application/x-www-form-urlencoded')
            
            elif action == "sqli_lesson":
                body = f"name={faker.name()}&auth_tan={random.randint(100,999)}"
                resp = self._make_request('webgoat', "POST", endpoint="SqlInjection/attack8", body=body, content_type='application/x-www-form-urlencoded')
            
            elif action == "xss_lesson":
                # **FIXED: Removed newlines from text generation**
                clean_text = faker.text(max_nb_chars=200).replace('\n', ' ').replace('\r', '')
                body = f"text_area={clean_text}"
                resp = self._make_request('webgoat', "POST", endpoint="CrossSiteScripting/attack1", body=body, content_type='application/x-www-form-urlencoded')
            
            elif action == "xxe_lesson":
                body = f""
                resp = self._make_request('webgoat', "POST", endpoint="service/restxml", body=body, content_type='application/xml')
            
            elif action == "csrf_lesson":
                # **FIXED: Removed newlines from sentence generation just in case**
                clean_review = faker.sentence(nb_words=15).replace('\n', ' ')
                body = f"reviewText={clean_review}&submit=Submit"
                resp = self._make_request('webgoat', "POST", endpoint="csrf/review", body=body, content_type='application/x-www-form-urlencoded')
            
            elif action == "check_webwolf_mail":
                resp = self._make_request('webwolf', "GET", endpoint="mail", content_type=None)
            
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