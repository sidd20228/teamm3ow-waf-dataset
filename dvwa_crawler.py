#!/usr/bin/env python3
"""
dvwa_realistic_crawler.py
Generate realistic benign web traffic for local DVWA for training transformer models.

REALISTIC TRAFFIC FEATURES:
- Natural HTTP method distribution (~70% GET, ~25% POST, ~5% other methods)
- Appropriate methods per endpoint (no DELETE on login forms, etc.)
- Realistic content types (form-urlencoded for web forms, JSON only for APIs)
- DVWA-specific vulnerability module targeting with appropriate parameters
- Standard web browser headers without unnecessary custom headers
- Proper form data for login, upload, and security settings endpoints
- Sophisticated duplicate detection using comprehensive request signatures
- Enhanced logging with content types, request/response sizes, and header hashes

Usage:
    python dvwa_realistic_crawler.py

NOTE: Run only against your local DVWA or systems you are authorized to test.
All generated requests simulate normal benign web browsing behavior.
"""
import requests
import time
import random
import string
import csv
import os
import json
import base64
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
from bs4 import BeautifulSoup
from faker import Faker
from tqdm import trange

# ---------- CONFIG ----------
BASE_URL = "http://localhost:8081/DVWA/"   # change if needed
NUM_REQUESTS = 10000
CONCURRENT_SESSIONS = 6   # number of simulated users/sessions to rotate
DEFAULT_TIMEOUT = 10
MIN_DELAY = 0.01
MAX_DELAY = 0.12
LOG_CSV = "dvwa_benign_requests.csv"
VERBOSE = False
# Optional HTTP proxy (e.g., ZAP) - set to None to disable
PROXY = None  # e.g. "http://127.0.0.1:8080"

# Authentication/session tuning for long runs
AUTH_TTL_SECONDS = 600  # re-authenticate a session after ~10 minutes to avoid PHP session expiry

# HTTP Methods distribution for equal representation
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded", 
    "multipart/form-data",
    "text/plain",
    "application/xml",
    "text/xml",
    "text/html",
    "application/octet-stream"
]

# ---------- Helpers ----------
faker = Faker()

def rand_uid(n=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def benign_xss_like(uid):
    return f"{faker.first_name()}_{uid}_safe"

def benign_sql_like(uid):
    return f"{random.randint(1,99999)}-{uid}"

def benign_cmd():
    return random.choice(["pwd","whoami","date","echo hello"])

def generate_complex_data():
    """Generate complex nested data structures for diverse requests"""
    data_types = [
        # Simple values
        lambda: faker.word(),
        lambda: str(random.randint(1, 100000)),
        lambda: faker.email(),
        lambda: faker.url(),
        lambda: faker.ipv4(),
        lambda: faker.uuid4(),
        lambda: datetime.now().isoformat(),
        lambda: base64.b64encode(faker.text().encode()).decode()[:20],
        # Arrays
        lambda: [faker.word() for _ in range(random.randint(1, 5))],
        lambda: [random.randint(1, 1000) for _ in range(random.randint(1, 3))],
        # Nested objects
        lambda: {
            "nested": faker.word(),
            "count": random.randint(1, 100),
            "active": random.choice([True, False])
        }
    ]
    return random.choice(data_types)()

def generate_diverse_params():
    """Generate diverse parameter combinations"""
    param_patterns = [
        {"q": faker.word(), "page": random.randint(1, 50)},
        {"search": faker.sentence(), "limit": random.randint(10, 100)},
        {"filter": faker.word(), "sort": random.choice(["asc", "desc"])},
        {"category": faker.word(), "type": faker.word()},
        {"start_date": faker.date_object().isoformat(), "end_date": faker.date_object().isoformat()},
        {"user_id": random.randint(1, 10000), "action": faker.word()},
        {"api_key": faker.uuid4(), "format": random.choice(["json", "xml", "csv"])},
        {"lang": random.choice(["en", "es", "fr", "de"]), "timezone": faker.timezone()},
        {"debug": random.choice(["true", "false", "1", "0"])},
        {"version": f"v{random.randint(1, 5)}", "client": faker.user_agent()}
    ]
    base = random.choice(param_patterns).copy()
    # Add some random parameters
    for _ in range(random.randint(0, 3)):
        base[faker.word()] = generate_complex_data()
    return base

def generate_json_payload():
    """Generate diverse JSON payloads"""
    payloads = [
        {"user": {"name": faker.name(), "email": faker.email(), "age": random.randint(18, 80)}},
        {"query": faker.sentence(), "filters": {faker.word(): faker.word() for _ in range(3)}},
        {"data": [{"id": i, "value": faker.word()} for i in range(random.randint(1, 5))]},
        {"settings": {"theme": faker.color_name(), "notifications": random.choice([True, False])}},
        {"coordinates": {"lat": float(faker.latitude()), "lng": float(faker.longitude())}},
        {"metadata": {faker.word(): generate_complex_data() for _ in range(random.randint(2, 5))}}
    ]
    return random.choice(payloads)

def generate_xml_payload():
    """Generate XML payload"""
    root_element = faker.word()
    items = []
    for _ in range(random.randint(1, 3)):
        items.append(f"<{faker.word()}>{faker.sentence()}</{faker.word()}>")
    return f"<{root_element}>{''.join(items)}</{root_element}>"

def generate_realistic_file_content(file_type):
    """Generate realistic file content based on file type"""
    if file_type == "txt":
        return f"""Sample Document - {faker.catch_phrase()}
        
Created by: {faker.name()}
Date: {faker.date()}

{faker.text(max_nb_chars=500)}

---
End of document
"""
    elif file_type == "csv":
        lines = ["id,name,email,department,salary"]
        for i in range(random.randint(3, 10)):
            lines.append(f"{i+1},{faker.name()},{faker.email()},{faker.job()},{random.randint(30000, 120000)}")
        return "\n".join(lines)
    
    elif file_type == "json":
        return json.dumps({
            "employees": [
                {
                    "id": i+1,
                    "name": faker.name(),
                    "email": faker.email(),
                    "position": faker.job(),
                    "joined": faker.date_object().isoformat()
                } for i in range(random.randint(2, 5))
            ],
            "metadata": {
                "generated": datetime.now().isoformat(),
                "version": f"v{random.randint(1, 5)}.{random.randint(0, 9)}"
            }
        }, indent=2)
    
    elif file_type == "xml":
        items = []
        for i in range(random.randint(2, 5)):
            items.append(f"""
    <employee id="{i+1}">
        <name>{faker.name()}</name>
        <email>{faker.email()}</email>
        <department>{faker.job()}</department>
    </employee>""")
        
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<company>
    <name>{faker.company()}</name>
    <employees>{"".join(items)}
    </employees>
</company>"""
    
    else:
        return f"Generated content for {file_type} file - {faker.text()}"

def generate_url_variations(base_url):
    """Generate diverse URL variations with encoding, fragments, etc."""
    variations = [base_url]
    
    # Add query parameters with encoding variations
    params = generate_diverse_params()
    query_strings = []
    
    # Normal encoding
    query_strings.append("&".join([f"{k}={v}" for k, v in params.items()]))
    
    # URL encoding
    query_strings.append("&".join([f"{quote(str(k))}={quote(str(v))}" for k, v in params.items()]))
    
    # Mixed encoding
    for k, v in params.items():
        if random.random() < 0.3:
            query_strings.append(f"{k}={quote(str(v))}")
        else:
            query_strings.append(f"{k}={v}")
    
    # Add fragments sometimes
    for qs in query_strings[:3]:  # Limit to avoid too many variations
        url_with_params = f"{base_url}?{qs}"
        variations.append(url_with_params)
        
        # Add fragment
        if random.random() < 0.3:
            fragment = random.choice(["section1", "top", "content", faker.word()])
            variations.append(f"{url_with_params}#{fragment}")
    
    return random.choice(variations)

def gen_headers():
    h = {
        "User-Agent": faker.user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9","en-GB,en;q=0.9","fr-FR,fr;q=0.9"]),
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
    }
    
    # Add referer for realistic browsing behavior
    if random.random() < 0.8:
        h["Referer"] = random.choice([BASE_URL, urljoin(BASE_URL,"index.php")])
    
    # Occasionally add common optional headers
    optional_headers = []
    
    if random.random() < 0.3:
        optional_headers.append(("Cache-Control", random.choice(["no-cache", "max-age=0"])))
    
    if random.random() < 0.2:
        optional_headers.append(("X-Requested-With", "XMLHttpRequest"))
        
    if random.random() < 0.1:
        optional_headers.append(("DNT", "1"))
        
    if random.random() < 0.1:
        optional_headers.append(("Upgrade-Insecure-Requests", "1"))
    
    # Add selected optional headers
    for header, value in optional_headers:
        h[header] = value
    
    return h

def unique_query_params(base=None):
    base = dict(base or {})
    base["_uid"] = rand_uid(12)
    if random.random() < 0.4:
        base["_t"] = str(int(time.time()*1000))[-6:]
    # occasionally add a random benign parameter
    if random.random() < 0.2:
        base["debug"] = random.choice(["0","1","yes","no"])
    return base

# ---------- Crawler & form extractor ----------
class SiteCrawler:
    def __init__(self, session):
        self.session = session
        self.found_urls = set()
        self.form_targets = []  # list of dicts: {url, method, inputs}
    
    def crawl(self, start_path="", max_pages=150):
        start = urljoin(BASE_URL, start_path)
        to_visit = [start]
        self.found_urls.add(start)
        idx = 0
        while to_visit and idx < max_pages:
            url = to_visit.pop(0)
            idx += 1
            try:
                resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
                if resp.status_code != 200:
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                # collect links
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith("#") or href.lower().startswith("mailto:"):
                        continue
                    full = urljoin(url, href)
                    parsed = urlparse(full)
                    # restrict to same host / path under DVWA
                    if parsed.netloc and "localhost" not in parsed.netloc and "127.0.0.1" not in parsed.netloc:
                        continue
                    if full not in self.found_urls and BASE_URL.rstrip("/") in full:
                        self.found_urls.add(full)
                        to_visit.append(full)
                # collect forms
                for form in soup.find_all("form"):
                    action = form.get("action") or url
                    full_action = urljoin(url, action)
                    method = form.get("method", "get").lower()
                    inputs = []
                    for inp in form.find_all(["input","textarea","select"]):
                        name = inp.get("name")
                        if not name:
                            continue
                        itype = inp.get("type","text")
                        inputs.append({"name": name, "type": itype})
                    self.form_targets.append({"url": full_action, "method": method, "inputs": inputs})
            except Exception:
                continue

# ---------- Traffic generator ----------
class DVWAGenerator:
    def __init__(self, base=BASE_URL, sessions=CONCURRENT_SESSIONS):
        self.base = base if base.endswith("/") else base + "/"
        self.sessions = [self._new_session() for _ in range(sessions)]
        self.crawled = False
        self.crawler = None
        self.all_endpoints = set()
        self.all_forms = []
        self.authenticated_sessions = set()
        self.last_auth_time = {i: 0 for i in range(sessions)}
        # prepare CSV
        self.csv_file = LOG_CSV
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp","session_id","method","url","params_or_data","status","unique_token","content_type","request_size","response_size","headers_hash"])

    def _new_session(self):
        s = requests.Session()
        if PROXY:
            s.proxies.update({"http":PROXY,"https":PROXY})
        s.headers.update({"User-Agent": faker.user_agent()})
        return s

    def _log_csv(self, session_id, method, url, pdata, status, token):
        with open(self.csv_file, "a", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([int(time.time()), session_id, method, url, str(pdata), status, token])

    def crawl_site(self, max_pages=250):
        # use first session to crawl and extract forms/links
        s0 = self.sessions[0]
        
        # Authenticate the session first
        if self._authenticate_session(s0, 0):
            if VERBOSE:
                print("[Crawl] Session authenticated, starting crawl...")
            # Start crawling from the main index page, not login
            start_path = "index.php"
        else:
            if VERBOSE:
                print("[Crawl] Warning: Could not authenticate session, limited access expected")
            # If not authenticated, still try from root
            start_path = ""
        
        self.crawler = SiteCrawler(s0)
        self.crawler.crawl(start_path, max_pages=max_pages)
        self.all_endpoints = set(self.crawler.found_urls)
        self.all_forms = list(self.crawler.form_targets)
        self.crawled = True
        if VERBOSE:
            print(f"[Crawl] found {len(self.all_endpoints)} pages and {len(self.all_forms)} forms")

    def _get_csrf_token(self, session, page_path):
        try:
            resp = session.get(page_path, timeout=DEFAULT_TIMEOUT, verify=False)
            if not resp or resp.status_code != 200:
                return None
            soup = BeautifulSoup(resp.text, "html.parser")
            el = soup.find("input", {"name": "user_token"}) or soup.find("input", {"name":"csrf_token"}) or soup.find("input", {"name":"token"})
            if el and el.has_attr("value"):
                return el["value"]
        except Exception:
            return None
        return None

    def _unique_sig(self, url, params):
        return f"{url}|{str(params)}|{rand_uid(6)}"

    def _session_rotate(self, idx):
        return self.sessions[idx % len(self.sessions)]
    
    def _authenticate_session(self, session, session_id, force=False):
        """Authenticate a session with DVWA using admin/password"""
        # enforce TTL for long runs
        now = time.time()
        if not force and session_id in self.authenticated_sessions and (now - self.last_auth_time.get(session_id, 0) < AUTH_TTL_SECONDS):
            return True
            
        try:
            # First, get the login page to retrieve any CSRF tokens
            login_url = urljoin(self.base, "login.php")
            resp = session.get(login_url, timeout=DEFAULT_TIMEOUT, verify=False)
            
            if resp.status_code != 200:
                return False
                
            # Parse for CSRF token if present
            soup = BeautifulSoup(resp.text, "html.parser")
            csrf_token = None
            token_input = soup.find("input", {"name": "user_token"})
            if token_input and token_input.has_attr("value"):
                csrf_token = token_input["value"]
            
            # Prepare login data
            login_data = {
                "username": "admin",
                "password": "password",
                "Login": "Login"
            }
            
            if csrf_token:
                login_data["user_token"] = csrf_token
                
            # Submit login form
            login_resp = session.post(
                login_url,
                data=login_data,
                headers={
                    "User-Agent": faker.user_agent(),
                    "Referer": login_url,
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                timeout=DEFAULT_TIMEOUT,
                verify=False,
                allow_redirects=True
            )
            
            # Check if login was successful 
            if login_resp.status_code == 200:
                if VERBOSE:
                    print(f"[Auth] Login response URL: {login_resp.url}")
                    print(f"[Auth] Login response contains 'Login failed': {'Login failed' in login_resp.text}")
                    print(f"[Auth] Login response contains 'Welcome': {'Welcome' in login_resp.text}")
                
                # Check for successful login indicators
                if ("index.php" in login_resp.url or 
                    "Welcome" in login_resp.text or 
                    "Logout" in login_resp.text or
                    "Login failed" not in login_resp.text and "login.php" not in login_resp.url):
                    self.authenticated_sessions.add(session_id)
                    self.last_auth_time[session_id] = now
                    if VERBOSE:
                        print(f"[Auth] Session {session_id} authenticated successfully")
                    return True
                else:
                    if VERBOSE:
                        print(f"[Auth] Authentication failed - still on login page or got login error")
                    
        except Exception as e:
            if VERBOSE:
                print(f"[Auth] Failed to authenticate session {session_id}: {e}")
                
        return False

    def _maybe_refresh_auth(self, session, session_id):
        """Re-authenticate if TTL expired."""
        if session_id not in self.authenticated_sessions:
            return self._authenticate_session(session, session_id)
        if time.time() - self.last_auth_time.get(session_id, 0) >= AUTH_TTL_SECONDS:
            return self._authenticate_session(session, session_id, force=True)
        return True

    def generate_request_variations(self, count=NUM_REQUESTS):
        if not self.crawled:
            self.crawl_site(max_pages=300)

        # For realistic traffic, we don't force equal distribution but use natural patterns
        # Web traffic is typically: ~70% GET, ~25% POST, ~5% other methods
        realistic_distribution = {
            "GET": 0.70,
            "POST": 0.25,
            "PUT": 0.02,
            "DELETE": 0.01,
            "PATCH": 0.01,
            "HEAD": 0.005,
            "OPTIONS": 0.005
        }
        
        method_counts = {}
        total_assigned = 0
        for method, ratio in realistic_distribution.items():
            method_counts[method] = int(count * ratio)
            total_assigned += method_counts[method]
        
        # Distribute any remaining requests to GET (most common)
        method_counts["GET"] += count - total_assigned

        # DVWA-specific vulnerability modules with their typical parameters and realistic methods
        dvwa_modules = {
            "vulnerabilities/sqli/": {
                "methods": ["GET", "POST"],
                "values": lambda: {"id": str(random.randint(1, 5000)), "Submit": "Submit"}
            },
            "vulnerabilities/sqli_blind/": {
                "methods": ["GET", "POST"],
                "values": lambda: {"id": str(random.randint(1, 5000)), "Submit": "Submit"}
            },
            "vulnerabilities/xss_r/": {
                "methods": ["GET"],
                "values": lambda: {"name": benign_xss_like(rand_uid(8))}
            },
            "vulnerabilities/xss_s/": {
                "methods": ["GET", "POST"],
                "values": lambda: {
                    "txtName": benign_xss_like(rand_uid(6)),
                    "mtxMessage": faker.sentence(),
                    "btnSign": "Sign Guestbook"
                }
            },
            "vulnerabilities/xss_d/": {
                "methods": ["GET"],
                "values": lambda: {"default": random.choice(["English", "French", "Spanish", "German"])}
            },
            "vulnerabilities/exec/": {
                "methods": ["GET", "POST"],
                "values": lambda: {"ip": faker.ipv4(), "Submit": "Submit"}
            },
            "vulnerabilities/csrf/": {
                "methods": ["GET", "POST"],
                "values": lambda: {
                    "password_new": f"newpass_{rand_uid(6)}",
                    "password_conf": f"newpass_{rand_uid(6)}",
                    "Change": "Change"
                }
            },
            "vulnerabilities/fi/": {
                "methods": ["GET"],
                "values": lambda: {"page": random.choice(["include.php", "file1.php", "file2.php", "file3.php"])}
            },
            "vulnerabilities/upload/": {
                "methods": ["GET", "POST"],
                "values": lambda: {"Upload": "Upload"}
            },
            "vulnerabilities/captcha/": {
                "methods": ["GET", "POST"],
                "values": lambda: {
                    "step": "1",
                    "password_new": f"pass_{rand_uid(8)}",
                    "password_conf": f"pass_{rand_uid(8)}",
                    "passed_captcha": "true",
                    "Change": "Change"
                }
            },
            "vulnerabilities/weak_id/": {
                "methods": ["GET"],
                "values": lambda: {}
            },
            "vulnerabilities/brute/": {
                "methods": ["GET", "POST"],
                "values": lambda: {
                    "username": faker.user_name(),
                    "password": faker.password(),
                    "Login": "Login"
                }
            },
            "vulnerabilities/authbypass/": {
                "methods": ["GET", "POST"],
                "values": lambda: {
                    "username": faker.user_name(),
                    "password": faker.password(),
                    "Login": "Login"
                }
            },
            "vulnerabilities/bac/": {
                "methods": ["GET"],
                "values": lambda: {"user_id": str(random.randint(1, 100))}
            },
            "vulnerabilities/csp/": {
                "methods": ["GET"],
                "values": lambda: {"include": random.choice(["source", "jsonp"])}
            },
            "vulnerabilities/javascript/": {
                "methods": ["GET", "POST"],
                "values": lambda: {"token": rand_uid(32)}
            },
            "vulnerabilities/open_redirect/": {
                "methods": ["GET"],
                "values": lambda: {"redirect": faker.url()}
            },
            "vulnerabilities/api/": {
                "methods": ["GET", "POST", "PUT", "DELETE"],  # API endpoints can support REST methods
                "values": lambda: {}
            }
        }

        # Common DVWA pages with realistic methods and parameters
        common_pages = {
            "index.php": {
                "methods": ["GET"],
                "values": lambda: {}
            },
            # Intentionally exclude login/logout to avoid skewing the dataset
            "security.php": {
                "methods": ["GET", "POST"],
                "values": lambda: {
                    "security": random.choice(["low", "medium", "high", "impossible"]),
                    "seclev_submit": "Submit"
                }
            },
            "phpinfo.php": {
                "methods": ["GET"],
                "values": lambda: {}
            },
            
            "about.php": {
                "methods": ["GET"],
                "values": lambda: {}
            },
            "instructions.php": {
                "methods": ["GET"],
                "values": lambda: {}
            }
        }

        sent = 0
        used_signatures = set()
        pbar = trange(count, desc="requests") if VERBOSE else None
        
        # Track request distribution
        sent_by_method = {method: 0 for method in HTTP_METHODS}
        
        while sent < count:
            # Generate diverse URL and parameters first, then select appropriate method
            endpoint_info = None
            
            if random.random() < 0.7:  # 70% DVWA vulnerability modules
                module_path = random.choice(list(dvwa_modules.keys()))
                base_url = urljoin(self.base, module_path)
                url = generate_url_variations(base_url) if random.random() < 0.3 else base_url
                endpoint_info = dvwa_modules[module_path]
                base_params = endpoint_info["values"]()
            elif random.random() < 0.9:  # 20% common pages
                page = random.choice(list(common_pages.keys()))
                base_url = urljoin(self.base, page)
                url = generate_url_variations(base_url) if random.random() < 0.3 else base_url
                endpoint_info = common_pages[page]
                base_params = endpoint_info["values"]()
            else:  # 10% discovered endpoints (assume GET only for discovered pages)
                if self.all_endpoints:
                    base_url = random.choice(list(self.all_endpoints))
                    url = generate_url_variations(base_url) if random.random() < 0.3 else base_url
                    endpoint_info = {"methods": ["GET"]}
                    base_params = generate_diverse_params()
                else:
                    base_url = urljoin(self.base, "index.php")
                    url = generate_url_variations(base_url) if random.random() < 0.3 else base_url
                    endpoint_info = {"methods": ["GET"]}
                    base_params = {}
                    
            # Select appropriate method based on endpoint capabilities and remaining quota
            endpoint_methods = endpoint_info.get("methods", ["GET"])
            available_methods = [m for m in endpoint_methods if sent_by_method[m] < method_counts[m]]
            
            if not available_methods:
                # If no methods available for this endpoint, try any remaining method with quota
                available_methods = [m for m in HTTP_METHODS if sent_by_method[m] < method_counts[m]]
                if not available_methods:
                    break
            
            method = random.choice(available_methods)

            # Add diverse parameters and uniqueness
            params = dict(base_params)
            # Only add extra diverse params occasionally to keep traffic realistic
            if random.random() < 0.3:
                params.update(generate_diverse_params())
            
            # Select realistic content type based on method and endpoint
            if method in ["GET", "HEAD", "DELETE", "OPTIONS"]:
                content_type = "application/x-www-form-urlencoded"  # Default for query params
            elif method == "POST":
                if "upload" in url.lower():
                    content_type = "multipart/form-data"
                elif "api" in url.lower() and random.random() < 0.4:
                    content_type = "application/json"
                else:
                    content_type = "application/x-www-form-urlencoded"
            elif method in ["PUT", "PATCH"]:
                if "api" in url.lower():
                    content_type = random.choice(["application/json", "application/xml"])
                else:
                    content_type = "application/x-www-form-urlencoded"
            else:
                content_type = "application/x-www-form-urlencoded"
                
            headers = gen_headers()
            if method in ["POST", "PUT", "PATCH"]:
                headers["Content-Type"] = content_type
            
            # Generate request body based on method and content type
            request_data = None
            files = None
            
            if method in ["POST", "PUT", "PATCH"]:
                if content_type == "application/json" and "api" in url.lower():
                    # Only use JSON for API endpoints
                    request_data = json.dumps(generate_json_payload())
                    params = {}  # JSON data goes in body
                elif content_type == "application/xml" and "api" in url.lower():
                    # Only use XML for API endpoints
                    request_data = generate_xml_payload()
                    params = {}
                elif content_type == "multipart/form-data":
                    # Handle file uploads with diverse realistic files
                    if "upload" in url.lower():
                        file_types = [
                            ("txt", "text/plain"),
                            ("csv", "text/csv"), 
                            ("json", "application/json"),
                            ("xml", "application/xml"),
                            ("jpg", "image/jpeg"),
                            ("png", "image/png"),
                            ("pdf", "application/pdf"),
                            ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                        ]
                        
                        file_ext, mime_type = random.choice(file_types)
                        filename = f"{faker.word()}_{rand_uid(6)}.{file_ext}"
                        
                        # Generate realistic content based on file type
                        if file_ext in ["txt", "csv", "json", "xml"]:
                            file_content = generate_realistic_file_content(file_ext)
                        elif file_ext == "jpg":
                            # Minimal JPEG header + random data
                            file_content = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00' + rand_uid(100).encode()
                        elif file_ext == "png":
                            # Minimal PNG header + random data  
                            file_content = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde' + rand_uid(50).encode()
                        elif file_ext == "pdf":
                            # Minimal PDF structure
                            file_content = f"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
({faker.sentence()}) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
0000000136 00000 n 
0000000189 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
290
%%EOF"""
                        elif file_ext == "docx":
                            # Minimal ZIP structure for DOCX
                            file_content = b'PK\x03\x04\x14\x00\x00\x00\x08\x00' + rand_uid(200).encode()
                        else:
                            file_content = f"Generated content for {file_ext} file - {faker.text()}"
                        
                        # Convert string content to bytes if needed
                        if isinstance(file_content, str):
                            file_content = file_content.encode('utf-8')
                            
                        files = {"uploaded": (filename, file_content, mime_type)}
                        del headers["Content-Type"]  # Let requests set it for multipart
                        
                        if VERBOSE:
                            print(f"[Upload] Uploading {filename} ({mime_type})")
                    request_data = params
                else:  # form-urlencoded (most common for web forms)
                    request_data = params
            
            # Create comprehensive signature for uniqueness
            sig_components = [
                method,
                url,
                str(sorted(params.items()) if params else ""),
                str(request_data) if request_data else "",
                content_type,
                str(sorted([(k, v) for k, v in headers.items() if k not in ["User-Agent", "X-Request-ID", "X-Correlation-ID"]]))
            ]
            sig = hashlib.md5("|".join(sig_components).encode()).hexdigest()
            
            if sig in used_signatures:
                continue
            used_signatures.add(sig)

            session_id = sent % len(self.sessions)
            session = self._session_rotate(sent)
            
            # Authenticate for protected areas (with TTL-based refresh)
            if "vulnerabilities/" in url or "security.php" in url or "index.php" in url:
                if not self._maybe_refresh_auth(session, session_id):
                    continue
            
            # Optionally vary DVWA security level via cookie (never touch PHPSESSID)
            if random.random() < 0.15:
                session.cookies.set("security", random.choice(["low", "medium", "high"]), domain="localhost")

            try:
                request_size = 0
                response_size = 0

                # If posting to DVWA form endpoints, try to add user_token CSRF
                if method == "POST" and isinstance(request_data, dict) and any(key in url.lower() for key in ["/csrf", "/captcha", "/brute", "/login.php", "/security.php", "/upload", "/xss_s", "/sqli", "/exec"]):
                    token = self._get_csrf_token(session, url)
                    if token:
                        request_data = dict(request_data)
                        request_data.setdefault("user_token", token)

                # Send request with re-auth retry if redirected to login
                resp, request_size = self._send_with_reauth(
                    session=session,
                    session_id=session_id,
                    method=method,
                    url=url,
                    params=params,
                    headers=headers,
                    request_data=request_data,
                    files=files,
                    content_type=content_type
                )

                status = getattr(resp, "status_code", "ERR")
                response_size = len(resp.content) if resp and hasattr(resp, 'content') else 0
                headers_hash = hashlib.md5(str(sorted(headers.items())).encode()).hexdigest()[:8]
                
                # Enhanced logging
                log_data = {
                    "params": params if method in ["GET", "HEAD", "OPTIONS", "DELETE"] else request_data,
                    "files": bool(files)
                }
                
                self._log_csv(
                    session_id, 
                    method, 
                    resp.url if resp else url, 
                    str(log_data), 
                    status, 
                    sig[:8],  # Use first 8 chars of signature as unique token
                    content_type,
                    request_size,
                    response_size,
                    headers_hash
                )
                
                sent += 1
                sent_by_method[method] += 1
                
                if pbar:
                    pbar.update(1)
                    pbar.set_description(f"requests ({method}: {sent_by_method[method]}/{method_counts[method]})")
                
                # Small delay
                time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
                
            except requests.RequestException as e:
                time.sleep(0.05)
                continue

        if pbar:
            pbar.close()
        
        # Print distribution summary
        if VERBOSE:
            print(f"[Done] Sent {sent} requests with distribution:")
            for method in HTTP_METHODS:
                print(f"  {method}: {sent_by_method[method]}/{method_counts[method]}")
        else:
            print(f"[Done] Sent {sent} requests across {len(HTTP_METHODS)} HTTP methods")

    def _log_csv(self, session_id, method, url, pdata, status, token, content_type="", request_size=0, response_size=0, headers_hash=""):
        with open(self.csv_file, "a", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([int(time.time()), session_id, method, url, str(pdata), status, token, content_type, request_size, response_size, headers_hash])

    # ---------- Internal helpers for robust auth ----------
    def _do_request(self, session, method, url, params, headers, request_data, files, content_type):
        """Send a single HTTP request and return (response, request_size)."""
        request_size = 0
        if method == "GET":
            resp = session.get(url, params=params, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
        elif method == "POST":
            if files:
                resp = session.post(url, data=request_data, files=files, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            elif isinstance(request_data, str):
                resp = session.post(url, data=request_data, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
                request_size = len(request_data.encode('utf-8'))
            else:
                resp = session.post(url, data=request_data, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
        elif method == "PUT":
            if isinstance(request_data, str):
                resp = session.put(url, data=request_data, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
                request_size = len(request_data.encode('utf-8'))
            else:
                resp = session.put(
                    url,
                    json=request_data if content_type == "application/json" else None,
                    data=request_data if content_type != "application/json" else None,
                    headers=headers,
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                )
        elif method == "DELETE":
            resp = session.delete(url, params=params, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
        elif method == "PATCH":
            if isinstance(request_data, str):
                resp = session.patch(url, data=request_data, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
                request_size = len(request_data.encode('utf-8'))
            else:
                resp = session.patch(
                    url,
                    json=request_data if content_type == "application/json" else None,
                    data=request_data if content_type != "application/json" else None,
                    headers=headers,
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                )
        elif method == "HEAD":
            resp = session.head(url, params=params, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
        elif method == "OPTIONS":
            resp = session.options(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
        else:
            resp = None
        return resp, request_size

    def _response_indicates_login(self, resp):
        """Heuristic: did we get bounced to the login page?"""
        if not resp:
            return False
        url_lower = (getattr(resp, "url", "") or "").lower()
        if "login.php" in url_lower:
            return True
        text = ""
        try:
            text = resp.text or ""
        except Exception:
            text = ""
        markers = [
            "Login :: Damn Vulnerable Web Application",
            "name=\"username\"",
            ">Login<",
        ]
        return any(m in text for m in markers)

    def _send_with_reauth(self, session, session_id, method, url, params, headers, request_data, files, content_type):
        """Send request once; if redirected to login, re-authenticate and retry once."""
        resp, request_size = self._do_request(session, method, url, params, headers, request_data, files, content_type)
        if self._response_indicates_login(resp) and ("vulnerabilities/" in url or "security.php" in url or "index.php" in url):
            # attempt re-auth once
            if self._authenticate_session(session, session_id):
                resp, request_size = self._do_request(session, method, url, params, headers, request_data, files, content_type)
        return resp, request_size

# ---------- Main ----------
if __name__ == "__main__":
    print("[*] DVWA benign traffic generator - target:", BASE_URL)
    g = DVWAGenerator()
    g.generate_request_variations(count=NUM_REQUESTS)
    print("[*] Completed. Saved requests to", LOG_CSV)
