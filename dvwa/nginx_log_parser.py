#!/usr/bin/env python3
"""
nginx_log_parser.py
Parse nginx access logs and convert to CSV format for training data.

This script reads nginx access logs and converts them to a structured CSV format
with columns: _id, body_bytes_sent, ip, request.method, request.path, 
request.protocol, request_body, status, timestamp

Usage:
    python nginx_log_parser.py

Configuration:
    - Set NGINX_LOG_PATH to your nginx access.log location
    - Set OUTPUT_CSV to desired output filename
    - Adjust LOG_FORMAT if your nginx uses different format
"""

import re
import csv
import os
import sys
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
import hashlib

# ---------- CONFIG ----------
NGINX_LOG_PATH = r"C:\nginx\logs\dvwa_access.log"  # Update this path
OUTPUT_CSV = "nginx_access_parsed.csv"
VERBOSE = True

# Common nginx log formats
LOG_FORMATS = {
    'combined': r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<body_bytes_sent>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"',
    'common': r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<body_bytes_sent>\d+)',
    'dvwa_custom': r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<body_bytes_sent>\d+) "(?P<referer>[^\"]*)" "(?P<user_agent>[^\"]*)"',
    # DVWA variant with single dash and trailing request_body field
    # Example:
    # 127.0.0.1 - [10/Oct/2025:17:25:27 +0530] "GET /DVWA/... HTTP/1.1" 302 154 request_body: "-"
    'dvwa_with_body': r'(?P<ip>\S+) - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d{3}) (?P<body_bytes_sent>\d+)(?: request_body: "(?P<request_body>[^"]*)")?'
}

def detect_log_format(log_line):
    """Detect which log format is being used"""
    for format_name, pattern in LOG_FORMATS.items():
        if re.match(pattern, log_line):
            return format_name, pattern
    return None, None

def parse_timestamp(timestamp_str):
    """Convert nginx timestamp to ISO format"""
    try:
        # nginx format: 10/Oct/2025:14:30:45 +0000
        dt = datetime.strptime(timestamp_str.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
        return dt.isoformat()
    except ValueError:
        return timestamp_str

def extract_request_body(method, path, referer="", user_agent=""):
    """Extract request body/parameters from the request"""
    request_body = ""
    
    if method.upper() == "POST":
        # For POST requests, we can't get the actual body from access logs
        # but we can extract query parameters from the path
        if '?' in path:
            _, query_string = path.split('?', 1)
            request_body = unquote(query_string)
    elif method.upper() == "GET":
        # For GET requests, extract query parameters
        if '?' in path:
            _, query_string = path.split('?', 1)
            request_body = unquote(query_string)
    
    return request_body

def clean_path(path):
    """Clean and normalize the request path"""
    if '?' in path:
        path = path.split('?')[0]  # Remove query parameters from path
    return unquote(path)  # URL decode

def generate_unique_id(ip, timestamp, method, path):
    """Generate a unique ID for each request"""
    unique_string = f"{ip}_{timestamp}_{method}_{path}"
    return hashlib.md5(unique_string.encode()).hexdigest()[:12]

def parse_log_file(log_path, output_csv):
    """Parse the nginx log file and convert to CSV"""
    
    if not os.path.exists(log_path):
        print(f"Error: Log file not found at {log_path}")
        print("Please update NGINX_LOG_PATH in the script to point to your nginx access.log")
        return False
    
    # Detect log format from first line
    log_format = None
    pattern = None
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        first_line = f.readline().strip()
        if first_line:
            log_format, pattern = detect_log_format(first_line)
            if not log_format:
                print(f"Warning: Could not detect log format. Trying 'combined' format.")
                log_format = 'combined'
                pattern = LOG_FORMATS['combined']
    
    if not pattern:
        print("Error: Could not determine log format")
        return False
    
    print(f"Detected log format: {log_format}")
    
    # Prepare CSV output
    csv_headers = ['_id', 'body_bytes_sent', 'ip', 'request.method', 'request.path', 
                   'request.protocol', 'request_body', 'status', 'timestamp']
    
    processed_count = 0
    error_count = 0
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as infile, \
         open(output_csv, 'w', newline='', encoding='utf-8') as outfile:
        
        writer = csv.writer(outfile)
        writer.writerow(csv_headers)
        
        for line_num, line in enumerate(infile, 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                match = re.match(pattern, line)
                if not match:
                    error_count += 1
                    if VERBOSE and error_count <= 5:
                        print(f"Warning: Could not parse line {line_num}: {line[:100]}...")
                    continue
                
                data = match.groupdict()
                
                # Extract required fields
                ip = data.get('ip', '').strip()
                method = data.get('method', '').strip()
                path = data.get('path', '').strip()
                protocol = data.get('protocol', '').strip()
                status = data.get('status', '').strip()
                body_bytes_sent = data.get('body_bytes_sent', '0').strip()
                timestamp_raw = data.get('timestamp', '').strip()
                referer = data.get('referer', '').strip()
                user_agent = data.get('user_agent', '').strip()
                
                # Process the data
                timestamp = parse_timestamp(timestamp_raw)
                clean_request_path = clean_path(path)
                # Prefer request_body captured from log line if present and not '-'
                request_body_captured = data.get('request_body')
                if request_body_captured and request_body_captured != '-':
                    request_body = unquote(request_body_captured)
                else:
                    request_body = extract_request_body(method, path, referer, user_agent)
                unique_id = generate_unique_id(ip, timestamp, method, clean_request_path)
                
                # Write to CSV
                writer.writerow([
                    unique_id,
                    body_bytes_sent,
                    ip,
                    method,
                    clean_request_path,
                    protocol,
                    request_body,
                    status,
                    timestamp
                ])
                
                processed_count += 1
                
                if VERBOSE and processed_count % 1000 == 0:
                    print(f"Processed {processed_count} lines...")
                    
            except Exception as e:
                error_count += 1
                if VERBOSE and error_count <= 5:
                    print(f"Error processing line {line_num}: {e}")
                continue
    
    print(f"\n=== Processing Complete ===")
    print(f"Total lines processed: {processed_count}")
    print(f"Errors encountered: {error_count}")
    print(f"Output saved to: {output_csv}")
    
    return True

def preview_log_file(log_path, lines=5):
    """Preview the first few lines of the log file"""
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        return
    
    print(f"\n=== Preview of {log_path} ===")
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= lines:
                break
            print(f"Line {i+1}: {line.strip()}")
    print("=" * 50)

def main():
    print("=== Nginx Access Log Parser ===")
    print(f"Log file: {NGINX_LOG_PATH}")
    print(f"Output CSV: {OUTPUT_CSV}")
    
    # Check if log file exists
    if not os.path.exists(NGINX_LOG_PATH):
        print(f"\nError: Nginx log file not found at: {NGINX_LOG_PATH}")
        print("\nCommon nginx log locations:")
        print("- Windows (nginx): C:\\nginx\\logs\\access.log")
        print("- Windows (XAMPP): C:\\xampp\\apache\\logs\\access.log") 
        print("- Linux: /var/log/nginx/access.log")
        print("- macOS: /usr/local/var/log/nginx/access.log")
        print("\nPlease update the NGINX_LOG_PATH variable in this script.")
        return
    
    # Preview log file
    if VERBOSE:
        preview_log_file(NGINX_LOG_PATH)
    
    # Parse the log file
    success = parse_log_file(NGINX_LOG_PATH, OUTPUT_CSV)
    
    if success:
        print(f"\n✅ Successfully converted nginx log to CSV format!")
        print(f"📄 Output file: {OUTPUT_CSV}")
        
        # Show preview of output
        if os.path.exists(OUTPUT_CSV):
            print(f"\n=== Preview of {OUTPUT_CSV} ===")
            with open(OUTPUT_CSV, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f):
                    if i >= 3:  # Show header + first 2 data rows
                        break
                    print(line.strip())
            print("...")
    else:
        print("❌ Failed to process log file")

if __name__ == "__main__":
    main()