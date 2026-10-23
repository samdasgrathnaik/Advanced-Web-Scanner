import argparse
import sys
import requests
import urllib3
import json
import csv
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
import concurrent.futures
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against MitM protocol downgrade attacks.",
    "Content-Security-Policy": "Prevents XSS and data injection attacks.",
    "X-Frame-Options": "Protects against Clickjacking attacks.",
    "X-Content-Type-Options": "Prevents MIME-sniffing vulnerabilities.",
    "Referrer-Policy": "Controls referrer information exposure.",
    "Permissions-Policy": "Controls browser features and APIs."
}

SENSITIVE_FILES = [
    "/.env",
    "/.git/config",
    "/robots.txt",
    "/backup.zip",
    "/phpinfo.php"
]

def format_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

def check_ssl(hostname):
    """Checks SSL certificate validity and expiration."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.utcnow()).days
                return {"valid": True, "days_remaining": days_left, "issuer": dict(x[0] for x in cert['issuer'])['organizationName']}
    except Exception as e:
        return {"valid": False, "error": str(e)}

def check_cookies(cookies):
    """Audits cookies for Secure, HttpOnly, and SameSite flags."""
    cookie_issues = []
    for cookie in cookies:
        issues = []
        if not cookie.secure: issues.append("Missing Secure")
        if not cookie.has_nonstandard_attr('HttpOnly'): issues.append("Missing HttpOnly")
        if 'SameSite' not in [attr.lower() for attr in cookie._rest.keys()]: issues.append("Missing SameSite")
        
        if issues:
            cookie_issues.append({"name": cookie.name, "flaws": issues})
    return cookie_issues

def check_sensitive_files(base_url):
    """Probes for common exposed sensitive files."""
    exposed_files = []
    for file in SENSITIVE_FILES:
        target_url = base_url.rstrip("/") + file
        try:
            response = requests.get(target_url, timeout=5, verify=False)
            if response.status_code == 200 and "<html" not in response.text[:100].lower():
                exposed_files.append(target_url)
        except requests.RequestException:
            pass
    return exposed_files

def check_security_headers(headers):
    missing_hdrs = []
    exposed_info = []
    
    for header, desc in SECURITY_HEADERS.items():
        if header not in headers:
            missing_hdrs.append(header)
            
    for info_header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
        if info_header in headers:
            exposed_info.append({info_header: headers[info_header]})
            
    return missing_hdrs, exposed_info

def check_cors(url):
    evil_origin = "https://evil-attacker.com"
    try:
        response = requests.get(url, headers={"Origin": evil_origin}, timeout=5, verify=False)
        acao = response.headers.get("Access-Control-Allow-Origin")
        acac = response.headers.get("Access-Control-Allow-Credentials")

        if acao == evil_origin:
            return {"vulnerable": True, "type": "Arbitrary Origin Reflected", "credentials": acac == "true"}
        elif response.headers.get("Access-Control-Allow-Origin") == "null":
            return {"vulnerable": True, "type": "Null Origin Allowed", "credentials": False}
        elif acao == "*":
            return {"vulnerable": False, "type": "Wildcard Allowed (Public API)"}
    except requests.RequestException:
        pass
    return {"vulnerable": False, "type": "Secure or Not Configured"}

def scan_target(url):
    target_url = format_url(url)
    hostname = urlparse(target_url).hostname
    
    print(f"\n{Fore.CYAN}{'='*65}")
    print(f"{Fore.CYAN}[*] Scanning: {Style.BRIGHT}{target_url}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
    
    report = {
        "url": target_url,
        "status": "Failed",
        "ssl": {},
        "missing_headers": [],
        "exposed_info": [],
        "cors": {},
        "insecure_cookies": [],
        "exposed_files": []
    }

    try:
        session = requests.Session()
        response = session.get(target_url, timeout=10, verify=False)
        report["status"] = response.status_code
        print(f"  {Fore.BLUE}[i] HTTP Status Code: {response.status_code}")
        
        # 1. SSL Check
        report["ssl"] = check_ssl(hostname)
        if report["ssl"].get("valid"):
            print(f"  {Fore.GREEN}[+] SSL Certificate: Valid ({report['ssl']['days_remaining']} days left)")
        else:
            print(f"  {Fore.RED}[-] SSL Certificate: Invalid or missing")

        # 2. Headers Check
        missing_hdrs, exposed_info = check_security_headers(response.headers)
        report["missing_headers"] = missing_hdrs
        report["exposed_info"] = exposed_info
        
        if missing_hdrs:
            print(f"  {Fore.YELLOW}[-] Missing Security Headers ({len(missing_hdrs)}/{len(SECURITY_HEADERS)}):")
            for hdr in missing_hdrs:
                print(f"      -> {hdr}")
        else:
            print(f"  {Fore.GREEN}[+] All Security Headers Present!")

        if exposed_info:
            for info in exposed_info:
                for k, v in info.items():
                    print(f"  {Fore.YELLOW}[!] Info Disclosure: {k} header exposed ({v})")
        
        # 3. Cookie Check
        report["insecure_cookies"] = check_cookies(session.cookies)
        if report["insecure_cookies"]:
            print(f"  {Fore.RED}[!] Insecure Cookies Detected: {len(report['insecure_cookies'])}")
            for c in report["insecure_cookies"]:
                print(f"      -> Cookie '{c['name']}': {', '.join(c['flaws'])}")
        else:
            print(f"  {Fore.GREEN}[+] Cookies: Secure or None detected.")

        # 4. CORS Check
        report["cors"] = check_cors(target_url)
        if report["cors"]["vulnerable"]:
            print(f"  {Fore.RED}[!] CORS Misconfiguration: {report['cors']['type']}")
        else:
            print(f"  {Fore.GREEN}[+] CORS Policy: {report['cors']['type']}")

        # 5. Sensitive File Discovery
        report["exposed_files"] = check_sensitive_files(target_url)
        if report["exposed_files"]:
            print(f"  {Fore.RED}[!] Exposed Files Found: {len(report['exposed_files'])}")
            for f in report["exposed_files"]:
                print(f"      -> {f}")
        else:
            print(f"  {Fore.GREEN}[+] Sensitive Files: None exposed.")
            
    except requests.exceptions.RequestException as e:
        print(f"  {Fore.RED}[!] Connection Failed: {e}")
        
    return report

def export_results(results, format, filename):
    if format == "json":
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\n{Fore.GREEN}[+] Results exported to {filename}")
        
    elif format == "csv":
        keys = ["url", "status", "ssl_valid", "missing_headers_count", "cors_vulnerable", "exposed_files_count"]
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "url": r["url"],
                    "status": r["status"],
                    "ssl_valid": r["ssl"].get("valid", False),
                    "missing_headers_count": len(r["missing_headers"]),
                    "cors_vulnerable": r.get("cors", {}).get("vulnerable", False),
                    "exposed_files_count": len(r["exposed_files"])
                })
        print(f"\n{Fore.GREEN}[+] Results exported to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Security & Exposure Scanner")
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-f", "--file", help="File containing list of URLs")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("--json", help="Export results to JSON file")
    parser.add_argument("--csv", help="Export results to CSV file")
    
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        try:
            with open(args.file, "r") as file:
                targets.extend([line.strip() for line in file if line.strip()])
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {args.file}")
            sys.exit(1)

    print(f"\n{Style.BRIGHT}[*] Starting audit of {len(targets)} target(s) with {args.threads} threads...")
    
    all_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(scan_target, url): url for url in targets}
        for future in concurrent.futures.as_completed(future_to_url):
            all_results.append(future.result())

    if args.json:
        export_results(all_results, "json", args.json)
    if args.csv:
        export_results(all_results, "csv", args.csv)

if __name__ == "__main__":
    main()
