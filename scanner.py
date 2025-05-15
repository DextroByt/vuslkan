import requests
from bs4 import BeautifulSoup
from Wappalyzer import Wappalyzer, WebPage
from jinja2 import Environment, FileSystemLoader
import warnings
from urllib.parse import urlparse
import os
import json
import time
import random
import sys

# Import dotenv to load environment variables from a .env file
from dotenv import load_dotenv

# Import your existing vulnerability checking logic
# Make sure check_vulnerabilities.py is in the same directory
from check_vulnerabilities import check_all_vulnerabilities

# Import Google AI
import google.generativeai as genai

warnings.filterwarnings("ignore", category=UserWarning, message="Caught 'unbalanced parenthesis at position 119'")
warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- Configuration ---
# Load environment variables from a .env file in the current directory
load_dotenv()

try:
    # Now os.environ will include variables from the .env file
    GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")

    if not GOOGLE_API_KEY:
        print("[!] Critical: GOOGLE_API_KEY not found in environment or .env file. AI features will be disabled.")
        # exit() # Or handle this more gracefully
    else:
        genai.configure(api_key=GOOGLE_API_KEY)
        # print("[*] Google AI configured successfully.")

except Exception as e:
    print(f"[!] Error configuring Google AI: {e}. AI features may be affected.")
    GOOGLE_API_KEY = None # Ensure it's None if configuration fails

# --- Constants ---
AI_MODEL_NAME = "gemini-1.5-flash-latest" # Or another suitable model
AI_REQUEST_DELAY = 2 # Seconds to wait between AI API calls to respect rate limits (adjust as needed)
MAX_AI_RETRIES = 2

class VulnerabilityScanner:
    def __init__(self, url):
        self.url = self._normalize_url(url)
        self.report_data = {
            'url': self.url,
            'scan_timestamp': time.strftime("%Y-%m-%d %H:%M:%S %Z"),
            'technologies': [],
            'forms': [],
            'headers': {},
            'cookies': {},
            'initial_vulnerabilities': [], # Raw findings from check_all_vulnerabilities
            'detailed_vulnerabilities': [] # Enriched findings with AI analysis
        }
        self.ai_model = None
        # Check GOOGLE_API_KEY again here in case of late initialization issues
        if GOOGLE_API_KEY:
            try:
                self.ai_model = genai.GenerativeModel(AI_MODEL_NAME)
                print(f"[*] Google AI Model '{AI_MODEL_NAME}' initialized.")
            except Exception as e:
                print(f"[!] Failed to initialize Google AI Model: {e}")
                self.ai_model = None

        print(f"[*] Scanner initialized for URL: {self.url}")

    def _normalize_url(self, url):
        parsed = urlparse(url)
        if not parsed.scheme:
            print(f"[*] URL '{url}' is missing a scheme. Defaulting to 'http://'.")
            return 'http://' + url
        return url

    def _fetch_response(self, method_name_for_log):
        try:
            response = requests.get(self.url, timeout=15, headers={'User-Agent': 'AdvancedVulnerabilityScanner/1.0'})
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(f"[!] {method_name_for_log} Error (RequestException): {e}")
        except Exception as e:
            print(f"[!] {method_name_for_log} Error (General): {e}")
        return None

    def detect_technologies(self):
        print("[*] Detecting technologies...")
        try:
            # Wappalyzer uses requests internally, might need adjustments if behind proxies etc.
            # Ensure the URL is reachable by the scanner
            webpage = WebPage.new_from_url(self.url)
            wappalyzer = Wappalyzer.latest()
            technologies = wappalyzer.analyze(webpage)
            # Ensure technologies are in a consistent format if needed by the template
            self.report_data['technologies'] = list(technologies) # technologies is a set, convert to list
            print(f"[*] Technologies detected: {self.report_data['technologies']}")
        except Exception as e:
            print(f"[!] Technology Detection Error: {e}")
            self.report_data['technologies'] = [{"name": "Error detecting technologies.", "version": None, "categories": []}] # Use a structured error format


    def analyze_forms(self):
        print("[*] Analyzing forms...")
        response = self._fetch_response("Form Analysis")
        if not response: return
        soup = BeautifulSoup(response.text, 'html.parser')
        for form_count, form in enumerate(soup.find_all('form')):
            self.report_data['forms'].append({
                'id': f"form_{form_count+1}",
                'action': form.get('action', 'N/A'),
                'method': form.get('method', 'GET').upper(),
                'inputs': [{'name': i.get('name', f'unnamed_input_{idx}'), 'type': i.get('type', 'text')} for idx, i in enumerate(form.find_all('input'))]
            })
        print(f"[*] Forms found: {len(self.report_data['forms'])}")


    def analyze_headers_and_cookies(self):
        print("[*] Analyzing headers and cookies...")
        response = self._fetch_response("Header/Cookie Analysis")
        if not response: return
        self.report_data['headers'] = dict(response.headers)
        self.report_data['cookies'] = requests.utils.dict_from_cookiejar(response.cookies)
        print("[*] Headers and cookies analyzed.")

    def check_basic_vulnerabilities(self):
        print("[*] Checking for basic vulnerabilities (pre-AI)...")
        try:
            # Assuming check_all_vulnerabilities returns a list of strings or dicts
            # Make sure check_all_vulnerabilities handles the URL correctly
            vulnerabilities_found = check_all_vulnerabilities(self.url)
            if vulnerabilities_found:
                # Ensure findings are strings or easily representable
                self.report_data['initial_vulnerabilities'] = [str(v) for v in vulnerabilities_found]
                print(f"[+] {len(self.report_data['initial_vulnerabilities'])} potential vulnerabilities identified by initial scan.")
            else:
                print("[-] No vulnerabilities reported by initial scan (check_all_vulnerabilities).")
                self.report_data['initial_vulnerabilities'] = ["No specific vulnerabilities found by the initial basic checks."]
        except Exception as e:
            print(f"[!] Vulnerability Check Error during call to check_all_vulnerabilities: {e}")
            self.report_data['initial_vulnerabilities'].append(f"Error during initial vulnerability scanning: {e}")


    def _get_ai_analysis(self, finding_data, technologies):
        """
        Queries the AI model for detailed analysis of a structured finding.
        """
        if not self.ai_model:
            return {"error": "AI model not available."}

        # Validate finding_data structure (basic check)
        if not isinstance(finding_data, dict):
             print(f"      [!] Error: _get_ai_analysis received non-dict finding_data: {finding_data}")
             return {"error": "Invalid finding data format."}

        # Convert technologies list of dicts/strings into a readable string
        technologies_str = ", ".join([tech.get('name', str(tech)) if isinstance(tech, dict) else str(tech) for tech in technologies]) if technologies else "None detected"

        # --- Construct the Prompt based on Finding Type ---
        finding_type = finding_data.get('type', 'unknown')
        original_output = finding_data.get('scanner_output', str(finding_data)) # Fallback to string representation
        url_context = finding_data.get('url', self.url) # Use finding-specific URL if available, else scan target

        prompt_parts = [
            "Analyze the following potential web security vulnerability detected by a scanner:",
            f"Scanner Finding Context:",
            f"  - Type (Scanner's categorization): {finding_type}",
            f"  - URL: {url_context}",
            f"  - Original Scanner Output: \"{original_output}\"",
        ]

        # Add details specific to the finding type if available
        if finding_type == 'sqli':
             prompt_parts.append(f"  - Method: {finding_data.get('method', 'N/A')}")
             if finding_data.get('parameter'):
                 prompt_parts.append(f"  - Parameter Tested: {finding_data['parameter']}")
             if finding_data.get('payload_used') is not None: # Check for None explicitly
                 prompt_parts.append(f"  - Payload Used: \"{finding_data['payload_used']}\"")
             prompt_parts.append("\nBased on the original output and context, determine if this likely indicates a SQL Injection vulnerability.")
             prompt_parts.append("If it is SQL Injection, provide specific details related to SQLi.")

        elif finding_type == 'xss':
             prompt_parts.append(f"  - Method: {finding_data.get('method', 'N/A')}")
             if finding_data.get('parameter'):
                 prompt_parts.append(f"  - Parameter Tested: {finding_data['parameter']}")
             if finding_data.get('payload_used') is not None:
                 prompt_parts.append(f"  - Payload Used: \"{finding_data['payload_used']}\"")
             prompt_parts.append("\nBased on the original output and context, determine if this likely indicates a Cross-Site Scripting (XSS) vulnerability.")
             prompt_parts.append("If it is XSS, provide specific details related to XSS, including the type (reflected, stored, DOM) if possible.")

        # Add context common to all findings
        prompt_parts.append(f"\nDetected Web Technologies on Target: {technologies_str}")

        # Add instructions for the desired JSON output format
        prompt_parts.append("""
Provide your analysis in a structured JSON format with the following keys:
- "vulnerability_name": A concise name for this vulnerability (must be a string). E.g., "Potential SQL Injection", "Reflected XSS".
- "detailed_description": A detailed explanation (must be a single string paragraph). Explain *why* the finding indicates the vulnerability type. For SQLi/XSS, mention the parameter and trigger.
- "potential_cves": A list of relevant CVE IDs (strings). Provide an empty list [] if none.
- "exploitation_summary": A brief summary of how this type of vulnerability could be exploited (must be a single string paragraph). For SQLi/XSS, suggest *types* of follow-up payloads (e.g., boolean-based, error-based, time-based for SQLi; basic script tags, event handlers for XSS). **Do not provide actual working exploit code or full scripts.**
- "mitigation_advice": Specific, actionable steps to mitigate *this type* of vulnerability (must be a single string paragraph). E.g., "Implement parameterized queries or prepared statements to prevent SQL Injection."
- "severity_assessment": Qualitative severity (e.g., "High", "Medium", "Low", "Informational", must be a string).

Ensure the *entire response* is a single, valid JSON object.
""")

        prompt = "\n".join(prompt_parts)

        # print("\n--- AI PROMPT ---") # Uncomment for debugging prompts
        # print(prompt)
        # print("-----------------")


        retries = 0
        while retries <= MAX_AI_RETRIES:
            try:
                # Use the scanner_output for logging preview, but use the full finding_data for the prompt
                log_preview = str(finding_data.get('scanner_output', str(finding_data)))[:80]
                print(f"      [*] Querying AI for finding type '{finding_type}': \"{log_preview}...\" (Attempt {retries + 1})")

                # Ensure self.ai_model is indeed the generative AI model object
                # Assuming self.ai_model has a generate_content method
                response = self.ai_model.generate_content(prompt)

                if not hasattr(response, 'text') or not response.text:
                     # Check for potential blocked reasons in the response object if available
                    blocked_reason = getattr(response, 'prompt_feedback', {}).get('block_reason', 'N/A')
                    error_msg = f"AI response text is empty or blocked. Reason: {blocked_reason}"
                    raise ValueError(error_msg)

                json_text_match = response.text.strip()
                # Clean potential markdown JSON block delimiters
                if json_text_match.startswith("```json"):
                    json_text_match = json_text_match[7:]
                if json_text_match.endswith("```"):
                    json_text_match = json_text_match[:-3]

                # Attempt to parse JSON
                ai_data = json.loads(json_text_match.strip())

                # --- Data Cleaning and Validation: Ensure expected fields are correct types ---
                # Define fields expected to be strings
                string_fields = ["vulnerability_name", "detailed_description", "exploitation_summary", "mitigation_advice", "severity_assessment"]
                for field in string_fields:
                    value = ai_data.get(field)
                    if isinstance(value, list):
                         print(f"      [!] Warning: AI returned list for expected string field '{field}'. Joining elements.")
                         ai_data[field] = "\n".join(map(str, value)) # Join with newline
                    elif not isinstance(value, str):
                        print(f"      [!] Warning: AI returned non-string type for '{field}' ({type(value)}). Converting to string.")
                        ai_data[field] = str(value) if value is not None else ""

                # Ensure potential_cves is always a list of strings
                cves = ai_data.get("potential_cves")
                if not isinstance(cves, list):
                     print(f"      [!] Warning: AI returned non-list type for 'potential_cves' ({type(cves)}). Defaulting to empty list.")
                     ai_data["potential_cves"] = []
                else:
                    # Ensure elements within the list are strings
                    ai_data["potential_cves"] = [str(cve) for cve in cves if cve is not None]


                # Basic validation (check for presence of required keys)
                required_keys = ["vulnerability_name", "detailed_description", "potential_cves", "exploitation_summary", "mitigation_advice", "severity_assessment"]
                if not all(key in ai_data for key in required_keys):
                    print(f"      [!] AI response JSON is missing required keys after cleaning. Received keys: {list(ai_data.keys())}")
                    # Store raw response for debugging
                    return {"error": "AI response JSON missing required keys.", "raw_response": response.text}

                # Optionally validate severity values
                valid_severities = ["High", "Medium", "Low", "Informational", "Unknown"] # Added "Unknown" as a fallback
                if ai_data["severity_assessment"] not in valid_severities:
                    print(f"      [!] Warning: AI returned unexpected severity '{ai_data['severity_assessment']}'. Defaulting to 'Unknown'.")
                    ai_data["severity_assessment"] = "Unknown"


                return ai_data # Return the cleaned and validated dictionary

            except json.JSONDecodeError as jde:
                error_msg = f"AI response was not valid JSON: {jde}. Response: {response.text[:500]}..."
                print(f"      [!] {error_msg}")
                if retries == MAX_AI_RETRIES: return {"error": error_msg, "raw_response": response.text}
            except ValueError as ve:
                 error_msg = f"AI response validation/cleaning failed: {ve}. Response: {response.text[:500]}..."
                 print(f"      [!] {error_msg}")
                 if retries == MAX_AI_RETRIES: return {"error": error_msg, "raw_response": response.text}
            except Exception as e:
                error_msg = f"Error querying Google AI: {e}. Response: {getattr(response, 'text', 'N/A')[:500]}..." # Get text safely
                print(f"      [!] {error_msg}")
                if retries == MAX_AI_RETRIES: return {"error": error_msg, "raw_response": getattr(response, 'text', 'N/A')} # Include raw if possible

            retries += 1
            # Implement exponential backoff with jitter + base delay
            delay = AI_REQUEST_DELAY * (retries + 1) + random.uniform(0, 1) # Add random jitter
            print(f"      [*] Retrying in {delay:.2f} seconds...")
            time.sleep(delay)

        return {"error": f"AI analysis failed after {MAX_AI_RETRIES} retries."}


    def enrich_vulnerabilities_with_ai(self):
        # Ensure detailed_vulnerabilities is initialized as a list
        if 'detailed_vulnerabilities' not in self.report_data or not isinstance(self.report_data['detailed_vulnerabilities'], list):
             self.report_data['detailed_vulnerabilities'] = []

        if not self.ai_model:
            print("[!] AI model not initialized. Skipping AI enrichment.")
            # Populate detailed_vulnerabilities with basic info if AI is off
            # Use initial_vulnerabilities structure as provided by check_basic_vulnerabilities
            initial_findings = self.report_data.get('initial_vulnerabilities', [])
            if not isinstance(initial_findings, list): # Handle case where initial might not be a list
                 print(f"[!] Warning: initial_vulnerabilities is not a list ({type(initial_findings)}). Cannot enrich or report.")
                 initial_findings = [] # Reset to empty list to prevent errors later

            for idx, finding_data in enumerate(initial_findings):
                 # Ensure finding_data is at least wrapped in a dict for consistency
                 if not isinstance(finding_data, dict):
                     finding_data = {'type': 'unknown', 'scanner_output': str(finding_data), 'url': self.url}

                 self.report_data['detailed_vulnerabilities'].append({
                     'id': f"vuln_{idx+1:03d}",
                     'original_finding': finding_data.get('scanner_output', str(finding_data)), # Store the original output/string
                     'original_finding_data': finding_data, # Store the structured data too
                     'ai_analysis': {"error": "AI analysis disabled or failed to initialize."}
                 })
            return

        print("\n[*] Enriching vulnerability findings with AI analysis...")
        initial_findings = self.report_data.get('initial_vulnerabilities', [])

        if not initial_findings: # Check if the list is empty
            print("[-] No initial vulnerabilities to enrich.")
            return

        if not isinstance(initial_findings, list): # Handle case where initial might not be a list
             print(f"[!] Warning: initial_vulnerabilities is not a list ({type(initial_findings)}). Cannot enrich.")
             return # Stop enrichment if data format is wrong

        # Prepare technologies list for the AI prompt
        technologies_list = [tech.get('name', str(tech)) if isinstance(tech, dict) else str(tech) for tech in self.report_data.get('technologies', [])]

        # Reset detailed_vulnerabilities to ensure only enriched findings are added
        self.report_data['detailed_vulnerabilities'] = []

        for idx, finding_data in enumerate(initial_findings):
            # Ensure finding_data is a dict before proceeding, wrap if necessary (fallback)
            if not isinstance(finding_data, dict):
                print(f"  [!] Warning: Finding {idx+1} is not in dictionary format. Wrapping in basic structure.")
                finding_data_processed = {'type': 'unknown', 'scanner_output': str(finding_data), 'url': self.url}
            else:
                 finding_data_processed = finding_data # Use the provided dict

            print(f"  -> Processing finding {idx+1}/{len(initial_findings)} (Type: {finding_data_processed.get('type', 'unknown')})")

            ai_analysis_result = self._get_ai_analysis(finding_data_processed, technologies_list)

            detailed_vuln_entry = {
                'id': f"vuln_{idx+1:03d}",
                # Store the original finding data structure
                'original_finding_data': finding_data_processed,
                # Also keep the string representation for compatibility/simplicity in templates
                'original_finding': finding_data_processed.get('scanner_output', str(finding_data_processed)),
                'ai_analysis': ai_analysis_result # This will contain the JSON fields or an error
            }
            self.report_data['detailed_vulnerabilities'].append(detailed_vuln_entry)

            if 'error' not in ai_analysis_result:
                print(f"      [+] AI analysis successful for finding {idx+1}.")
            else:
                # Use get for safer error message access
                error_details = ai_analysis_result.get('error', 'Unknown error')
                raw_response_snippet = str(ai_analysis_result.get('raw_response', 'N/A'))[:100] + '...'
                print(f"      [!] AI analysis failed for finding {idx+1}: {error_details} (Raw: {raw_response_snippet})")

            # Add delay only if not the last item
            if idx < len(initial_findings) - 1:
                 # Use the same AI request delay here
                 time.sleep(AI_REQUEST_DELAY) # Add basic rate limiting between AI calls


        print("[*] AI enrichment process completed.")


    def generate_report(self):
        print("\n[*] Generating enhanced report...")
        # Prepare Jinja2 environment
        # Create a 'templates' directory in the same location as your script
        # and place 'report_template.html' and 'report_template.txt' there.
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        if not os.path.exists(template_dir):
            os.makedirs(template_dir)
            # Create placeholder templates if they don't exist
            print(f"[*] Creating placeholder templates in '{template_dir}'. Please customize them.")
            placeholder_html = """
<html>
<head>
    <title>Vulnerability Scan Report for {{ url }}</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; margin: 20px; }
        h1, h2 { color: #333; }
        .section { margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #eee; }
        .vulnerability { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .vulnerability h3 { margin-top: 0; color: #c0392b; }
        .severity-High { color: red; font-weight: bold; }
        .severity-Medium { color: orange; font-weight: bold; }
        .severity-Low { color: green; font-weight: bold; }
        .severity-Informational { color: blue; }
        pre { background-color: #f4f4f4; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p><strong>Target URL:</strong> <a href="{{ url }}">{{ url }}</a></p>
    <p><strong>Scan Timestamp:</strong> {{ scan_timestamp }}</p>

    <div class="section">
        <h2>Detected Technologies</h2>
        {% if technologies %}
            <ul>
            {% for tech in technologies %}
                <li>{{ tech.name }}{% if tech.version %} (Version: {{ tech.version }}){% endif %}</li>
            {% endfor %}
            </ul>
        {% else %}
            <p>No specific technologies detected or error during detection.</p>
        {% endif %}
    </div>

    <div class="section">
        <h2>Analyzed Forms</h2>
        {% if forms %}
            {% for form in forms %}
                <div class="vulnerability" style="border-color:#5cb85c;"> {# Using vulnerability style for structure #}
                    <h3>Form {{ loop.index }}</h3>
                    <p><strong>Action:</strong> {{ form.action | default('N/A') }}</p>
                    <p><strong>Method:</strong> {{ form.method | default('N/A') }}</p>
                    <p><strong>Inputs:</strong></p>
                    <ul>
                        {% for input in form.inputs %}
                            <li>Name: {{ input.name | default('N/A') }}, Type: {{ input.type | default('N/A') }}</li>
                        {% endfor %}
                    </ul>
                </div>
            {% endfor %}
        {% else %}
            <p>No forms found.</p>
        {% endif %}
    </div>

    <div class="section">
        <h2>HTTP Headers</h2>
         {% if headers %}
            <pre>{{ headers | tojson(indent=2) }}</pre>
         {% else %}
             <p>No headers captured.</p>
         {% endif %}
    </div>

     <div class="section">
        <h2>Cookies</h2>
         {% if cookies %}
            <pre>{{ cookies | tojson(indent=2) }}</pre>
         {% else %}
             <p>No cookies captured.</p>
         {% endif %}
    </div>


    <div class="section">
        <h2>Vulnerability Findings ({{ detailed_vulnerabilities | length }} found)</h2>
        {% if detailed_vulnerabilities %}
            {% for vuln in detailed_vulnerabilities %}
                <div class="vulnerability">
                    <h3>{{ vuln.ai_analysis.vulnerability_name | default(vuln.original_finding) }} ({{vuln.id}})</h3>
                    <p><strong>Original Scanner Finding:</strong> {{ vuln.original_finding }}</p>

                    {% if vuln.ai_analysis and not vuln.ai_analysis.error %}
                        <p><strong>AI Description:</strong> {{ vuln.ai_analysis.detailed_description }}</p>
                        <p><strong>Potential CVEs:</strong>
                             {% if vuln.ai_analysis.potential_cves %}
                                {{ vuln.ai_analysis.potential_cves | join(', ') }}
                            {% else %}
                                N/A
                            {% endif %}
                        </p>
                        <p><strong>Exploitation Summary:</strong> {{ vuln.ai_analysis.exploitation_summary }}</p>
                        <p><strong>Mitigation Advice:</strong> {{ vuln.ai_analysis.mitigation_advice }}</p>
                        <p><strong>Severity:</strong> <span class="severity-{{ vuln.ai_analysis.severity_assessment }}">{{ vuln.ai_analysis.severity_assessment | default('Unknown') }}</span></p>
                    {% else %}
                        <p><strong>AI Analysis:</strong> {{ vuln.ai_analysis.error | default('Unavailable') }}</p>
                        {% if vuln.ai_analysis and vuln.ai_analysis.raw_response %}
                             <p><strong>Raw AI Response:</strong> <pre>{{ vuln.ai_analysis.raw_response }}</pre></p>
                        {% endif %}
                    {% endif %}
                </div>
            {% endfor %}
        {% else %}
            <p>No potential vulnerabilities identified.</p>
        {% endif %}
    </div>

</body>
</html>
            """
            placeholder_txt = """
Vulnerability Scan Report for {{ url }}
Scan Timestamp: {{ scan_timestamp }}

Detected Technologies:
{% if technologies %}
{% for tech in technologies %}
- {{ tech.name }}{% if tech.version %} (Version: {{ tech.version }}){% endif %}
{% endfor %}
{% else %}
No specific technologies detected.
{% endif %}

Analyzed Forms ({{ forms | length }} found):
{% if forms %}
{% for form in forms %}
Form {{ loop.index }}:
  Action: {{ form.action | default('N/A') }}
  Method: {{ form.method | default('N/A') }}
  Inputs:
  {% for input in form.inputs %}
    - Name: {{ input.name | default('N/A') }}, Type: {{ input.type | default('N/A') }}
  {% endfor %}
{% endfor %}
{% else %}
No forms found.
{% endif %}

HTTP Headers:
{% if headers %}
{{ headers | tojson(indent=2) }}
{% else %}
No headers captured.
{% endif %}

Cookies:
{% if cookies %}
{{ cookies | tojson(indent=2) }}
{% else %}
No cookies captured.
{% endif %}

Vulnerability Findings ({{ detailed_vulnerabilities | length }} found):
{% if detailed_vulnerabilities %}
{% for vuln in detailed_vulnerabilities %}
--- Finding {{ loop.index }} ({{vuln.id}}) ---
Original Scanner Finding: {{ vuln.original_finding }}

{% if vuln.ai_analysis and not vuln.ai_analysis.error %}
Vulnerability Name: {{ vuln.ai_analysis.vulnerability_name | default('N/A') }}
Severity: {{ vuln.ai_analysis.severity_assessment | default('Unknown') }}
Potential CVEs: {% if vuln.ai_analysis.potential_cves %}{{ vuln.ai_analysis.potential_cves | join(', ') }}{% else %}N/A{% endif %}
Detailed Description:
{{ vuln.ai_analysis.detailed_description }}
Exploitation Summary:
{{ vuln.ai_analysis.exploitation_summary }}
Mitigation Advice:
{{ vuln.ai_analysis.mitigation_advice }}
{% else %}
AI Analysis Error: {{ vuln.ai_analysis.error | default('Unavailable') }}
{% if vuln.ai_analysis and vuln.ai_analysis.raw_response %}
Raw AI Response: {{ vuln.ai_analysis.raw_response }}
{% endif %}
{% endif %}

{% endfor %}
{% else %}
No potential vulnerabilities identified.
{% endif %}
            """
            with open(os.path.join(template_dir, 'report_template.html'), 'w', encoding='utf-8') as f_html:
                f_html.write(placeholder_html)
            with open(os.path.join(template_dir, 'report_template.txt'), 'w', encoding='utf-8') as f_txt:
                f_txt.write(placeholder_txt)
            print(f"[*] Created default HTML and TXT templates. You can customize them in '{template_dir}'.")


        env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
        env.filters['tojson'] = json.dumps # Add json.dumps filter for pretty printing JSON in templates

        # HTML Report
        try:
            template_html = env.get_template('report_template.html')
            # Pass the entire report_data dict to the template
            html_output = template_html.render(self.report_data)
            report_filename_html = f"vulnerability_report_{urlparse(self.url).netloc}_{time.strftime('%Y%m%d_%H%M%S')}.html"
            with open(report_filename_html, 'w', encoding='utf-8') as f:
                f.write(html_output)
            print(f"✅ HTML report saved as '{report_filename_html}'")
        except Exception as e:
            print(f"[!] HTML Report Generation Failed: {e}")

        # TXT Report
        try:
            template_txt = env.get_template('report_template.txt') # You'll need to create this template
            # Pass the entire report_data dict to the template
            txt_output = template_txt.render(self.report_data)
            report_filename_txt = f"vulnerability_report_{urlparse(self.url).netloc}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_filename_txt, 'w', encoding='utf-8') as f:
                f.write(txt_output)
            print(f"✅ TXT report saved as '{report_filename_txt}'")
        except Exception as e:
            print(f"[!] TXT Report Generation Failed: {e}")


    def run_scan(self):
        print(f"🔍 Starting full scan for {self.url} at {self.report_data['scan_timestamp']}...")
        self.detect_technologies()
        self.analyze_forms()
        self.analyze_headers_and_cookies()
        self.check_basic_vulnerabilities() # Populates initial_vulnerabilities

        # Only run AI enrichment if AI model was successfully initialized
        if self.ai_model:
             self.enrich_vulnerabilities_with_ai() # Populates detailed_vulnerabilities
        else:
             print("[!] Skipping AI enrichment because the AI model was not initialized.")
             # Fallback: if AI enrichment is skipped, populate detailed_vulnerabilities with basic info
             for idx, finding in enumerate(self.report_data.get('initial_vulnerabilities', [])):
                 self.report_data['detailed_vulnerabilities'].append({
                     'id': f"vuln_{idx+1:03d}",
                     'original_finding': str(finding),
                     'ai_analysis': {"error": "AI analysis was skipped (AI model not available)."}
                 })


        self.generate_report()
        print("🏁 Scan finished.")




# Define your app name and version
APP_NAME = "Vulskan"
APP_VERSION = "1.1" # Or your current version number

# --- Vulnerability Checking Functions Code ---
# Paste the entire block of vulnerability checking functions here,
# including create_finding, check_sql_injection, check_xss,
# check_csrf, check_command_injection, check_file_inclusion,
# check_insecure_http_methods, check_server_info_disclosure,
# check_clickjacking, check_ssl_tls, check_open_redirect,
# check_subdomain_takeover, and check_all_vulnerabilities.
# ENSURE THESE FUNCTIONS ARE DEFINED *BEFORE* THE __main__ BLOCK
# AND *OUTSIDE* your Scanner class definition, as planned.
# They should all accept 'session' as the first argument.
# --- End Vulnerability Checking Functions Code ---


# --- Your Scanner Class Definition ---
# Place your class Scanner: ... or class VulnerabilityScanner: ... definition here.
# Make sure its run_scan method calls check_all_vulnerabilities
# and passes it the session, url, and forms data, as described in the previous answer.
# Ensure its __init__ method initializes a requests.Session object and stores it,
# and also handles basic URL normalization (adding http/s if missing).
# --- End Scanner Class Definition ---

if __name__ == '__main__':
    # --- Welcome Banner ---
    print("\n" + "="*60)
    print(f"✨ {APP_NAME} - Advanced Web Vulnerability Scanner {APP_VERSION} ✨".center(60))
    print("="*60 + "\n")

    # --- Important Warnings and Fair Use Statement ---
    print("## 🚨 IMPORTANT SECURITY NOTICE & FAIR USE 🚨 ##")
    print("-" * 60)
    print("This tool is developed for **authorized security testing** and **educational purposes only**.")
    print("It is designed to help identify potential vulnerabilities in web applications.")
    print("\n**STRICTLY PROHIBITED USAGE:**")
    print(" - Scanning any target without explicit, prior, and written permission from the owner.")
    print(" - Engaging in any activity that violates laws, regulations, or terms of service.")
    print(" - Causing damage, disruption, or unauthorized access to any system.")
    print("\n**RESPONSIBLE USAGE:**")
    print(" - Only scan systems you own or have explicit permission to scan.")
    print(" - Use this tool in a controlled environment for learning and testing.")
    print(" - Adhere to ethical hacking principles and legal boundaries.")
    print("-" * 60)

    # --- Disclaimer of Responsibility ---
    print("\n## 🛡️ DISCLAIMER OF RESPONSIBILITY 🛡️ ##")
    print("-" * 60)
    print(f"By using {APP_NAME}, you acknowledge and agree that:")
    print(" - You are **ENTIRELY responsible** for your actions and any direct or indirect consequences.")
    print(" - You bear all risks associated with the use or misuse of this software.")
    print(" - The developer(s), contributors, and anyone associated with this project **SHALL NOT BE HELD RESPONSIBLE**")
    print("   for any damage, legal issues, or misuse resulting from the use of this tool.")
    print("\n**USE THIS SOFTWARE AT YOUR OWN RISK AND ON YOUR OWN SOLE RESPONSIBILITY.**")
    print("-" * 60)

    print("\nPress Enter to confirm you understand and agree to the terms above and proceed, or Ctrl+C to exit.")
    try:
        input() # Wait for user acknowledgment
    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Exiting.")
        sys.exit(0) # Exit cleanly

    print("\n" + "="*60 + "\n") # Separator before scan starts

    # --- Get Target URL and Start Scan ---
    target_url = input("🔗 Enter target URL (e.g., http://example.com or https://example.com): ").strip()

    if not target_url:
        print("\n❌ Error: Target URL cannot be empty. Exiting.")
        sys.exit(1) # Exit with an error code
    else:
        try:
            # The Scanner class's __init__ should handle URL normalization
            # Initialize the scanner which should also initialize a requests.Session internally
            scanner = VulnerabilityScanner(target_url)

            print(f"\nInitiating scan for: {target_url}\n")
            # The run_scan method will call the standalone check_all_vulnerabilities function
            # and pass the session, url, and forms to it.
            scanner.run_scan()

        except requests.exceptions.MissingSchema:
            print(f"\n❌ Error: Invalid URL format. Please include the scheme (http:// or https://).")
            sys.exit(1)
        except requests.exceptions.ConnectionError as e:
            print(f"\n❌ Connection Error: Could not connect to the target URL. Details: {e}")
            sys.exit(1)
        except Exception as e:
            # Catch any other unexpected errors during the scan process
            print(f"\n🔥 An unexpected error occurred during the scan: {e}")
            # You might want to add more specific error handling or logging here
            sys.exit(1) # Exit with an error code

    print("\n" + "="*60)
    print(f"✅ Scan process finished for {target_url}")
    print("="*60 + "\n")