from flask import Flask, render_template, request
import requests
import concurrent.futures
from tags import xsstags  # Ensure this returns a dict or list of scripts
from sqltags import sqltags  # Ensure this returns a list of payloads

app = Flask(__name__)

# Function to check XSS vulnerabilities
def check_xss(url):
    try:
        for key, xss_test_script in xsstags.items():  # Use .items() if it's a dict
            response = requests.get(url, params={"q": xss_test_script})
            if xss_test_script in response.text:
                return True
    except requests.RequestException as e:
        print(f"XSS check failed: {e}")
    return False

# Function to check SQL Injection vulnerabilities
def check_sql_injection(url):
    try:
        for sql_test_payload in sqltags:  # Assuming sqltags is a list of payloads
            response = requests.get(url, params={"id": sql_test_payload})
            if "sql" in response.text.lower():
                return True
    except requests.RequestException as e:
        print(f"SQL Injection check failed: {e}")
        return False
    return False

# Run both checks concurrently using multithreading
def run_checks(url):
    with concurrent.futures.ThreadPoolExecutor(max_workers=20000) as executor:
        xss_future = executor.submit(check_xss, url)
        sql_future = executor.submit(check_sql_injection, url)
        return xss_future.result(), sql_future.result()

@app.route("/", methods=["GET", "POST"])
def index():
    url = None
    xss_vulnerable = sql_injection_vulnerable = None

    if request.method == "POST":
        url = request.form.get("url")
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        xss_vulnerable, sql_injection_vulnerable = run_checks(url)

    return render_template("index.html", url=url, xss=xss_vulnerable, sql=sql_injection_vulnerable)

if __name__ == "__main__":
    app.run(debug=True)
