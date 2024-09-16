from flask import Flask, render_template, request
import requests
from tags import tags
#


app = Flask(__name__)


def check_xss(url):
    for key, xss_test_script in tags.items():
        response = requests.get(url, params={"q": tags})
        if xss_test_script in response.text:
            return True
    return False

def check_sql_injection(url):
    sql_test_payload = "' OR '1'='1"
    response = requests.get(url, params={"id": sql_test_payload})
    if "sql" in response.text.lower():
        return True
    return False

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        xss_vulnerable = check_xss(url)
        sql_injection_vulnerable = check_sql_injection(url)
        return render_template("result.html", url=url, xss=xss_vulnerable, sql=sql_injection_vulnerable)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)

