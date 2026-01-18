from flask import Flask, render_template, request, jsonify
import re
import requests
import hashlib
import math
from collections import Counter

app = Flask(__name__)

# =========================
# OWASP A03 – Input Sanitization
# =========================
def sanitize_input(value):
    if value is None:
        return ""
    return re.sub(r"[<>\"'`;()]", "", value)

# HIBP API key 
HIBP_API_KEY = "YOUR_HIBP_API_KEY"

@app.route('/')
def index():
    return render_template('email.html')

@app.route('/check_email', methods=['POST'])
def check_email():
    email = sanitize_input(request.form['email'])

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "AdvancedPasswordCheckerDemo"
    }

    breached = False
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            breached = True
        elif response.status_code == 404:
            breached = False
        else:
            breached = False
    except requests.exceptions.RequestException:
        breached = False

    return render_template('email.html', email=email, breached=breached)

# Password page
@app.route('/password')
def password():
    return render_template('password.html')

# Check password (Results.html)
@app.route('/check_password', methods=['POST'])
def check_password():
    password = sanitize_input(request.form['password'])

    def calculate_entropy(pwd):
        probabilities = [n / len(pwd) for n in Counter(pwd).values()]
        entropy = -sum(p * math.log2(p) for p in probabilities)
        return round(entropy * len(pwd), 2)

    entropy = calculate_entropy(password)

    def check_password_breach(pwd):
        sha1_pwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
        prefix = sha1_pwd[:5]
        suffix = sha1_pwd[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)
        if response.status_code == 200:
            for line in response.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix.strip() == suffix:
                    return int(count)
        return 0

    breach_count = check_password_breach(password)

    return render_template('Results.html',
                           entropy=entropy,
                           breach_count=breach_count)

# API endpoint for JS breach check
@app.route('/api/check_password', methods=['POST'])
def api_check_password():
    data = request.get_json()
    password = sanitize_input(data.get('password', ''))

    def check_password_breach(pwd):
        sha1_pwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
        prefix = sha1_pwd[:5]
        suffix = sha1_pwd[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)
        if response.status_code == 200:
            for line in response.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix.strip() == suffix:
                    return int(count)
        return 0

    breach_count = check_password_breach(password)
    breached = breach_count > 0

    return jsonify({'breached': breached, 'count': breach_count})

if __name__ == '__main__':
    app.run(debug=True)
