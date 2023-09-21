from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from whois import whois
from datetime import datetime
import tldextract

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect', methods=['POST'])
def detect_phishing():
    url = request.form['url']
    features = extract_url_features(url)
    # Here, you can add more logic to classify the URL as phishing or not based on the features.
    return jsonify(features)

def extract_url_features(url):
    features = {}

    # URL-based Features
    features['url_length'] = len(url)
    
    domain_parts = tldextract.extract(url)
    if domain_parts.subdomain:
        features['num_subdomains'] = len(domain_parts.subdomain.split('.'))
    else:
        features['num_subdomains'] = 0

    features['has_ip'] = any(char.isdigit() for char in domain_parts.domain)
    features['use_https'] = True if "https" in url else False

    suspicious_words = ["secure", "account", "login", "signin", "payment"]
    features['suspicious_words'] = any(word in url for word in suspicious_words)

    special_chars = ['@', '&', '%', '#', '$', '=']
    features['num_special_chars'] = sum(url.count(char) for char in special_chars)
    features['tld'] = domain_parts.suffix
    features['domain'] = domain_parts.domain + '.' + domain_parts.suffix

    # Webpage Content Features
    try:
        response = requests.get(url, timeout=5)
        content = response.content.decode('utf-8')
        soup = BeautifulSoup(content, 'html.parser')

        features['has_forms'] = True if soup.find("form") else False
        features['external_redirection'] = True if soup.find("meta", attrs={"http-equiv": "refresh"}) else False

        scripts = [script.get('src') for script in soup.find_all('script') if script.get('src')]
        styles = [link.get('href') for link in soup.find_all('link', rel="stylesheet") if link.get('href')]
        features['external_resources'] = any(("http" in resource) for resource in scripts + styles)
        
    except requests.RequestException:
        # Handle or log exceptions
        pass

    # WHOIS Check
    try:
        whois_result = whois(features['domain'])
        features['creation_date'] = whois_result.creation_date
        features['registrar'] = whois_result.registrar
        features['expiration_date'] = whois_result.expiration_date

        if whois_result.creation_date:
            features['domain_age_days'] = (datetime.now() - whois_result.creation_date).days
        else:
            features['domain_age_days'] = None

    except Exception as e:
        # Handle or log exceptions
        pass

    # SSL Check
    try:
        cert = requests.get(url, timeout=5, verify=True).cert
        features['ssl_valid'] = True
        if cert:
            not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            features['ssl_expiry_days'] = (not_after - datetime.now()).days
    except:
        features['ssl_valid'] = False
        features['ssl_expiry_days'] = None
    
    return features

if __name__ == '__main__':
    app.run(debug=True)
