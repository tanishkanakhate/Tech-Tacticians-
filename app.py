"""
PhishGuard - Intelligent Phishing URL Detection Platform
Flask Backend Server
"""

import os
import sys
from flask import Flask, render_template, request, jsonify

\# Ensure application root is in python path
current_dir = os.path.dirname(os.path.abspath(\_\_file\_\_))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from ml.model import classifier

app = Flask(
    \_\_name\_\_,
    template_folder="templates",
    static_folder="static"
)

SAMPLE_URLS = [
    {
        "url": "[https://www.google.com](https://www.google.com)",
        "category": "Legitimate",
        "description": "Standard search engine with HTTPS and recognized domain."
    },
    {
        "url": "[https://github.com/torvalds/linux](https://github.com/torvalds/linux)",
        "category": "Legitimate",
        "description": "Official open-source repository on a trusted platform."
    },
    {
        "url": "[http://tinyurl.com/update-bank-credentials-now](http://tinyurl.com/update-bank-credentials-now)",
        "category": "Suspicious",
        "description": "Shortened link with credential update keywords and HTTP."
    },
    {
        "url": "[http://192.168.1.105/bank-login.html](http://192.168.1.105/bank-login.html)",
        "category": "Phishing",
        "description": "Direct IP hosting with financial/login path."
    },
    {
        "url": "[http://secure-banking-update.wellsfargo.com.suspicious-domain.cc/login](http://secure-banking-update.wellsfargo.com.suspicious-domain.cc/login)",
        "category": "Phishing",
        "description": "Subdomain brand spoofing with suspicious multi-level TLD."
    },
    {
        "url": "[http://www.paypal.com@verify-now-safety.net/webscr](http://www.paypal.com@verify-now-safety.net/webscr)",
        "category": "Phishing",
        "description": "Using '@' symbol to mask actual target destination."
    }
]


@app.route("/")
def index():
    """Render the PhishGuard frontend dashboard."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_url():
    """
    Main detection endpoint:
    Receives URL, validates, extracts features, performs classification,
    and returns risk score and analysis.
    """
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({
            "status": "error",
            "message": "Missing 'url' parameter in JSON payload."
        }), 400

    raw_url = str(data.get("url", "")).strip()

    if not raw_url:
        return jsonify({
            "status": "error",
            "message": "URL cannot be empty."
        }), 400

    if len(raw_url) > 2048:
        return jsonify({
            "status": "error",
            "message": "URL exceeds maximum allowable length of 2048 characters."
        }), 400

    try:
        result = classifier.predict(raw_url)
        return jsonify({
            "status": "success",
            "data": result
        }), 200
    except Exception as e:
        app.logger.error(f"Error scanning URL '{raw_url}': {e}")
        return jsonify({
            "status": "error",
            "message": f"Scan failed: {str(e)}"
        }), 500


@app.route("/api/sample-urls", methods=["GET"])
def get_sample_urls():
    """Provide sample URLs for testing the detection engine."""
    return jsonify({
        "status": "success",
        "samples": SAMPLE_URLS
    }), 200


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint to verify backend status."""
    return jsonify({
        "status": "healthy",
        "service": "PhishGuard",
        "version": "1.0.0",
        "model_loaded": classifier.model is not None
    }), 200


if \_\_name\_\_ == "\_\_main\_\_":
    host = os.environ.get("PHISHGUARD_HOST", "127.0.0.1")
    port = int(os.environ.get("PHISHGUARD_PORT", 5000))
    print(f"\n=======================================================")
    print(f" Shield Active: PhishGuard is running at http\://{host}:{port}")
    print(f" Press Ctrl+C to terminate the server.")
    print(f"=======================================================\n")
    app.run(host=host, port=port, debug=True) what features are added in this


