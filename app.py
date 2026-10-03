from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from detector import analyze

app = Flask(__name__, static_folder="static")
CORS(app)  # lets the browser extension call the API

@app.get("/")
def home(): return send_from_directory("static", "index.html")

@app.post("/api/analyze")
def api_analyze():
    url = (request.get_json(silent=True) or {}).get("url", "")
    if not url: return jsonify(error="url required"), 400
    return jsonify(analyze(url))

@app.post("/api/bulk")  # for chat/message flows: scan every link in a text
def api_bulk():
    import re
    text = (request.get_json(silent=True) or {}).get("text", "")
    urls = re.findall(r"(?:https?://|www\.)[^\s<>\"']+", text)
    return jsonify([analyze(u) for u in urls])

if __name__ == "__main__":
    app.run(port=5000, debug=True)
