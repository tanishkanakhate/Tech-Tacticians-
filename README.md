# PhishGuard – Intelligent Phishing URL Detection (PS-05)
## Run
    pip install -r requirements.txt
    python app.py            # open http://localhost:5000
## Browser extension
chrome://extensions → Developer mode → Load unpacked → select the `extension` folder.
## API
POST /api/analyze {"url": "..."}  ·  POST /api/bulk {"text": "message with links"}
