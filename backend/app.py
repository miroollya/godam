from flask import Flask, request, render_template, jsonify
import requests
import joblib
import pandas as pd

app = Flask(__name__)

# Load AI Model
model = joblib.load('file_analyzer_model.pkl')

# VirusTotal API Key
VIRUSTOTAL_API_KEY = '4c71afc46ed41a028544981d56f105d2f12d44e5ae68e0137d8277c048e05c76'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    uploaded_file = request.files['file']
    files = {'file': (uploaded_file.filename, uploaded_file)}

    # Step 1: Send file to VirusTotal
    vt_response = requests.post(
        'https://www.virustotal.com/api/v3/files',
        headers={'x-apikey': VIRUSTOTAL_API_KEY},
        files=files
    )

    if vt_response.status_code != 200:
        return jsonify({'error': 'Failed to analyze file with VirusTotal'}), 500

    vt_result = vt_response.json()
    
    # Step 2: Extract feature from VT report
    stats = vt_result['data']['attributes']['last_analysis_stats']
    positives = stats.get('malicious', 0)
    total_scans = sum(stats.values())

    # Step 3: Predict using AI model
    features = pd.DataFrame([[positives, total_scans]], columns=['positives', 'total_scans'])
    prediction = model.predict(features)[0]
    verdict = 'Malicious' if prediction == 1 else 'Safe'

    # Return result
    return jsonify({
        'VirusTotal Stats': stats,
        'AI Verdict': verdict
    })

if __name__ == '__main__':
    app.run(debug=True)
