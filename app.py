from flask import Flask, request, render_template, jsonify
import os
from config import Config
from services.virustotal_service import VirusTotalService
from services.openai_service import OpenAIService
from services.ml_service import MLService
from services.url_service import URLService
from services.email_service import EmailService
from utils.response_formatter import ResponseFormatter
from utils.file_handler import FileHandler

app = Flask(__name__)
app.config.from_object(Config)

# Initialize services
vt_service = VirusTotalService()
openai_service = OpenAIService()
ml_service = MLService()
url_service = URLService()
email_service = EmailService()
file_handler = FileHandler()
response_formatter = ResponseFormatter()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze/file', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # Step 1: VirusTotal Analysis
        vt_results = vt_service.analyze_file(file)
        if vt_results.get('error'):
            return jsonify(vt_results), 400

        formatted_results = response_formatter.format_virustotal_response(vt_results)
        
        # Step 2: ML Analysis
        is_malicious = formatted_results.get('malicious', 0) > 0
        ml_results = ml_service.analyze_and_learn(
            {**formatted_results, 'is_malicious': is_malicious},
            'file'
        )
        
        # Step 3: AI Analysis
        ai_analysis = openai_service.analyze_security_data(
            {
                'vt_results': formatted_results,
                'ml_results': ml_results
            },
            'file'
        )
        
        return jsonify({
            'virustotal_results': formatted_results,
            'ml_analysis': ml_results,
            'ai_analysis': ai_analysis
        })
    
    except Exception as e:
        return jsonify({
            'error': True,
            'message': str(e)
        }), 500

@app.route('/analyze/url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        # Step 1: VirusTotal Analysis
        vt_results = vt_service.analyze_url(data['url'])
        if vt_results.get('error'):
            return jsonify(vt_results), 400

        formatted_vt_results = response_formatter.format_virustotal_response(vt_results)
        
        # Step 2: URL Pattern Analysis
        url_analysis = url_service.analyze_url(data['url'])
        
        # Step 3: ML Analysis
        is_suspicious = url_analysis['is_suspicious'] or formatted_vt_results.get('malicious', 0) > 0
        ml_results = ml_service.analyze_and_learn(
            {
                'url': data['url'],
                'vt_results': formatted_vt_results,
                'url_analysis': url_analysis,
                'is_suspicious': is_suspicious
            },
            'url'
        )
        
        # Step 4: AI Analysis
        ai_analysis = openai_service.analyze_security_data(
            {
                'url': data['url'],
                'vt_results': formatted_vt_results,
                'url_analysis': url_analysis,
                'ml_results': ml_results
            },
            'url'
        )
        
        return jsonify({
            'virustotal_results': formatted_vt_results,
            'url_analysis': url_analysis,
            'ml_analysis': ml_results,
            'ai_analysis': ai_analysis
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analyze/email', methods=['POST'])
def analyze_email():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({'error': 'No email provided'}), 400
    
    try:
        # Extract domain for VirusTotal analysis
        domain = data['email'].split('@')[1]
        
        # Step 1: VirusTotal Analysis
        vt_results = vt_service.analyze_domain(domain)
        if vt_results.get('error'):
            return jsonify(vt_results), 400

        formatted_vt_results = response_formatter.format_virustotal_response(vt_results)
        
        # Step 2: Email Pattern Analysis
        email_analysis = email_service.analyze_email(data['email'])
        
        # Step 3: ML Analysis
        is_suspicious = email_analysis['is_suspicious'] or formatted_vt_results.get('malicious', 0) > 0
        ml_results = ml_service.analyze_and_learn(
            {
                'email': data['email'],
                'vt_results': formatted_vt_results,
                'email_analysis': email_analysis,
                'is_suspicious': is_suspicious
            },
            'email'
        )
        
        # Step 4: AI Analysis
        ai_analysis = openai_service.analyze_security_data(
            {
                'email': data['email'],
                'vt_results': formatted_vt_results,
                'email_analysis': email_analysis,
                'ml_results': ml_results
            },
            'email'
        )
        
        return jsonify({
            'virustotal_results': formatted_vt_results,
            'email_analysis': email_analysis,
            'ml_analysis': ml_results,
            'ai_analysis': ai_analysis
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')