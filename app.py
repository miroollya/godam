from flask import Flask, request, render_template, jsonify
import os
from config import Config
from services.virustotal_service import VirusTotalService
from services.openai_service import OpenAIService
from utils.response_formatter import ResponseFormatter
from utils.file_handler import FileHandler

app = Flask(__name__)
app.config.from_object(Config)

# Initialize services
vt_service = VirusTotalService()
openai_service = OpenAIService()
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
        # Analyze with VirusTotal
        vt_results = vt_service.analyze_file(file)
        
        if vt_results.get('error'):
            return jsonify(vt_results), 400

        # Format the response
        formatted_results = response_formatter.format_virustotal_response(vt_results)
        
        # Get AI analysis
        ai_analysis = openai_service.analyze_security_data(formatted_results, 'virustotal')
        
        return jsonify({
            'virustotal_results': formatted_results,
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
    
    # URL analysis implementation here
    return jsonify({'message': 'URL analysis endpoint'}), 501

@app.route('/analyze/email', methods=['POST'])
def analyze_email():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({'error': 'No email provided'}), 400
    
    # Email analysis implementation here
    return jsonify({'message': 'Email analysis endpoint'}), 501

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')