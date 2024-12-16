"""Configuration settings for the security analyzer"""
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # File upload settings
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # API keys
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    HYBRID_ANALYSIS_API_KEY = os.getenv('HYBRID_ANALYSIS_API_KEY')
    
    # Data storage
    DATA_DIR = 'data'
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = 'logs/security_analyzer.log'
    
    # Feature flags
    ENABLE_HYBRID_ANALYSIS = os.getenv('ENABLE_HYBRID_ANALYSIS', 'true').lower() == 'true'
    
    # Threat Intelligence
    THREAT_SCORE_THRESHOLD = {
        'low': 30,
        'medium': 60,
        'high': 80
    }
    
    # Initialize required directories
    @classmethod
    def init_directories(cls):
        """Initialize required directories"""
        directories = [
            cls.UPLOAD_FOLDER,
            cls.DATA_DIR,
            'logs'
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)