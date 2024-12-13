import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    MODEL_PATH = 'models/security_classifier.pkl'
    TRAIN_ENDPOINT = "/train"