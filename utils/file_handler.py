import os
from werkzeug.utils import secure_filename
from typing import BinaryIO
from config import Config

class FileHandler:
    def __init__(self):
        self.upload_folder = Config.UPLOAD_FOLDER
        os.makedirs(self.upload_folder, exist_ok=True)

    def save_file(self, file: BinaryIO, filename: str) -> str:
        """Save uploaded file and return the path"""
        filename = secure_filename(filename)
        filepath = os.path.join(self.upload_folder, filename)
        file.save(filepath)
        return filepath

    def cleanup_file(self, filepath: str) -> None:
        """Remove temporary file"""
        if os.path.exists(filepath):
            os.remove(filepath)