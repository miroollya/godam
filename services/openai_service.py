import openai
from config import Config

openai.api_key = Config.OPENAI_API_KEY

class OpenAIService:
    @staticmethod
    def analyze_security_data(data, data_type):
        """Analyze security data using OpenAI"""
        prompts = {
            'virustotal': f"""
                Analyze these VirusTotal scan results and determine if the resource is suspicious or clean:
                {data}
                Provide a detailed security assessment and explanation.
            """,
            'email': f"""
                Analyze this email sender address for potential security concerns:
                {data}
                Consider common phishing patterns, domain reputation, and email security best practices.
            """
        }

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing security data."},
                {"role": "user", "content": prompts.get(data_type, prompts['virustotal'])}
            ]
        )
        
        return response.choices[0].message['content']