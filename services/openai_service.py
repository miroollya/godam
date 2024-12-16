"""OpenAI service for security analysis"""
import openai
from config import Config
from typing import Any, Dict

class OpenAIService:
    def __init__(self):
        openai.api_key = Config.OPENAI_API_KEY

    def analyze_security_data(self, data: Any, data_type: str) -> Dict[str, Any]:
        """Analyze security data using OpenAI"""
        try:
            system_prompts = {
                'file': """You are a cybersecurity expert analyzing file scan results. 
                          Format your response in the following structure:
                          - Summary: Brief overview with threat level (SAFE/LOW RISK/MEDIUM RISK/HIGH RISK)
                          - Key Findings: Bullet points of main security concerns
                          - Technical Details: Detailed analysis of threats found
                          - Recommendations: Security advice
                          Use HTML tags for highlighting: 
                          <span class="text-red-500"> for threats
                          <span class="text-yellow-500"> for warnings
                          <span class="text-green-500"> for safe elements""",
                
                'url': """You are a cybersecurity expert analyzing URLs for security threats.
                         Format your response in the following structure:
                         - Summary: Brief overview with threat level (SAFE/LOW RISK/MEDIUM RISK/HIGH RISK)
                         - Domain Analysis: Analysis of the domain reputation
                         - Pattern Analysis: Suspicious patterns found
                         - Technical Details: Detailed breakdown of findings
                         - Recommendations: Security advice
                         Use HTML tags for highlighting:
                         <span class="text-red-500"> for threats
                         <span class="text-yellow-500"> for warnings
                         <span class="text-green-500"> for safe elements""",
                
                'email': """You are a cybersecurity expert analyzing email addresses for potential threats.
                           Format your response in the following structure:
                           - Summary: Brief overview with threat level (SAFE/LOW RISK/MEDIUM RISK/HIGH RISK)
                           - Domain Analysis: Analysis of the email domain
                           - Pattern Analysis: Suspicious patterns found
                           - Technical Details: Detailed breakdown of findings
                           - Recommendations: Security advice
                           Use HTML tags for highlighting:
                           <span class="text-red-500"> for threats
                           <span class="text-yellow-500"> for warnings
                           <span class="text-green-500"> for safe elements"""
            }

            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompts.get(data_type, system_prompts['file'])},
                    {"role": "user", "content": str(data)}
                ]
            )
            
            return {
                'analysis': response.choices[0].message['content'],
                'format_version': '2.0'  # For frontend to know this is the new format
            }
        except Exception as e:
            return {
                'error': str(e),
                'analysis': f"AI analysis failed: {str(e)}",
                'format_version': '2.0'
            }