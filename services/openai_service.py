"""OpenAI service for advanced security analysis with bullet point format output"""
import openai
from config import Config
from typing import Any, Dict

class OpenAIService:
    def __init__(self):
        openai.api_key = Config.OPENAI_API_KEY

    def analyze_security_data(self, data: Any, data_type: str) -> str:
        """Analyze security data using OpenAI"""
        try:
            system_prompts = {
                'virustotal': (
                    "You are a top-tier cybersecurity analyst specializing in malware analysis. Your task is to analyze "
                    "VirusTotal scan results and present findings clearly in bullet point format. Ensure to include:\n\n"
                    "- **File Hashes**: List of suspicious file hashes found.\n"
                    "- **Malicious Signatures**: Names of malware or heuristic detections.\n"
                    "- **Related CVEs**: Known vulnerabilities linked to findings.\n"
                    "- **Threat Score**: Overall threat score (e.g., 0-100).\n"
                    "- **Recommended Mitigations**: Steps to protect the system or respond to the threat.\n"
                    "Provide detailed and actionable findings in a clean, easy-to-read bullet point format."
                ),
                'url': (
                    "You are a cybersecurity expert with expertise in URL threat analysis. Your task is to analyze a URL "
                    "for potential security risks and provide findings in bullet point format. Include:\n\n"
                    "- **URL Analyzed**: The URL being investigated.\n"
                    "- **Indicators of Compromise (IOCs)**: Suspicious keywords, TLDs, or patterns.\n"
                    "- **Hosting Reputation**: Reputation of the hosting server and its age.\n"
                    "- **Redirection Behavior**: Any suspicious redirects detected.\n"
                    "- **Malicious Content**: Details of malware, phishing, or spam identified.\n"
                    "- **Recommended Actions**: Steps to handle and secure the environment.\n"
                    "Ensure the output is detailed, structured, and actionable."
                ),
                'email': (
                    "You are a cybersecurity expert analyzing email threats for phishing or malicious content. Your task is "
                    "to provide findings in bullet point format. Include:\n\n"
                    "- **Email Address**: The sender's email address.\n"
                    "- **Header Analysis**: Suspicious headers, forged details, or anomalies.\n"
                    "- **Attachments or Links**: Malicious files, obfuscated links, or attachments found.\n"
                    "- **Indicators of Compromise (IOCs)**: Red flags such as spoofed domains, unusual content, or patterns.\n"
                    "- **Phishing Indicators**: Tactics used (e.g., urgency, impersonation, fake login pages).\n"
                    "- **Recommended Actions**: Steps for mitigation, user protection, and email filtering.\n"
                    "Provide detailed insights with a focus on actionable security measures."
                )
            }

            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompts.get(data_type, system_prompts['virustotal'])},
                    {"role": "user", "content": str(data)}
                ]
            )
            
            return response.choices[0].message['content']
        except Exception as e:
            return f"AI analysis failed: {str(e)}"
