# **AI-Powered File Analyzer with VirusTotal Integration**

## **Overview**  
This project is an **AI-powered hybrid file analyzer** that combines:  
1. **VirusTotal API** for real-time file analysis.  
2. **Machine Learning Models** (RandomForest & XGBoost) to predict file safety.  

The system intercepts uploaded files, analyzes them using VirusTotal's threat intelligence, and utilizes AI models to summarize the results as **"Safe"** or **"Malicious"**.  

---

## **Features**  
- **Real-Time File Analysis**: Integrates with VirusTotal to analyze files for malware, suspicious activities, or other threats.  
- **AI Verdict**: Trained AI models (RandomForest & XGBoost) predict the file's safety based on VirusTotal scan results.  
- **User-Friendly Interface**: Upload files easily using a clean web interface.  
- **API Integration**: Fast and efficient backend built with Flask.  

---

## **Tech Stack**  

### **Frontend**  
- HTML, CSS (Basic static page).  

### **Backend**  
- **Flask**: Handles file uploads and API endpoints.  
- **VirusTotal API**: For file scanning and threat intelligence.  
- **AI Models**:  
   - **RandomForest**  
   - **XGBoost**  
- **Pandas**: For data processing.  
- **Joblib**: Saving and loading AI models.

---

## **System Architecture**  

```plaintext
User → Upload File → Flask Backend → VirusTotal API → AI Model Prediction → Response (Safe/Malicious)


