from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
from models.url_model import URLPhishingDetector
from models.sms_model import SMSPhishingDetector
from models.email_model import EmailPhishingDetector
import os

app = Flask(__name__)

# Initialize models
url_detector = URLPhishingDetector()
sms_detector = SMSPhishingDetector()
email_detector = EmailPhishingDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect_url', methods=['POST'])
def detect_url():
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Get prediction and confidence
        prediction, confidence, features = url_detector.predict(url)
        
        result = {
            'url': url,
            'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
            'confidence': f"{confidence:.2f}%",
            'risk_level': 'High' if prediction == 1 else 'Low',
            'features_analyzed': len(features),
            'suspicious_features': [f for f, v in features.items() if v > 0.5]
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/detect_sms', methods=['POST'])
def detect_sms():
    try:
        data = request.get_json()
        sms_text = data.get('sms_text', '')
        
        if not sms_text:
            return jsonify({'error': 'SMS text is required'}), 400
        
        # Get prediction and confidence
        prediction, confidence, features = sms_detector.predict(sms_text)
        
        result = {
            'sms_text': sms_text,
            'prediction': 'Spam/Phishing' if prediction == 1 else 'Legitimate',
            'confidence': f"{confidence:.2f}%",
            'risk_level': 'High' if prediction == 1 else 'Low',
            'features_analyzed': len(features),
            'suspicious_features': [f for f, v in features.items() if v > 0.5]
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/detect_email', methods=['POST'])
def detect_email():
    try:
        data = request.get_json()
        email_text = data.get('email_text', '')
        
        if not email_text:
            return jsonify({'error': 'Email text is required'}), 400
        
        # Get prediction and confidence
        prediction, confidence, features = email_detector.predict(email_text)
        
        result = {
            'email_text': email_text[:200] + '...' if len(email_text) > 200 else email_text,
            'prediction': 'Spam/Phishing' if prediction == 1 else 'Legitimate',
            'confidence': f"{confidence:.2f}%",
            'risk_level': 'High' if prediction == 1 else 'Low',
            'features_analyzed': len(features),
            'suspicious_features': [f for f, v in features.items() if v > 0.5]
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 