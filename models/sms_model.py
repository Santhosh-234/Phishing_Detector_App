import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import joblib
import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import os

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

class SMSPhishingDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.scaler = StandardScaler()
        self.load_or_train_model()
    
    def extract_features(self, text):
        """Extract features from SMS text"""
        features = {}
        
        # Text length features
        features['length'] = len(text)
        features['word_count'] = len(text.split())
        features['char_count'] = len(text.replace(' ', ''))
        
        # Case features
        features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / len(text) if len(text) > 0 else 0
        features['lowercase_ratio'] = sum(1 for c in text if c.islower()) / len(text) if len(text) > 0 else 0
        
        # Special character features
        features['digit_count'] = sum(1 for c in text if c.isdigit())
        features['digit_ratio'] = features['digit_count'] / len(text) if len(text) > 0 else 0
        features['special_char_count'] = sum(1 for c in text if not c.isalnum() and not c.isspace())
        features['special_char_ratio'] = features['special_char_count'] / len(text) if len(text) > 0 else 0
        
        # URL features
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        features['has_url'] = 1 if re.search(url_pattern, text) else 0
        features['url_count'] = len(re.findall(url_pattern, text))
        
        # Phone number features
        phone_pattern = r'\b\d{10,}\b'
        features['has_phone'] = 1 if re.search(phone_pattern, text) else 0
        features['phone_count'] = len(re.findall(phone_pattern, text))
        
        # Spam keywords
        spam_keywords = [
            'free', 'win', 'winner', 'won', 'prize', 'cash', 'money', 'urgent', 'limited', 'offer',
            'click', 'call', 'text', 'sms', 'claim', 'claim now', 'act now', 'limited time',
            'exclusive', 'special', 'discount', 'save', 'sale', 'buy', 'purchase', 'credit',
            'loan', 'debt', 'refinance', 'mortgage', 'insurance', 'investment', 'stock',
            'crypto', 'bitcoin', 'lottery', 'gambling', 'casino', 'poker', 'bet', 'wager'
        ]
        
        text_lower = text.lower()
        features['spam_keyword_count'] = sum(1 for keyword in spam_keywords if keyword in text_lower)
        features['spam_keyword_ratio'] = features['spam_keyword_count'] / features['word_count'] if features['word_count'] > 0 else 0
        
        # Urgency indicators
        urgency_words = ['urgent', 'immediate', 'now', 'today', 'limited', 'expire', 'deadline', 'last chance']
        features['urgency_count'] = sum(1 for word in urgency_words if word in text_lower)
        
        # Exclamation and question marks
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['exclamation_ratio'] = features['exclamation_count'] / len(text) if len(text) > 0 else 0
        
        # Repetition features
        words = text.lower().split()
        if words:
            word_freq = {}
            for word in words:
                word_freq[word] = word_freq.get(word, 0) + 1
            features['repeated_words'] = sum(1 for count in word_freq.values() if count > 1)
            features['repetition_ratio'] = features['repeated_words'] / len(word_freq) if len(word_freq) > 0 else 0
        
        # Average word length
        if words:
            features['avg_word_length'] = np.mean([len(word) for word in words])
        else:
            features['avg_word_length'] = 0
        
        # Contains numbers in words
        features['has_numbers_in_words'] = 1 if any(any(c.isdigit() for c in word) for word in words) else 0
        
        return features
    
    def load_or_train_model(self):
        """Load existing model or train a new one"""
        model_path = 'models/sms_model.pkl'
        vectorizer_path = 'models/sms_vectorizer.pkl'
        scaler_path = 'models/sms_scaler.pkl'
        
        if os.path.exists(model_path) and os.path.exists(vectorizer_path) and os.path.exists(scaler_path):
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)
            self.scaler = joblib.load(scaler_path)
        else:
            self.train_model()
    
    def train_model(self):
        """Train the SMS phishing detection model"""
        print("Training SMS phishing detection model...")
        
        # Load and preprocess SMS dataset
        data = []
        labels = []
        
        with open('SMSSpamCollection', 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('\t', 1)
                if len(parts) == 2:
                    label, text = parts
                    data.append(text)
                    labels.append(1 if label == 'spam' else 0)
        
        # Create DataFrame
        df = pd.DataFrame({'text': data, 'label': labels})
        
        # Extract text features
        text_features = []
        for text in df['text']:
            text_features.append(self.extract_features(text))
        
        text_features_df = pd.DataFrame(text_features)
        
        # Extract TF-IDF features
        tfidf_features = self.vectorizer.fit_transform(df['text']).toarray()
        tfidf_df = pd.DataFrame(tfidf_features, columns=[f'tfidf_{i}' for i in range(tfidf_features.shape[1])])
        
        # Combine features
        X = pd.concat([text_features_df, tfidf_df], axis=1)
        y = df['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train_scaled, y_train)
        
        # Save model
        joblib.dump(self.model, 'models/sms_model.pkl')
        joblib.dump(self.vectorizer, 'models/sms_vectorizer.pkl')
        joblib.dump(self.scaler, 'models/sms_scaler.pkl')
        
        # Print accuracy
        train_score = self.model.score(X_train_scaled, y_train)
        test_score = self.model.score(X_test_scaled, y_test)
        print(f"SMS Model - Train accuracy: {train_score:.4f}, Test accuracy: {test_score:.4f}")
    
    def predict(self, text):
        """Predict if SMS text is spam/phishing"""
        # Extract text features
        text_features = self.extract_features(text)
        text_features_df = pd.DataFrame([text_features])
        
        # Extract TF-IDF features
        tfidf_features = self.vectorizer.transform([text]).toarray()
        tfidf_df = pd.DataFrame(tfidf_features, columns=[f'tfidf_{i}' for i in range(tfidf_features.shape[1])])
        
        # Combine features
        X = pd.concat([text_features_df, tfidf_df], axis=1)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Make prediction
        prediction = self.model.predict(X_scaled)[0]
        confidence = max(self.model.predict_proba(X_scaled)[0]) * 100
        
        return prediction, confidence, text_features 