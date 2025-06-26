import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib
import re
import tldextract
from urllib.parse import urlparse
import os

class URLPhishingDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
            'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
            'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
            'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www',
            'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
            'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
            'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
            'nb_subdomains', 'prefix_suffix', 'random_domain',
            'shortening_service', 'path_extension', 'nb_redirection',
            'nb_external_redirection', 'length_words_raw', 'char_repeat',
            'shortest_words_raw', 'shortest_word_host', 'shortest_word_path',
            'longest_words_raw', 'longest_word_host', 'longest_word_path',
            'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints',
            'domain_in_brand', 'brand_in_subdomain', 'brand_in_path',
            'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
            'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
            'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection',
            'ratio_intErrors', 'ratio_extErrors', 'login_form', 'external_favicon',
            'links_in_tags', 'submit_email', 'ratio_intMedia', 'ratio_extMedia',
            'sfh', 'iframe', 'popup_window', 'safe_anchor', 'onmouseover',
            'right_clic', 'empty_title', 'domain_in_title', 'domain_with_copyright',
            'whois_registered_domain', 'domain_registration_length', 'domain_age',
            'web_traffic', 'dns_record', 'google_index', 'page_rank'
        ]
        self.load_or_train_model()
    
    def extract_features(self, url):
        """Extract features from a URL"""
        features = {}
        
        try:
            # Basic URL features
            features['length_url'] = len(url)
            
            # Parse URL
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            features['length_hostname'] = len(hostname)
            
            # IP address check
            features['ip'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname) else 0
            
            # Count various characters
            features['nb_dots'] = url.count('.')
            features['nb_hyphens'] = url.count('-')
            features['nb_at'] = url.count('@')
            features['nb_qm'] = url.count('?')
            features['nb_and'] = url.count('&')
            features['nb_or'] = url.count('|')
            features['nb_eq'] = url.count('=')
            features['nb_underscore'] = url.count('_')
            features['nb_tilde'] = url.count('~')
            features['nb_percent'] = url.count('%')
            features['nb_slash'] = url.count('/')
            features['nb_star'] = url.count('*')
            features['nb_colon'] = url.count(':')
            features['nb_comma'] = url.count(',')
            features['nb_semicolumn'] = url.count(';')
            features['nb_dollar'] = url.count('$')
            features['nb_space'] = url.count(' ')
            features['nb_www'] = 1 if 'www' in hostname else 0
            features['nb_com'] = 1 if '.com' in hostname else 0
            features['nb_dslash'] = url.count('//')
            
            # Protocol features
            features['http_in_path'] = 1 if 'http' in parsed.path else 0
            features['https_token'] = 1 if 'https' in url else 0
            
            # Digit ratios
            digits_url = sum(c.isdigit() for c in url)
            digits_host = sum(c.isdigit() for c in hostname)
            features['ratio_digits_url'] = digits_url / len(url) if len(url) > 0 else 0
            features['ratio_digits_host'] = digits_host / len(hostname) if len(hostname) > 0 else 0
            
            # Domain features
            extracted = tldextract.extract(url)
            features['punycode'] = 1 if 'xn--' in hostname else 0
            features['port'] = 1 if parsed.port else 0
            features['tld_in_path'] = 1 if extracted.suffix in parsed.path else 0
            features['tld_in_subdomain'] = 1 if extracted.suffix in extracted.subdomain else 0
            features['abnormal_subdomain'] = 1 if len(extracted.subdomain) > 3 else 0
            features['nb_subdomains'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            
            # Suspicious patterns
            features['prefix_suffix'] = 1 if '-' in hostname else 0
            features['random_domain'] = 1 if re.search(r'\d{4,}', hostname) else 0
            features['shortening_service'] = 1 if any(service in hostname for service in ['bit.ly', 'tinyurl', 'goo.gl']) else 0
            features['path_extension'] = 1 if '.' in parsed.path else 0
            
            # Default values for features not easily extractable from single URL
            features['nb_redirection'] = 0
            features['nb_external_redirection'] = 0
            features['length_words_raw'] = len(url.split())
            features['char_repeat'] = 0
            features['shortest_words_raw'] = min(len(word) for word in url.split()) if url.split() else 0
            features['shortest_word_host'] = min(len(word) for word in hostname.split('.')) if hostname.split('.') else 0
            features['shortest_word_path'] = min(len(word) for word in parsed.path.split('/')) if parsed.path.split('/') else 0
            features['longest_words_raw'] = max(len(word) for word in url.split()) if url.split() else 0
            features['longest_word_host'] = max(len(word) for word in hostname.split('.')) if hostname.split('.') else 0
            features['longest_word_path'] = max(len(word) for word in parsed.path.split('/')) if parsed.path.split('/') else 0
            features['avg_words_raw'] = np.mean([len(word) for word in url.split()]) if url.split() else 0
            features['avg_word_host'] = np.mean([len(word) for word in hostname.split('.')]) if hostname.split('.') else 0
            features['avg_word_path'] = np.mean([len(word) for word in parsed.path.split('/')]) if parsed.path.split('/') else 0
            
            # Phishing hints
            phishing_keywords = ['login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm']
            features['phish_hints'] = sum(1 for keyword in phishing_keywords if keyword in url.lower())
            
            # Brand features (simplified)
            features['domain_in_brand'] = 0
            features['brand_in_subdomain'] = 0
            features['brand_in_path'] = 0
            
            # TLD features
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
            features['suspecious_tld'] = 1 if any(tld in hostname for tld in suspicious_tlds) else 0
            
            # Default values for remaining features
            features['statistical_report'] = 0
            features['nb_hyperlinks'] = 0
            features['ratio_intHyperlinks'] = 0
            features['ratio_extHyperlinks'] = 0
            features['ratio_nullHyperlinks'] = 0
            features['nb_extCSS'] = 0
            features['ratio_intRedirection'] = 0
            features['ratio_extRedirection'] = 0
            features['ratio_intErrors'] = 0
            features['ratio_extErrors'] = 0
            features['login_form'] = 0
            features['external_favicon'] = 0
            features['links_in_tags'] = 0
            features['submit_email'] = 0
            features['ratio_intMedia'] = 0
            features['ratio_extMedia'] = 0
            features['sfh'] = 0
            features['iframe'] = 0
            features['popup_window'] = 0
            features['safe_anchor'] = 0
            features['onmouseover'] = 0
            features['right_clic'] = 0
            features['empty_title'] = 0
            features['domain_in_title'] = 0
            features['domain_with_copyright'] = 0
            features['whois_registered_domain'] = 0
            features['domain_registration_length'] = 0
            features['domain_age'] = 0
            features['web_traffic'] = 0
            features['dns_record'] = 0
            features['google_index'] = 0
            features['page_rank'] = 0
            
        except Exception as e:
            # Return default features if URL parsing fails
            features = {name: 0 for name in self.feature_names}
        
        return features
    
    def load_or_train_model(self):
        """Load existing model or train a new one"""
        model_path = 'models/url_model.pkl'
        scaler_path = 'models/url_scaler.pkl'
        
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
        else:
            self.train_model()
    
    def train_model(self):
        """Train the URL phishing detection model"""
        print("Training URL phishing detection model...")
        
        # Load dataset
        df = pd.read_csv('dataset_phishing.csv')
        
        # Prepare features and target
        X = df.drop(['url', 'status'], axis=1, errors='ignore')
        y = df['status'].map({'phishing': 1, 'legitimate': 0})
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train_scaled, y_train)
        
        # Save model
        joblib.dump(self.model, 'models/url_model.pkl')
        joblib.dump(self.scaler, 'models/url_scaler.pkl')
        
        # Print accuracy
        train_score = self.model.score(X_train_scaled, y_train)
        test_score = self.model.score(X_test_scaled, y_test)
        print(f"URL Model - Train accuracy: {train_score:.4f}, Test accuracy: {test_score:.4f}")
    
    def predict(self, url):
        """Predict if a URL is phishing"""
        # Extract features
        features = self.extract_features(url)
        
        # Convert to feature vector
        feature_vector = [features.get(name, 0) for name in self.feature_names]
        
        # Scale features
        feature_vector_scaled = self.scaler.transform([feature_vector])
        
        # Make prediction
        prediction = self.model.predict(feature_vector_scaled)[0]
        confidence = max(self.model.predict_proba(feature_vector_scaled)[0]) * 100
        
        return prediction, confidence, features 