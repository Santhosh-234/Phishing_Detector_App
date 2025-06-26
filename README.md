# Phishing Detection Web Application

A comprehensive machine learning-based phishing detection system that analyzes URLs, SMS messages, and emails to identify potential phishing attempts.

## Features

- **Multi-domain Detection**: Supports URL, SMS, and Email phishing detection
- **Machine Learning Models**: Uses Random Forest classifiers with feature engineering
- **Real-time Analysis**: Instant predictions with confidence scores
- **Modern Web Interface**: Responsive design with Bootstrap and interactive charts
- **Feature Analysis**: Detailed breakdown of suspicious features detected

## Dataset Information

The application uses three publicly available datasets:

1. **URL Phishing Dataset** (`dataset_phishing.csv`): Contains 11,055 URLs with 87 features
2. **SMS Spam Dataset** (`SMSSpamCollection`): Contains 5,574 SMS messages labeled as spam/ham
3. **Email Spam Dataset** (`spam_assassin.csv`): Contains 4,827 emails labeled as spam/legitimate

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd Phishing_Detector_App
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the application**:
   Open your browser and navigate to `http://localhost:5000`

## Deployment

### Option 1: Render (Recommended - Free)

1. **Create a Render account** at [render.com](https://render.com)

2. **Connect your GitHub repository**:
   - Go to your Render dashboard
   - Click "New +" and select "Web Service"
   - Connect your GitHub account and select this repository

3. **Configure the service**:
   - **Name**: `phishing-detector-app`
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`

4. **Deploy**: Click "Create Web Service"

Your app will be available at `https://your-app-name.onrender.com`

### Option 2: Railway (Alternative - Free)

1. **Create a Railway account** at [railway.app](https://railway.app)

2. **Deploy from GitHub**:
   - Go to Railway dashboard
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose this repository

3. **Automatic deployment**: Railway will automatically detect the configuration and deploy your app

Your app will be available at `https://your-app-name.railway.app`

### Option 3: Heroku (Paid but Reliable)

1. **Install Heroku CLI** and create an account at [heroku.com](https://heroku.com)

2. **Deploy using CLI**:
   ```bash
   heroku create your-app-name
   git add .
   git commit -m "Deploy to Heroku"
   git push heroku main
   ```

3. **Open the app**:
   ```bash
   heroku open
   ```

## Usage

### URL Detection
- Enter a URL in the URL detection tab
- The system analyzes 87 URL-based features including:
  - Domain characteristics
  - URL structure patterns
  - Suspicious keywords
  - Security indicators

### SMS Detection
- Enter SMS text in the SMS detection tab
- The system analyzes text features including:
  - Spam keywords
  - URL presence
  - Phone numbers
  - Urgency indicators
  - Text patterns

### Email Detection
- Enter email content in the Email detection tab
- The system analyzes email features including:
  - Header information
  - Content patterns
  - Spam indicators
  - Suspicious links

## Model Architecture

### URL Phishing Detector
- **Algorithm**: Random Forest Classifier
- **Features**: 87 URL-based features
- **Accuracy**: ~95.2%

### SMS Phishing Detector
- **Algorithm**: Random Forest + TF-IDF Vectorization
- **Features**: Text analysis + 1000 TF-IDF features
- **Accuracy**: ~97.8%

### Email Phishing Detector
- **Algorithm**: Random Forest + TF-IDF Vectorization
- **Features**: Text analysis + 2000 TF-IDF features
- **Accuracy**: ~94.5%

## API Endpoints

- `GET /`: Main application interface
- `POST /detect_url`: URL phishing detection
- `POST /detect_sms`: SMS phishing detection
- `POST /detect_email`: Email phishing detection
- `GET /dashboard`: Model performance dashboard

## Example API Usage

### URL Detection
```bash
curl -X POST http://localhost:5000/detect_url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### SMS Detection
```bash
curl -X POST http://localhost:5000/detect_sms \
  -H "Content-Type: application/json" \
  -d '{"sms_text": "Free entry in 2 a wkly comp to win FA Cup final tkts"}'
```

### Email Detection
```bash
curl -X POST http://localhost:5000/detect_email \
  -H "Content-Type: application/json" \
  -d '{"email_text": "Subject: Urgent: Your account has been compromised..."}'
```

## Project Structure

```
Phishing_Detector_App/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # Project documentation
├── render.yaml           # Render deployment config
├── railway.json          # Railway deployment config
├── Procfile              # Heroku deployment config
├── runtime.txt           # Python runtime version
├── models/               # Machine learning models
│   ├── __init__.py
│   ├── url_model.py      # URL phishing detector
│   ├── sms_model.py      # SMS phishing detector
│   └── email_model.py    # Email phishing detector
├── templates/            # HTML templates
│   ├── index.html        # Main application interface
│   └── dashboard.html    # Performance dashboard
├── dataset_phishing.csv  # URL phishing dataset
├── SMSSpamCollection     # SMS spam dataset
└── spam_assassin.csv     # Email spam dataset
```

## Model Training

The models are automatically trained when the application starts for the first time. The trained models are saved as pickle files in the `models/` directory:

- `url_model.pkl` and `url_scaler.pkl`
- `sms_model.pkl`, `sms_vectorizer.pkl`, and `sms_scaler.pkl`
- `email_model.pkl`, `email_vectorizer.pkl`, and `email_scaler.pkl`

## Performance Metrics

The application provides real-time performance metrics through the dashboard:

- Detection accuracy for each model
- Total detections processed
- Feature analysis breakdown
- Confidence scores for predictions

## Security Features

- Input validation and sanitization
- Error handling for malformed inputs
- Secure model loading and prediction
- Rate limiting considerations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Dataset sources: Various public datasets from Kaggle and research repositories
- Machine learning libraries: scikit-learn, pandas, numpy
- Web framework: Flask
- Frontend: Bootstrap, Font Awesome, Plotly

## Support

For issues and questions, please create an issue in the repository or contact the development team. 