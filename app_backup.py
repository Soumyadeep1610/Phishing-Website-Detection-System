from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
import pickle
import re
import warnings
import os
import json
from urllib.parse import urlparse
from datetime import datetime
from models import db, URLCheck, Feedback, User
import requests
import whois
from virustotal_python import Virustotal
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

warnings.filterwarnings('ignore')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key_here'  # Add a secret key for sessions

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

mail = Mail(app)
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# VirusTotal API setup (optional, requires VT_API_KEY env var)
VT_API_KEY = os.getenv('VT_API_KEY')
vt_client = Virustotal(API_KEY=VT_API_KEY) if VT_API_KEY else None

vector = pickle.load(open("vectorizer.pkl", 'rb'))
model_lr = pickle.load(open("phishing.pkl", 'rb'))  # Logistic Regression
model_mnb = pickle.load(open("phishing_mnb.pkl", 'rb'))  # Multinomial Naive Bayes

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def check_ssl_validity(url):
    try:
        response = requests.get(url, timeout=10, verify=True)
        return True
    except requests.exceptions.SSLError:
        return False
    except:
        return None  # Unable to check

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age_days = (datetime.now() - creation_date).days
            return age_days
        return None
    except:
        return None

def check_virustotal(url):
    if not vt_client:
        return None
    try:
        resp = vt_client.request("urls", data={"url": url})
        url_id = resp.data["id"]
        analysis_resp = vt_client.get_object("/analyses/{}", url_id)
        stats = analysis_resp.data["attributes"]["stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
    except:
        return None

def get_prediction_details(cleaned_url, full_url, enable_advanced=False, enable_vt=False):
    vectorized = vector.transform([cleaned_url])

    # Get predictions from both models
    prediction_lr = model_lr.predict(vectorized)[0]
    probabilities_lr = model_lr.predict_proba(vectorized)[0]
    confidence_lr = max(probabilities_lr) * 100

    prediction_mnb = model_mnb.predict(vectorized)[0]
    probabilities_mnb = model_mnb.predict_proba(vectorized)[0]
    confidence_mnb = max(probabilities_mnb) * 100

    # Ensemble: Use majority vote or average confidence
    if prediction_lr == prediction_mnb:
        prediction = prediction_lr
        confidence = (confidence_lr + confidence_mnb) / 2
    else:
        # If models disagree, choose the one with higher confidence
        if confidence_lr > confidence_mnb:
            prediction = prediction_lr
            confidence = confidence_lr
        else:
            prediction = prediction_mnb
            confidence = confidence_mnb

    reasons = []
    if len(cleaned_url) > 50:
        reasons.append("URL is unusually long")
    if any(keyword in cleaned_url.lower() for keyword in ['login', 'bank', 'password', 'secure']):
        reasons.append("Contains suspicious keywords")
    if cleaned_url.count('.') > 3:
        reasons.append("Too many subdomains")

    # Advanced checks
    ssl_valid = None
    domain_age = None
    vt_report = None
    if enable_advanced:
        ssl_valid = check_ssl_validity(full_url)
        if ssl_valid is False:
            reasons.append("Invalid SSL certificate")
        try:
            domain = urlparse(full_url).netloc
            domain_age = get_domain_age(domain)
            if domain_age and domain_age < 30:
                reasons.append("Domain is very new (<30 days)")
        except:
            pass
    if enable_vt:
        vt_report = check_virustotal(full_url)
        if vt_report and vt_report.get("malicious", 0) > 0:
            reasons.append(f"VirusTotal reports {vt_report['malicious']} malicious detections")

    return prediction, confidence, reasons, ssl_valid, domain_age, vt_report

@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    if request.method == "POST":
        urls_input = request.form['url'].strip()
        enable_advanced = 'enable_advanced' in request.form
        enable_vt = 'enable_vt' in request.form

        # Split by newlines and filter out empty lines
        urls = [url.strip() for url in urls_input.split('\n') if url.strip()]

        if not urls:
            return render_template("index.html", error="Please enter at least one URL.")

        results = []
        session_check_ids = []

        for url in urls:
            if not is_valid_url(url):
                results.append({
                    'url': url,
                    'error': "Invalid URL format. Please enter a valid URL."
                })
                continue

            cleaned_url = re.sub(r'^https?://(www\.)?', '', url)

            prediction, confidence, reasons, ssl_valid, domain_age, vt_report = get_prediction_details(cleaned_url, url, enable_advanced, enable_vt)

            if prediction == 'bad':
                result = f"This is a Phishing website !! (Confidence: {confidence:.1f}%)"
            elif prediction == 'good':
                result = f"This is a healthy and good website !! (Confidence: {confidence:.1f}%)"
            else:
                result = "Something went wrong !!"

            # Store in DB
            url_check = URLCheck(url=url, prediction=prediction, confidence=confidence, ssl_valid=ssl_valid, domain_age_days=domain_age, vt_positives=vt_report.get('malicious', 0) if vt_report else None, user_id=current_user.id if current_user.is_authenticated else None)
            db.session.add(url_check)
            db.session.commit()

            session_check_ids.append(url_check.id)

            results.append({
                'url': url,
                'prediction': prediction,
                'confidence': confidence,
                'result': result,
                'reasons': reasons,
                'ssl_valid': ssl_valid,
                'domain_age': domain_age,
                'vt_report': vt_report,
                'url_check_id': url_check.id
            })

        # Add all check IDs to session
        if 'session_checks' not in session:
            session['session_checks'] = []
        session['session_checks'].extend(session_check_ids)
        session.modified = True

        return render_template("index.html", results=results)
    else:
        return render_template("index.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('login.html', action='register')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.')
    return render_template('login.html', action='login')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/feedback/<int:url_check_id>/<feedback_type>", methods=['POST'])
@login_required
def submit_feedback(url_check_id, feedback_type):
    feedback = Feedback(url_check_id=url_check_id, feedback_type=feedback_type)
    db.session.add(feedback)
    db.session.commit()

    # Send thank you email if mail is configured
    if app.config.get('MAIL_USERNAME') and app.config.get('MAIL_PASSWORD') and current_user.email:
        try:
            msg = Message(
                'Thank you for your feedback - PhishGuard',
                recipients=[current_user.email]
            )
            msg.body = f"""
Dear {current_user.username},

Thank you for providing feedback on our URL analysis!

Your feedback helps us improve our phishing detection system.

Details:
- Feedback Type: {feedback_type.replace('_', ' ').title()}
- URL Check ID: {url_check_id}

We appreciate your contribution to making the internet safer!

Best regards,
PhishGuard Team
            """
            mail.send(msg)
            print(f"Email sent successfully to {current_user.email}")
        except Exception as e:
            print(f"Failed to send feedback email to {current_user.email}: {e}")
            flash('Feedback submitted successfully, but email notification failed.', 'warning')
    else:
        print(f"Email not configured or user email missing. MAIL_USERNAME: {app.config.get('MAIL_USERNAME')}, MAIL_PASSWORD: {'*' * len(app.config.get('MAIL_PASSWORD', ''))}, user_email: {current_user.email}")

    flash('Feedback submitted successfully!', 'success')
    return redirect(url_for('index'))

@app.route("/history")
@login_required
def history():
    checks = URLCheck.query.filter_by(user_id=current_user.id).order_by(URLCheck.timestamp.desc()).limit(20).all()
    return render_template("history.html", checks=checks)

@app.route("/dashboard")
@login_required
def dashboard():
    all_checks = URLCheck.query.filter_by(user_id=current_user.id).order_by(URLCheck.timestamp.desc()).all()
    total_checks = len(all_checks)
    phishing_checks = sum(1 for check in all_checks if check.prediction == 'bad')
    safe_checks = sum(1 for check in all_checks if check.prediction == 'good')

    return render_template("dashboard.html",
                         total_checks=total_checks,
                         phishing_checks=phishing_checks,
                         safe_checks=safe_checks,
                         all_checks=all_checks)

@app.route("/api/checks")
@login_required
def api_checks():
    checks = URLCheck.query.filter_by(user_id=current_user.id).order_by(URLCheck.timestamp.desc()).all()
    checks_data = []
    for check in checks:
        checks_data.append({
            'id': check.id,
            'url': check.url,
            'prediction': check.prediction,
            'confidence': float(check.confidence),
            'timestamp': check.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'ssl_valid': check.ssl_valid,
            'domain_age_days': check.domain_age_days,
            'vt_positives': check.vt_positives
        })
    return jsonify({'checks': checks_data})

@app.route("/learn")
def learn():
    return render_template("learn.html")

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/delete_account", methods=['POST'])
@login_required
def delete_account():
    # Get all URLCheck IDs for the user
    url_check_ids = [check.id for check in URLCheck.query.filter_by(user_id=current_user.id).all()]

    # Delete associated Feedback records first
    if url_check_ids:
        Feedback.query.filter(Feedback.url_check_id.in_(url_check_ids)).delete()

    # Delete associated URLCheck records
    URLCheck.query.filter_by(user_id=current_user.id).delete()

    # Delete the user
    db.session.delete(current_user)
    db.session.commit()

    # Log out the user
    logout_user()

    flash('Your account has been deleted successfully.')
    return redirect(url_for('index'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
