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
app.secret_key = os.getenv('FLASK_SECRET', 'your_secret_key_here')  # prefer env var

# Email configuration (optional)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

mail = Mail(app)
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

# VirusTotal API setup (optional)
VT_API_KEY = os.getenv('VT_API_KEY')
vt_client = None
if VT_API_KEY:
    try:
        vt_client = Virustotal(API_KEY=VT_API_KEY)
    except Exception as e:
        app.logger.warning(f"VirusTotal client init failed: {e}")
        vt_client = None

# Load vectorizer and models (wrap in try/except to give helpful error)
try:
    vector = pickle.load(open("vectorizer.pkl", 'rb'))
except Exception as e:
    app.logger.error(f"Failed to load vectorizer.pkl: {e}")
    vector = None

# Allowed model filenames — try common names with fallback
_model_files = {
    'lr': ["phishing_lr.pkl", "phishing.pkl"],
    'mnb': ["phishing_mnb.pkl", "phishing_nb.pkl"]
}

def _load_first_existing(file_list):
    for fname in file_list:
        if os.path.exists(fname):
            try:
                return pickle.load(open(fname, 'rb'))
            except Exception as e:
                app.logger.warning(f"Failed to unpickle {fname}: {e}")
    return None

model_lr = _load_first_existing(_model_files['lr'])
model_mnb = _load_first_existing(_model_files['mnb'])

if model_lr is None:
    app.logger.warning("Logistic Regression model not loaded. Make sure phishing_lr.pkl or phishing.pkl exists.")
if model_mnb is None:
    app.logger.warning("MultinomialNB model not loaded. Make sure phishing_mnb.pkl exists.")

# ----------------- Helper functions -----------------
def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def check_ssl_validity(url):
    """Return True if SSL OK, False if SSL error, None if can't check."""
    try:
        # requests verifies SSL by default; set a short timeout
        r = requests.get(url, timeout=8, verify=True)
        return True
    except requests.exceptions.SSLError:
        return False
    except requests.exceptions.RequestException:
        # network error or timeout - can't determine
        return None
    except Exception:
        return None

def get_domain_age(domain):
    """Return domain age in days or None."""
    try:
        # remove port if present
        domain = domain.split(':')[0]
        w = whois.whois(domain)
        creation_date = w.creation_date
        if not creation_date:
            return None
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            return (datetime.now() - creation_date).days
        return None
    except Exception:
        return None

def check_virustotal(url):
    """Return simple summary dict or None if not configured/failed."""
    if not vt_client:
        return None
    try:
        # VirusTotal URL scanning: encode the URL endpoint usage may vary by library version
        resp = vt_client.request("urls", data={"url": url})
        url_id = resp.data.get("id")
        if not url_id:
            return None
        analysis_resp = vt_client.get_object(f"/analyses/{url_id}")
        stats = analysis_resp.data.get("attributes", {}).get("stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
    except Exception as e:
        app.logger.warning(f"VirusTotal check failed: {e}")
        return None

def get_prediction_details(cleaned_url, full_url, enable_advanced=False, enable_vt=False):
    """Return tuple: (prediction_label, confidence_float, reasons_list, ssl_valid_bool_or_none, domain_age_days_or_none, vt_report_or_none)"""
    # basic checks
    if vector is None or model_lr is None or model_mnb is None:
        # if models not loaded, return unknown
        return "unknown", 0.0, ["Model or vectorizer not loaded"], None, None, None

    try:
        vectorized = vector.transform([cleaned_url])
    except Exception as e:
        app.logger.error(f"Vectorization failed for {cleaned_url}: {e}")
        return "unknown", 0.0, ["Failed to vectorize URL"], None, None, None

    try:
        # predictions
        prediction_lr = model_lr.predict(vectorized)[0]
        probs_lr = model_lr.predict_proba(vectorized)[0]
        confidence_lr = max(probs_lr) * 100
    except Exception:
        prediction_lr = None
        confidence_lr = 0.0

    try:
        prediction_mnb = model_mnb.predict(vectorized)[0]
        probs_mnb = model_mnb.predict_proba(vectorized)[0]
        confidence_mnb = max(probs_mnb) * 100
    except Exception:
        prediction_mnb = None
        confidence_mnb = 0.0

    # map numeric labels to strings if needed
    # many saved models use 0/1; handle both numeric and string
    def label_to_str(l):
        if l is None:
            return "unknown"
        if isinstance(l, (int, float)):
            return "bad" if int(l) == 1 else "good"
        if isinstance(l, str):
            return l
        return str(l)

    pred_lr_str = label_to_str(prediction_lr)
    pred_mnb_str = label_to_str(prediction_mnb)

    # ensemble logic: majority vote when available
    preds = [p for p in [pred_lr_str, pred_mnb_str] if p != "unknown"]
    if not preds:
        prediction = "unknown"
        confidence = 0.0
    elif len(preds) == 1:
        prediction = preds[0]
        confidence = confidence_lr if pred_lr_str != "unknown" else confidence_mnb
    else:
        # if both agree -> average confidence; else choose higher confidence
        if pred_lr_str == pred_mnb_str:
            prediction = pred_lr_str
            confidence = (confidence_lr + confidence_mnb) / 2
        else:
            if confidence_lr >= confidence_mnb:
                prediction = pred_lr_str
                confidence = confidence_lr
            else:
                prediction = pred_mnb_str
                confidence = confidence_mnb

    reasons = []
    if len(cleaned_url) > 50:
        reasons.append("URL is unusually long")
    if any(k in cleaned_url.lower() for k in ['login', 'bank', 'password', 'secure']):
        reasons.append("Contains suspicious keywords")
    if cleaned_url.count('.') > 3:
        reasons.append("Too many subdomains")

    ssl_valid = None
    domain_age = None
    vt_report = None

    if enable_advanced:
        try:
            ssl_valid = check_ssl_validity(full_url)
            if ssl_valid is False:
                reasons.append("Invalid SSL certificate")
        except Exception as e:
            app.logger.warning(f"SSL check failed for {full_url}: {e}")
            ssl_valid = None

        try:
            domain = urlparse(full_url).netloc
            domain_age = get_domain_age(domain)
            if domain_age is not None and domain_age < 30:
                reasons.append("Domain is very new (<30 days)")
        except Exception as e:
            app.logger.warning(f"Whois check failed for {full_url}: {e}")
            domain_age = None

    if enable_vt:
        try:
            vt_report = check_virustotal(full_url)
            if vt_report and vt_report.get("malicious", 0) > 0:
                reasons.append(f"VirusTotal reports {vt_report['malicious']} malicious detections")
        except Exception as e:
            app.logger.warning(f"VirusTotal check exception: {e}")
            vt_report = None

    return prediction, confidence, reasons, ssl_valid, domain_age, vt_report

# ----------------- Routes -----------------
@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    if request.method == "POST":
        urls_input = request.form.get('url', '').strip()
        enable_advanced = 'enable_advanced' in request.form
        enable_vt = 'enable_vt' in request.form

        urls = [u.strip() for u in urls_input.split('\n') if u.strip()]
        if not urls:
            flash("Please enter at least one URL.", "warning")
            return render_template("index.html")

        results = []
        session_check_ids = []

        for url in urls:
            if not is_valid_url(url):
                results.append({'url': url, 'error': "Invalid URL format. Please enter a valid URL."})
                continue

            cleaned_url = re.sub(r'^https?://(www\.)?', '', url, flags=re.IGNORECASE)
            prediction, confidence, reasons, ssl_valid, domain_age, vt_report = get_prediction_details(cleaned_url, url, enable_advanced, enable_vt)

            if prediction == 'bad':
                result_text = f"🚨 This is a Phishing website! (Confidence: {confidence:.1f}%)"
            elif prediction == 'good':
                result_text = f"✅ This is a Safe website! (Confidence: {confidence:.1f}%)"
            else:
                result_text = "⚠️ Unable to classify the website."

            try:
                url_check = URLCheck(
                    url=url,
                    prediction=prediction,
                    confidence=confidence,
                    ssl_valid=ssl_valid,
                    domain_age_days=domain_age,
                    vt_positives=vt_report.get('malicious', 0) if vt_report else None,
                    user_id=current_user.id if current_user.is_authenticated else None
                )
                db.session.add(url_check)
                db.session.commit()
                session_check_ids.append(url_check.id)
                url_check_id = url_check.id
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"DB save failed for {url}: {e}")
                url_check_id = None

            results.append({
                'url': url,
                'prediction': prediction,
                'confidence': confidence,
                'result': result_text,
                'reasons': reasons,
                'ssl_valid': ssl_valid,
                'domain_age': domain_age,
                'vt_report': vt_report,
                'url_check_id': url_check_id
            })

        # store in session
        session.setdefault('session_checks', [])
        session['session_checks'].extend([i for i in session_check_ids if i])
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
        if not username or not email or not password:
            flash('Please provide username, email and password.', 'warning')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'warning')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
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
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
        return render_template('login.html', action='login')
    else:
        return render_template('login.html', action='login')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route("/feedback/<int:url_check_id>/<feedback_type>", methods=['POST'])
@login_required
def submit_feedback(url_check_id, feedback_type):
    try:
        # Save feedback to DB
        fb = Feedback(url_check_id=url_check_id, feedback_type=feedback_type, user_id=current_user.id)
        db.session.add(fb)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to save feedback: {e}")
        flash('Failed to save feedback.', 'danger')
        return redirect(url_for('index'))

    # Send email to user if mail configured
    if app.config.get('MAIL_USERNAME') and app.config.get('MAIL_PASSWORD') and current_user.email:
        try:
            msg = Message(
                subject='Thank you for your feedback - PhishGuard',
                recipients=[current_user.email]
            )
            msg.body = f"""
Dear {current_user.username},

Thank you for providing feedback on our URL analysis!

Details:
- Feedback Type: {feedback_type.replace('_', ' ').title()}
- URL Check ID: {url_check_id}

Your feedback helps us improve our phishing detection system.

Best regards,
PhishGuard Team
"""
            mail.send(msg)
        except Exception as e:
            app.logger.warning(f"Failed to send feedback email: {e}")
            flash('Feedback submitted, but email notification failed.', 'warning')
    else:
        app.logger.info("Mail not configured or user email missing; skipping email send.")

    flash('Feedback submitted successfully!', 'success')
    return redirect(url_for('index'))


@app.route("/history")
@login_required
def history():
    checks = URLCheck.query.filter_by(user_id=current_user.id).order_by(URLCheck.timestamp.desc()).limit(50).all()
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
            'confidence': float(check.confidence) if check.confidence is not None else None,
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
    try:
        # Collect user checks and delete feedback then checks then user
        url_check_ids = [c.id for c in URLCheck.query.filter_by(user_id=current_user.id).all()]
        if url_check_ids:
            Feedback.query.filter(Feedback.url_check_id.in_(url_check_ids)).delete(synchronize_session=False)
            URLCheck.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash('Your account has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to delete account: {e}")
        flash('Failed to delete account.', 'danger')
    return redirect(url_for('index'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
