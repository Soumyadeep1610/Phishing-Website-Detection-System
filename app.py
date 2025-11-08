from flask import Flask, render_template, request, redirect, url_for, flash
import pickle
import re
import warnings
import os
from urllib.parse import urlparse
from datetime import datetime
from models import db, URLCheck, Feedback, User
import requests
import whois
from virustotal_python import Virustotal
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail

warnings.filterwarnings('ignore')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.secret_key = os.getenv('FLASK_SECRET', 'your_secret_key_here')

# Email config (optional)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
mail = Mail(app)

# Initialize database
db.init_app(app)

# Login manager setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# VirusTotal API setup
VT_API_KEY = os.getenv('VT_API_KEY')
vt_client = None
if VT_API_KEY:
    try:
        vt_client = Virustotal(API_KEY=VT_API_KEY)
    except Exception as e:
        app.logger.warning(f"VirusTotal client init failed: {e}")

# Load vectorizer and ML models
try:
    vector = pickle.load(open("vectorizer.pkl", 'rb'))
except Exception:
    vector = None

def _load_first_existing(file_list):
    for fname in file_list:
        if os.path.exists(fname):
            try:
                return pickle.load(open(fname, 'rb'))
            except Exception:
                continue
    return None

model_lr = _load_first_existing(["phishing_lr.pkl", "phishing.pkl"])
model_mnb = _load_first_existing(["phishing_mnb.pkl", "phishing_nb.pkl"])

# ---------------- Helper functions ----------------
def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def check_ssl_validity(url):
    try:
        r = requests.get(url, timeout=8, verify=True)
        return True
    except requests.exceptions.SSLError:
        return False
    except requests.exceptions.RequestException:
        return None

def get_domain_age(domain):
    try:
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
    if not vt_client:
        return None
    try:
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
    except Exception:
        return None

def get_prediction_details(cleaned_url, full_url, enable_advanced=False, enable_vt=False):
    if vector is None or model_lr is None or model_mnb is None:
        return "unknown", 0.0, ["Model or vectorizer not loaded"], None, None, None

    try:
        vectorized = vector.transform([cleaned_url])
    except Exception:
        return "unknown", 0.0, ["Failed to vectorize URL"], None, None, None

    try:
        pred_lr = model_lr.predict(vectorized)[0]
        conf_lr = max(model_lr.predict_proba(vectorized)[0]) * 100
    except Exception:
        pred_lr, conf_lr = None, 0.0

    try:
        pred_mnb = model_mnb.predict(vectorized)[0]
        conf_mnb = max(model_mnb.predict_proba(vectorized)[0]) * 100
    except Exception:
        pred_mnb, conf_mnb = None, 0.0

    def label_to_str(l):
        if l is None: return "unknown"
        return "bad" if int(l) == 1 else "good" if isinstance(l, (int, float)) else str(l)

    preds = [label_to_str(p) for p in [pred_lr, pred_mnb] if label_to_str(p) != "unknown"]
    if not preds:
        prediction, confidence = "unknown", 0.0
    elif len(preds) == 1:
        prediction, confidence = preds[0], conf_lr if label_to_str(pred_lr) != "unknown" else conf_mnb
    else:
        if preds[0] == preds[1]:
            prediction, confidence = preds[0], (conf_lr + conf_mnb)/2
        else:
            if conf_lr >= conf_mnb:
                prediction, confidence = preds[0], conf_lr
            else:
                prediction, confidence = preds[1], conf_mnb

    reasons = []
    if len(cleaned_url) > 50: reasons.append("URL is unusually long")
    if any(k in cleaned_url.lower() for k in ['login','bank','password','secure']):
        reasons.append("Contains suspicious keywords")
    if cleaned_url.count('.') > 3: reasons.append("Too many subdomains")

    ssl_valid, domain_age, vt_report = None, None, None

    if enable_advanced:
        ssl_valid = check_ssl_validity(full_url)
        if ssl_valid is False: reasons.append("Invalid SSL certificate")
        domain = urlparse(full_url).netloc
        domain_age = get_domain_age(domain)
        if domain_age is not None and domain_age < 30: reasons.append("Domain is very new (<30 days)")

    if enable_vt:
        vt_report = check_virustotal(full_url)
        if vt_report and vt_report.get("malicious",0) > 0:
            reasons.append(f"VirusTotal reports {vt_report['malicious']} malicious detections")

    return prediction, confidence, reasons, ssl_valid, domain_age, vt_report

# ---------------- Routes ----------------
@app.route("/", methods=['GET','POST'])
@login_required
def index():
    if request.method == "POST":
        urls_input = request.form.get('url','').strip()
        enable_advanced = 'enable_advanced' in request.form
        enable_vt = 'enable_vt' in request.form
        urls = [u.strip() for u in urls_input.split('\n') if u.strip()]
        results = []

        for url in urls:
            if not is_valid_url(url):
                results.append({'url': url, 'error': "Invalid URL format."})
                continue
            cleaned_url = re.sub(r'^https?://(www\.)?', '', url, flags=re.IGNORECASE)
            prediction, confidence, reasons, ssl_valid, domain_age, vt_report = get_prediction_details(cleaned_url, url, enable_advanced, enable_vt)

            result_text = f"⚠️ Unable to classify the website."
            if prediction == 'bad': result_text = f"🚨 Phishing! Confidence: {confidence:.1f}%"
            elif prediction == 'good': result_text = f"✅ Safe! Confidence: {confidence:.1f}%"

            try:
                url_check = URLCheck(
                    url=url,
                    prediction=prediction,
                    confidence=confidence,
                    ssl_valid=ssl_valid,
                    domain_age_days=domain_age,
                    vt_positives=vt_report.get('malicious',0) if vt_report else None,
                    user=current_user
                )
                db.session.add(url_check)
                db.session.commit()
                url_check_id = url_check.id
            except Exception:
                db.session.rollback()
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

        return render_template("index.html", results=results)
    return render_template("index.html")


# --------------- Register/Login/Logout ----------------
@app.route("/register", methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if not username or not email or not password:
            flash("Please fill all fields.", "warning")
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "warning")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for('login'))
    return render_template("login.html", action='register')


@app.route("/login", methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid email or password.", "danger")
    return render_template("login.html", action='login')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

# ----------------- Dashboard -----------------
@app.route("/dashboard")
@login_required
def dashboard():
    user_checks = current_user.url_checks
    return render_template("dashboard.html", user=current_user, url_checks=user_checks)

# ----------------- Feedback -----------------
@app.route("/feedback/<int:url_check_id>", methods=['POST'])
@login_required
def feedback(url_check_id):
    feedback_type = request.form.get('feedback_type')
    url_check = URLCheck.query.get_or_404(url_check_id)
    new_feedback = Feedback(url_check=url_check, feedback_type=feedback_type)
    db.session.add(new_feedback)
    db.session.commit()
    flash("Feedback submitted. Thank you!", "success")
    return redirect(url_for('dashboard'))

# ----------------- Run App -----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # This will create your tables in PostgreSQL
    app.run(debug=True)

