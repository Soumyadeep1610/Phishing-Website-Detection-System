from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    url_checks = db.relationship('URLCheck', backref='user', lazy=True)

    def __repr__(self):
        return f"<User {self.username} ({self.email})>"

class URLCheck(db.Model):
    __tablename__ = 'url_check'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    prediction = db.Column(db.String(10), nullable=False)  # 'good' or 'bad'
    confidence = db.Column(db.Float, nullable=True)
    ssl_valid = db.Column(db.Boolean, nullable=True)  # SSL certificate validity
    domain_age_days = db.Column(db.Integer, nullable=True)  # Domain age in days
    vt_positives = db.Column(db.Integer, nullable=True)  # VirusTotal positives
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign key
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Relationships
    feedbacks = db.relationship('Feedback', backref='url_check', lazy=True)

    def __repr__(self):
        return f"<URLCheck {self.url} - {self.prediction}>"

class Feedback(db.Model):
    __tablename__ = 'feedback'

    id = db.Column(db.Integer, primary_key=True)
    url_check_id = db.Column(db.Integer, db.ForeignKey('url_check.id'), nullable=False)
    feedback_type = db.Column(db.String(20), nullable=False)  # 'false_positive' or 'false_negative'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Feedback URLCheckID:{self.url_check_id} Type:{self.feedback_type}>"
