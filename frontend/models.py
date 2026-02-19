from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), nullable=False)
    status = db.Column(db.String(20), default='offline')  # online, offline
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

class FileLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(500), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)

    agent = db.relationship('Agent', backref=db.backref('files', lazy=True))


class DeletionAuditLog(db.Model):
    __tablename__ = "deletion_audit_log"

    id = db.Column(db.Integer, primary_key=True)
    record_id = db.Column(db.String(255), nullable=False, index=True)
    task_id = db.Column(db.String(100), nullable=True, index=True)
    agent_ip = db.Column(db.String(64), nullable=True, index=True)
    file_hash = db.Column(db.String(128), nullable=True, index=True)
    filename = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(1000), nullable=False)
    language = db.Column(db.String(64), nullable=True)
    confidence = db.Column(db.Float, nullable=True)
    action = db.Column(db.String(64), nullable=False)  # approved, rejected, delete_dispatched
    action_by = db.Column(db.String(128), nullable=False, default="admin-ui")
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
