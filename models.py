from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    uploads = db.relationship('DataUpload', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class DataUpload(db.Model):
    """Model for tracking CSV uploads"""
    __tablename__ = 'data_uploads'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    row_count = db.Column(db.Integer)
    column_count = db.Column(db.Integer)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    processing_status = db.Column(db.String(50), default='pending')  # pending, processing, completed, failed
    
    # Relationships
    records = db.relationship('ThreatRecord', backref='upload', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<DataUpload {self.original_filename}>'


class ThreatRecord(db.Model):
    """Model for individual threat intelligence records"""
    __tablename__ = 'threat_records'
    
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('data_uploads.id'), nullable=False)
    
    # Original data
    raw_text = db.Column(db.Text)
    source_url = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime)
    
    # Classification results
    threat_type = db.Column(db.String(50))  # hack, malware, vulnerability
    confidence_score = db.Column(db.Float)
    
    # NLP Analysis
    entities = db.Column(db.Text)  # JSON string of extracted entities
    keywords = db.Column(db.Text)  # JSON string of keywords
    sentiment_score = db.Column(db.Float)
    
    # Enrichment data
    ioc_data = db.Column(db.Text)  # JSON string of IOCs (IPs, domains, hashes, etc.)
    severity_level = db.Column(db.String(20))  # low, medium, high, critical
    
    # Graph data
    graph_node_id = db.Column(db.String(100))
    related_records = db.Column(db.Text)  # JSON string of related record IDs
    
    # Metadata
    processed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_entities(self, entities_dict):
        """Store entities as JSON"""
        self.entities = json.dumps(entities_dict)
    
    def get_entities(self):
        """Retrieve entities from JSON"""
        return json.loads(self.entities) if self.entities else {}
    
    def set_keywords(self, keywords_list):
        """Store keywords as JSON"""
        self.keywords = json.dumps(keywords_list)
    
    def get_keywords(self):
        """Retrieve keywords from JSON"""
        return json.loads(self.keywords) if self.keywords else []
    
    def set_ioc_data(self, ioc_dict):
        """Store IOC data as JSON"""
        self.ioc_data = json.dumps(ioc_dict)
    
    def get_ioc_data(self):
        """Retrieve IOC data from JSON"""
        return json.loads(self.ioc_data) if self.ioc_data else {}
    
    def __repr__(self):
        return f'<ThreatRecord {self.id} - {self.threat_type}>'


class AnalysisReport(db.Model):
    """Model for storing analysis reports"""
    __tablename__ = 'analysis_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('data_uploads.id'))
    report_type = db.Column(db.String(50))  # classification, graph, system
    
    # Statistics
    total_records = db.Column(db.Integer)
    hack_count = db.Column(db.Integer, default=0)
    malware_count = db.Column(db.Integer, default=0)
    vulnerability_count = db.Column(db.Integer, default=0)
    
    # Graph metrics
    graph_data = db.Column(db.Text)  # JSON string of graph visualization data
    
    # Report metadata
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    summary = db.Column(db.Text)
    
    def set_graph_data(self, graph_dict):
        """Store graph data as JSON"""
        self.graph_data = json.dumps(graph_dict)
    
    def get_graph_data(self):
        """Retrieve graph data from JSON"""
        return json.loads(self.graph_data) if self.graph_data else {}
    
    def __repr__(self):
        return f'<AnalysisReport {self.id} - {self.report_type}>'


class SystemLog(db.Model):
    """Model for system activity logs"""
    __tablename__ = 'system_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<SystemLog {self.action} at {self.timestamp}>'
