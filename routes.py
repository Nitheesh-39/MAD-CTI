"""
Flask Routes - Authentication, Main, Admin, and API endpoints
"""

import os
import json
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
import pandas as pd

from models import db, User, DataUpload, ThreatRecord, AnalysisReport, SystemLog
from agents import MultiAgentOrchestrator
from utils import allowed_file, generate_sample_csv, get_analytics_data

# Blueprints
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
main_bp = Blueprint('main', __name__)
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
api_bp = Blueprint('api', __name__, url_prefix='/api')


# ============================================================================
# Authentication Routes
# ============================================================================

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'danger')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('auth/register.html')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('auth/register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('auth/register.html')
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Log activity
        log = SystemLog(user_id=user.id, action='user_registered', 
                       details=f'New user registered: {username}',
                       ip_address=request.remote_addr)
        db.session.add(log)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log activity
            log = SystemLog(user_id=user.id, action='user_login',
                          details=f'User logged in: {username}',
                          ip_address=request.remote_addr)
            db.session.add(log)
            db.session.commit()
            
            flash(f'Welcome back, {user.username}!', 'success')
            
            # Redirect to admin dashboard if admin
            if user.is_admin:
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('main.dashboard'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    # Log activity
    log = SystemLog(user_id=current_user.id, action='user_logout',
                   details=f'User logged out: {current_user.username}',
                   ip_address=request.remote_addr)
    db.session.add(log)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))


# ============================================================================
# Main User Routes
# ============================================================================

@main_bp.route('/')
def index():
    """Landing page"""
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('main.dashboard'))
    return render_template('index.html')


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    # Get user's uploads
    uploads = DataUpload.query.filter_by(user_id=current_user.id).order_by(DataUpload.upload_date.desc()).all()
    
    # Get statistics
    total_uploads = len(uploads)
    total_records = sum(upload.row_count or 0 for upload in uploads)
    
    # Get recent threat records
    recent_threats = ThreatRecord.query.join(DataUpload).filter(
        DataUpload.user_id == current_user.id
    ).order_by(ThreatRecord.processed_at.desc()).limit(10).all()
    
    return render_template('dashboard.html', 
                         uploads=uploads,
                         total_uploads=total_uploads,
                         total_records=total_records,
                         recent_threats=recent_threats)


@main_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """CSV file upload"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            filepath = os.path.join('uploads', unique_filename)
            
            # Save file
            file.save(filepath)
            
            # Get file info
            file_size = os.path.getsize(filepath)
            
            # Read CSV to get row/column count
            try:
                df = pd.read_csv(filepath)
                row_count = len(df)
                column_count = len(df.columns)
            except Exception as e:
                flash(f'Error reading CSV file: {str(e)}', 'danger')
                os.remove(filepath)
                return redirect(request.url)
            
            # Create upload record
            upload = DataUpload(
                user_id=current_user.id,
                filename=unique_filename,
                original_filename=filename,
                file_path=filepath,
                file_size=file_size,
                row_count=row_count,
                column_count=column_count,
                processing_status='pending'
            )
            db.session.add(upload)
            db.session.commit()
            
            # Log activity
            log = SystemLog(user_id=current_user.id, action='csv_upload',
                          details=f'Uploaded file: {filename} ({row_count} rows)',
                          ip_address=request.remote_addr)
            db.session.add(log)
            db.session.commit()
            
            flash(f'File uploaded successfully! {row_count} records ready for processing.', 'success')
            return redirect(url_for('main.process_upload', upload_id=upload.id))
        
        flash('Invalid file type. Please upload a CSV file.', 'danger')
    
    return render_template('upload.html')


@main_bp.route('/process/<int:upload_id>')
@login_required
def process_upload(upload_id):
    """Process uploaded CSV file through multi-agent system"""
    upload = DataUpload.query.get_or_404(upload_id)
    
    # Check ownership
    if upload.user_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Check if already processed
    if upload.processing_status == 'completed':
        flash('This file has already been processed', 'info')
        return redirect(url_for('main.view_results', upload_id=upload_id))
    
    # Update status
    upload.processing_status = 'processing'
    db.session.commit()
    
    try:
        # Read CSV
        df = pd.read_csv(upload.file_path)
        
        # Initialize multi-agent orchestrator
        orchestrator = MultiAgentOrchestrator()
        
        # Process each record
        processed_count = 0
        for idx, row in df.iterrows():
            # Get text content (assuming there's a 'text' or 'content' column)
            text = ''
            if 'text' in df.columns:
                text = str(row['text'])
            elif 'content' in df.columns:
                text = str(row['content'])
            elif 'message' in df.columns:
                text = str(row['message'])
            else:
                # Concatenate all columns
                text = ' '.join(str(val) for val in row.values)
            
            # Process through agents
            results = orchestrator.process_record(text, record_id=idx)
            
            # Create threat record
            threat_record = ThreatRecord(
                upload_id=upload.id,
                raw_text=text[:5000],  # Limit text length
                threat_type=results['classification']['primary_category'],
                confidence_score=results['classification']['primary_confidence'],
                sentiment_score=results['nlp_analysis'].get('sentiment', 0.0),
                severity_level=results['scores']['severity_level']
            )
            
            # Store entities
            threat_record.set_entities(results['nlp_analysis'].get('entities', {}))
            threat_record.set_keywords(results['nlp_analysis'].get('keywords', []))
            threat_record.set_ioc_data(results['iocs'])
            
            db.session.add(threat_record)
            processed_count += 1
            
            # Commit in batches
            if processed_count % 10 == 0:
                db.session.commit()
        
        # Final commit
        db.session.commit()
        
        # Update upload status
        upload.processing_status = 'completed'
        db.session.commit()
        
        # Create analysis report
        create_analysis_report(upload.id)
        
        # Log activity
        log = SystemLog(user_id=current_user.id, action='data_processed',
                       details=f'Processed {processed_count} records from {upload.original_filename}',
                       ip_address=request.remote_addr)
        db.session.add(log)
        db.session.commit()
        
        flash(f'Successfully processed {processed_count} records!', 'success')
        return redirect(url_for('main.view_results', upload_id=upload_id))
        
    except Exception as e:
        upload.processing_status = 'failed'
        db.session.commit()
        flash(f'Error processing file: {str(e)}', 'danger')
        return redirect(url_for('main.dashboard'))


@main_bp.route('/results/<int:upload_id>')
@login_required
def view_results(upload_id):
    """View analysis results"""
    upload = DataUpload.query.get_or_404(upload_id)
    
    # Check ownership
    if upload.user_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Get threat records
    threats = ThreatRecord.query.filter_by(upload_id=upload_id).all()
    
    # Get analysis report
    report = AnalysisReport.query.filter_by(upload_id=upload_id).first()
    
    # Calculate statistics
    stats = {
        'total': len(threats),
        'hack': sum(1 for t in threats if t.threat_type == 'hack'),
        'malware': sum(1 for t in threats if t.threat_type == 'malware'),
        'vulnerability': sum(1 for t in threats if t.threat_type == 'vulnerability'),
        'critical': sum(1 for t in threats if t.severity_level == 'critical'),
        'high': sum(1 for t in threats if t.severity_level == 'high'),
        'medium': sum(1 for t in threats if t.severity_level == 'medium'),
        'low': sum(1 for t in threats if t.severity_level == 'low'),
    }
    
    return render_template('results.html', 
                         upload=upload,
                         threats=threats,
                         report=report,
                         stats=stats)


# ============================================================================
# Admin Routes
# ============================================================================

@admin_bp.route('/dashboard')
@login_required
def dashboard():
    """Admin dashboard"""
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Get all users
    users = User.query.all()
    
    # Get all uploads
    uploads = DataUpload.query.order_by(DataUpload.upload_date.desc()).all()
    
    # Get all threat records
    threats = ThreatRecord.query.all()
    
    # Calculate statistics
    stats = {
        'total_users': len(users),
        'total_uploads': len(uploads),
        'total_threats': len(threats),
        'hack_count': sum(1 for t in threats if t.threat_type == 'hack'),
        'malware_count': sum(1 for t in threats if t.threat_type == 'malware'),
        'vulnerability_count': sum(1 for t in threats if t.threat_type == 'vulnerability'),
        'critical_count': sum(1 for t in threats if t.severity_level == 'critical'),
    }
    
    # Get recent activity logs
    recent_logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(20).all()
    
    return render_template('admin/dashboard.html',
                         users=users,
                         uploads=uploads,
                         stats=stats,
                         recent_logs=recent_logs)


@admin_bp.route('/users')
@login_required
def users():
    """User management"""
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.dashboard'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users, now=datetime.utcnow())


@admin_bp.route('/reports')
@login_required
def reports():
    """System reports"""
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Get all analysis reports
    reports = AnalysisReport.query.order_by(AnalysisReport.generated_at.desc()).all()
    
    return render_template('admin/reports.html', reports=reports)


@admin_bp.route('/analytics')
@login_required
def analytics():
    """Analytics and visualizations"""
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.dashboard'))
    
    return render_template('admin/analytics.html')


# ============================================================================
# API Routes
# ============================================================================

@api_bp.route('/analytics/data')
@login_required
def analytics_data():
    """Get analytics data for charts"""
    data = get_analytics_data()
    return jsonify(data)


@api_bp.route('/threat/<int:threat_id>')
@login_required
def get_threat(threat_id):
    """Get detailed threat information"""
    threat = ThreatRecord.query.get_or_404(threat_id)
    
    # Check access
    if not current_user.is_admin and threat.upload.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = {
        'id': threat.id,
        'threat_type': threat.threat_type,
        'confidence_score': threat.confidence_score,
        'severity_level': threat.severity_level,
        'entities': threat.get_entities(),
        'keywords': threat.get_keywords(),
        'iocs': threat.get_ioc_data(),
        'sentiment_score': threat.sentiment_score,
        'processed_at': threat.processed_at.isoformat() if threat.processed_at else None
    }
    
    return jsonify(data)


@api_bp.route('/download/sample-csv')
def download_sample_csv():
    """Download sample CSV file"""
    filepath = generate_sample_csv()
    return send_file(filepath, as_attachment=True, download_name='sample_threat_data.csv')


# ============================================================================
# Helper Functions
# ============================================================================

def create_analysis_report(upload_id):
    """Create analysis report for an upload"""
    upload = DataUpload.query.get(upload_id)
    threats = ThreatRecord.query.filter_by(upload_id=upload_id).all()
    
    # Calculate statistics
    total_records = len(threats)
    hack_count = sum(1 for t in threats if t.threat_type == 'hack')
    malware_count = sum(1 for t in threats if t.threat_type == 'malware')
    vulnerability_count = sum(1 for t in threats if t.threat_type == 'vulnerability')
    
    # Create graph data
    graph_data = {
        'threat_distribution': {
            'hack': hack_count,
            'malware': malware_count,
            'vulnerability': vulnerability_count
        },
        'severity_distribution': {
            'critical': sum(1 for t in threats if t.severity_level == 'critical'),
            'high': sum(1 for t in threats if t.severity_level == 'high'),
            'medium': sum(1 for t in threats if t.severity_level == 'medium'),
            'low': sum(1 for t in threats if t.severity_level == 'low')
        }
    }
    
    # Create report
    report = AnalysisReport(
        upload_id=upload_id,
        report_type='classification',
        total_records=total_records,
        hack_count=hack_count,
        malware_count=malware_count,
        vulnerability_count=vulnerability_count,
        summary=f"Analyzed {total_records} threat records: {hack_count} hacks, {malware_count} malware, {vulnerability_count} vulnerabilities"
    )
    report.set_graph_data(graph_data)
    
    db.session.add(report)
    db.session.commit()
    
    return report
