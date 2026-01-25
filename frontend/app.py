from flask import Flask, request, jsonify, render_template, flash, redirect, url_for
from models import db, Agent, FileLog
from datetime import datetime
import logging
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
db.init_app(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Mock data generator
def generate_mock_data():
    with app.app_context():
        # Drop all tables and recreate to handle schema changes
        db.drop_all()
        db.create_all()
        
        # Add mock agents
        agents = [
            Agent(ip='192.168.1.10', status='online'),
            Agent(ip='192.168.1.11', status='online'),
            Agent(ip='192.168.1.12', status='offline'),
        ]
        try:
            db.session.add_all(agents)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding agents: {e}")

        # Add mock file logs
        files = [
            FileLog(filename='matlab_script.m', path='/home/user/documents/matlab_script.m', agent_id=1, status='pending'),
            FileLog(filename='data.mat', path='/home/user/data/data.mat', agent_id=1, status='pending'),
            FileLog(filename='report.pdf', path='/home/user/reports/report.pdf', agent_id=2, status='pending'),
            FileLog(filename='temp.txt', path='/tmp/temp.txt', agent_id=2, status='pending'),
        ]
        try:
            db.session.add_all(files)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding files: {e}")

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/verification')
def verification():
    return render_template('verification.html')

@app.route('/submit-instruction', methods=['POST'])
def submit_instruction():
    try:
        data = request.get_json()
        if not data or 'instruction' not in data:
            return jsonify({'error': 'Invalid request data'}), 400
        
        instruction = data['instruction'].strip()
        if not instruction:
            return jsonify({'error': 'Instruction cannot be empty'}), 400
        
        # Log the instruction
        logger.info(f"Instruction submitted: {instruction}")
        
        # Here, you would send the instruction to the Core Controller
        # For now, just return success
        return jsonify({'message': 'Instruction submitted successfully'})
    except Exception as e:
        logger.error(f"Error submitting instruction: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/clients-status', methods=['GET'])
def clients_status():
    try:
        agents = Agent.query.all()
        status_list = [{'id': a.id, 'ip': a.ip, 'status': a.status, 'last_seen': a.last_seen.isoformat() if a.last_seen else None} for a in agents]
        return jsonify(status_list)
    except Exception as e:
        logger.error(f"Error getting client status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/files-preview', methods=['GET'])
def files_preview():
    try:
        search = request.args.get('search', '').strip()
        query = FileLog.query.filter_by(status='pending')
        if search:
            query = query.filter(FileLog.filename.contains(search) | FileLog.path.contains(search))
        
        files = query.all()
        file_list = [{
            'id': f.id, 
            'filename': f.filename, 
            'path': f.path, 
            'agent_ip': f.agent.ip, 
            'status': f.status,
            'created_at': f.created_at.isoformat() if f.created_at else None
        } for f in files]
        return jsonify(file_list)
    except Exception as e:
        logger.error(f"Error getting files preview: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/approve-deletion', methods=['POST'])
def approve_deletion():
    try:
        data = request.get_json()
        if not data or 'file_ids' not in data:
            return jsonify({'error': 'Invalid request data'}), 400
        
        file_ids = data['file_ids']
        if not isinstance(file_ids, list) or not file_ids:
            return jsonify({'error': 'file_ids must be a non-empty list'}), 400
        
        # Update status to approved and set approved_at
        now = datetime.utcnow()
        FileLog.query.filter(FileLog.id.in_(file_ids)).update({
            'status': 'approved',
            'approved_at': now
        })
        db.session.commit()
        
        logger.info(f"Files approved for deletion: {file_ids}")
        # Here, notify the agents to delete the files
        return jsonify({'message': f'{len(file_ids)} files approved for deletion'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error approving deletion: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/reject-deletion', methods=['POST'])
def reject_deletion():
    try:
        data = request.get_json()
        if not data or 'file_ids' not in data:
            return jsonify({'error': 'Invalid request data'}), 400
        
        file_ids = data['file_ids']
        if not isinstance(file_ids, list) or not file_ids:
            return jsonify({'error': 'file_ids must be a non-empty list'}), 400
        
        # Update status to rejected
        FileLog.query.filter(FileLog.id.in_(file_ids)).update({'status': 'rejected'})
        db.session.commit()
        
        logger.info(f"Files rejected for deletion: {file_ids}")
        return jsonify({'message': f'{len(file_ids)} files rejected for deletion'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error rejecting deletion: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    generate_mock_data()
    app.run(debug=True)

if __name__ == '__main__':
    generate_mock_data()
    app.run(debug=True)