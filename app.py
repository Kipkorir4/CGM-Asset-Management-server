from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_restful import Api, Resource
from models import db, User, Complaint
from datetime import date

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cgm.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'aiileonikumotomanze'

# Initialize the extensions
db.init_app(app)
migrate = Migrate(app, db)
CORS(app, supports_credentials=True)
api = Api(app)

class ClearSession(Resource):
    def delete(self):
        session.clear()
        return {}, 204

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {}, 204

        user = User.query.get(user_id)
        if not user:
            return {}, 204

        return user.to_dict(), 200

api.add_resource(ClearSession, '/clear-session')
api.add_resource(CheckSession, '/check-session')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    requested_role = data.get('role')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        normalized_user_role = user.role.lower().replace(' ', '-')
        normalized_requested_role = requested_role.lower().replace(' ', '-')
        
        if normalized_user_role != normalized_requested_role:
            return jsonify({'message': 'Incorrect credentials'}), 401
        
        session['user_id'] = user.id
        session.modified = True 
        print(session)
        # Ensure the session is marked as modified
        return jsonify({'message': f'Welcome, {user.role}', 'role': user.role}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/complaints/<int:user_id>', methods=['GET'])
def get_complaints(user_id):
    if 'user_id' not in session or session['user_id'] != user_id:
        return jsonify({'message': 'Unauthorized'}), 403

    complaints = Complaint.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'id': c.id,
        'category': c.category,
        'description': c.description,
        'date': c.date.isoformat()
    } for c in complaints])

@app.route('/complaints', methods=['POST'])
def file_complaint():
    print(session,'session results 201')

    if 'user_id' in session:
        
        data = request.get_json()
        user_id = session['user_id']
        category = data.get('category')
        description = data.get('description')
        complaint_date = date.today()

    # if user_id != session['user_id']:
    #     return jsonify({'message': 'Unauthorized'}), 403

    new_complaint = Complaint(
        user_id=user_id,
        category=category,
        description=description,
        date=complaint_date
    )
    db.session.add(new_complaint)
    db.session.commit()

    # Generate complaint number
    new_complaint.complaint_number = f"CMP{new_complaint.id:05d}"  # CMP00001, CMP00002, etc.
    db.session.commit()

    return jsonify({'success': True, 'complaint_number': new_complaint.complaint_number})

@app.route('/users/<role>', methods=['GET'])
def get_users_by_role(role):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403
    
    users = User.query.filter_by(role=role).all()
    return jsonify([user.to_dict() for user in users])

@app.route('/all-complaints', methods=['GET'])
def get_all_complaints():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    complaints = Complaint.query.all()
    return jsonify([{
        'tenant': c.user.username,
        'complaint_number': c.id,
        'category': c.category,
        'description': c.description,
        'status': 'Approved' if c.amount_allocated > 0 else 'Denied',
        'amount_allocated': c.amount_allocated
    } for c in complaints])

@app.route('/accepted-complaints', methods=['GET'])
def get_accepted_complaints():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    complaints = Complaint.query.filter(Complaint.amount_allocated == 0).all()
    return jsonify([{
        'id': c.id,
        'complaintNumber': c.complaint_number,
        'category': c.category,
        'budgetBalance': c.budget_balance,
        'amountAllocated': c.amount_allocated
    } for c in complaints])

@app.route('/allocate-budget/<int:complaint_id>', methods=['POST'])
def allocate_budget(complaint_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    amount = data.get('amount')

    complaint = Complaint.query.get(complaint_id)
    if not complaint:
        return jsonify({'message': 'Complaint not found'}), 404

    # Perform budget allocation logic here

    complaint.amount_allocated = amount
    db.session.commit()

    return jsonify({'success': True, 'complaint_number': complaint.complaint_number})

@app.route('/decline-complaint/<int:complaint_id>', methods=['POST'])
def decline_complaint(complaint_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    complaint = Complaint.query.get(complaint_id)
    if not complaint:
        return jsonify({'message': 'Complaint not found'}), 404

    db.session.delete(complaint)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/enroll', methods=['POST'])
def enroll_user():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    role = data.get('role')
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    new_user = User(username=username, password=password, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/complaints', methods=['GET'])
def fetch_all_complaints():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    complaints = Complaint.query.all()
    return jsonify([{
        'id': c.id,
        'tenant': c.user.username,
        'complaint_number': c.complaint_number,
        'category': c.category,
        'description': c.description,
        'date': c.date.isoformat()
    } for c in complaints])

@app.route('/complaints/<int:complaint_id>/<action>', methods=['POST'])
def handle_complaint_action(complaint_id, action):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    complaint = Complaint.query.get(complaint_id)
    if not complaint:
        return jsonify({'message': 'Complaint not found'}), 404

    if action == 'accept':
        message_to_tenant = 'The complaint was approved and a technician will be sent to assess the issue.'
        message_to_finance_and_ceo = {
            'Tenant': complaint.user.username,
            'Complaint Number': complaint.complaint_number,
            'Complaint Category': complaint.category,
            'Complaint Description': complaint.description,
            'Action': 'Accepted'
        }
        # Send messages to finance manager and CEO (placeholder logic)
    elif action == 'decline':
        message_to_tenant = 'Unfortunately, it might take a while before the issue is resolved.'
        message_to_ceo = {
            'Tenant': complaint.user.username,
            'Complaint Number': complaint.complaint_number,
            'Complaint Category': complaint.category,
            'Complaint Description': complaint.description,
            'Action': 'Declined'
        }
        # Send message to CEO (placeholder logic)
    else:
        return jsonify({'message': 'Invalid action'}), 400

    # Placeholder for sending messages to tenant and other roles
    print(message_to_tenant)
    if action == 'accept':
        print(message_to_finance_and_ceo)
    else:
        print(message_to_ceo)

    return jsonify({'message': f'Complaint {action}ed successfully'})

def init_db():
    with app.app_context():
        db.create_all()
        # Add default users if they don't exist
        if not User.query.filter_by(username='mainman').first():
            user = User(username='mainman', role='CEO')
            user.password_hash = 'mkubwawaCGM'
            db.session.add(user)
        
        if not User.query.filter_by(username='houseman').first():
            user = User(username='houseman', role='Tenant')
            user.password_hash = 'rentyaCGM'
            db.session.add(user)
        
        if not User.query.filter_by(username='pesawoman').first():
            user = User(username='pesawoman', role='Finance Manager')
            user.password_hash = 'pesayaCGM'
            db.session.add(user)
        
        if not User.query.filter_by(username='weraman').first():
            user = User(username='weraman', role='Procurement Manager')
            user.password_hash = 'nikoCGM'
            db.session.add(user)

        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
