from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, User, Complaint
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cgm.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  
db.init_app(app)
jwt = JWTManager(app)

# Custom error handler for validation errors
@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    response = e.get_response()
    response.data = jsonify({"error": e.description})
    response.content_type = "application/json"
    return response

# Initialize the database if necessary
@app.before_first_request
def create_tables():
    db.create_all()

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity={'id': user.id, 'username': user.username, 'role': user.role})
        return jsonify(access_token=access_token), 200
    return jsonify({"error": "Invalid credentials"}), 401

# Tenant Routes
@app.route('/tenant/complaints', methods=['GET'])
@jwt_required()
def get_tenant_complaints():
    current_user = get_jwt_identity()
    if current_user['role'] != 'tenant':
        return jsonify({"error": "Unauthorized access"}), 403

    tenant_id = current_user['id']
    complaints = Complaint.query.filter_by(tenant_id=tenant_id).all()
    return jsonify([c.to_dict() for c in complaints])

@app.route('/tenant/complaint', methods=['POST'])
@jwt_required()
def file_complaint():
    current_user = get_jwt_identity()
    if current_user['role'] != 'tenant':
        return jsonify({"error": "Unauthorized access"}), 403

    data = request.get_json()
    complaint = Complaint(
        tenant_id=current_user['id'],
        category=data['category'],
        description=data['description']
    )
    db.session.add(complaint)
    db.session.commit()
    # Notify Procurement Manager (simple print statement, replace with actual notification logic)
    print(f"New complaint filed by {current_user['username']}: {data['category']}")
    return jsonify({"message": "Complaint filed successfully"}), 201

# CEO Routes
@app.route('/ceo/affiliates/<role>', methods=['GET'])
@jwt_required()
def view_affiliates(role):
    current_user = get_jwt_identity()
    if current_user['role'] != 'CEO':
        return jsonify({"error": "Unauthorized access"}), 403

    page = request.args.get('page', 1, type=int)
    per_page = 10
    users = User.query.filter_by(role=role).paginate(page=page, per_page=per_page)
    return jsonify([user.to_dict() for user in users.items])

@app.route('/ceo/complaints', methods=['GET'])
@jwt_required()
def view_all_complaints():
    current_user = get_jwt_identity()
    if current_user['role'] != 'CEO':
        return jsonify({"error": "Unauthorized access"}), 403

    complaints = Complaint.query.all()
    return jsonify([c.to_dict() for c in complaints])

@app.route('/ceo/enroll', methods=['POST'])
@jwt_required()
def enroll_user():
    current_user = get_jwt_identity()
    if current_user['role'] != 'CEO':
        return jsonify({"error": "Unauthorized access"}), 403

    data = request.get_json()
    new_user = User(username=data['username'], role=data['role'])
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

# Procurement Manager Routes
@app.route('/procurement/complaints', methods=['GET', 'POST'])
@jwt_required()
def manage_complaints():
    current_user = get_jwt_identity()
    if current_user['role'] != 'Procurement Manager':
        return jsonify({"error": "Unauthorized access"}), 403

    if request.method == 'GET':
        complaints = Complaint.query.filter_by(status='Pending').all()
        return jsonify([c.to_dict() for c in complaints])

    if request.method == 'POST':
        data = request.get_json()
        complaint = Complaint.query.get(data['complaint_id'])
        if data['action'] == 'accept':
            complaint.status = 'Approved'
            # Notify Tenant and Finance Manager (replace with actual notification logic)
            print(f"Complaint {complaint.id} approved.")
        elif data['action'] == 'decline':
            complaint.status = 'Denied'
            # Notify Tenant (replace with actual notification logic)
            print(f"Complaint {complaint.id} denied.")
        db.session.commit()
        return jsonify({"message": "Complaint updated successfully"})

# Finance Manager Routes
@app.route('/finance/complaints', methods=['GET', 'POST'])
@jwt_required()
def allocate_budget():
    current_user = get_jwt_identity()
    if current_user['role'] != 'Finance Manager':
        return jsonify({"error": "Unauthorized access"}), 403

    if request.method == 'GET':
        complaints = Complaint.query.filter_by(status='Approved').all()
        return jsonify([c.to_dict() for c in complaints])

    if request.method == 'POST':
        data = request.get_json()
        complaint = Complaint.query.get(data['complaint_id'])
        complaint.amount_allocated = data['amount']
        # Notify Procurement Manager (replace with actual notification logic)
        print(f"Complaint {complaint.id} allocated a budget of {data['amount']}.")
        db.session.commit()
        return jsonify({"message": "Budget allocated successfully"})

if __name__ == '__main__':
    app.run(debug=True)
