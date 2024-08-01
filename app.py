from flask import Flask, request, jsonify, session
from flask_cors import CORS
from models import db, User

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cgm.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Required for session management
db.init_app(app)
CORS(app)  # Enable CORS for all routes

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    requested_role = data.get('role')  # Get the role from the request

    # Log incoming data for debugging
    app.logger.info(f"Login attempt: {username} for role {requested_role}")

    # Query the user by username only
    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):  # Use check_password to verify the password
        # Normalize both user role and requested role by lowercasing and replacing hyphens with spaces
        normalized_user_role = user.role.lower().replace(' ', '-')
        normalized_requested_role = requested_role.lower().replace(' ', '-')
        
        if normalized_user_role != normalized_requested_role:
            return jsonify({'message': 'Incorrect role for the provided credentials'}), 401
        
        session['user_id'] = user.id
        return jsonify({'message': f'Welcome, {user.role}', 'role': user.role}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

def init_db():
    with app.app_context():
        db.create_all()
        # Check if default users exist and add them if not
        if not User.query.filter_by(username='mainman').first():
            db.session.add(User(username='mainman', password='mkubwawaCGM', role='CEO'))
        if not User.query.filter_by(username='houseman').first():
            db.session.add(User(username='houseman', password='rentyaCGM', role='Tenant'))
        if not User.query.filter_by(username='pesawoman').first():
            db.session.add(User(username='pesawoman', password='pesayaCGM', role='Finance Manager'))
        if not User.query.filter_by(username='weraman').first():
            db.session.add(User(username='weraman', password='nikoCGM', role='Procurement Manager'))
        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
