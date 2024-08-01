from flask import Flask, request, jsonify, session
from flask_cors import CORS
from models import db, User
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cgm.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Required for session management
db.init_app(app)
CORS(app, resources={r"/*": {"origins": ["http://localhost:5173"]}})  # Enable CORS for all routes


bcrypt = Bcrypt(app)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password_hash = data.get('password')
    requested_role = data.get('role')  # Get the role from the request

    # Log incoming data for debugging
    app.logger.info(f"Login attempt: {username} for role {requested_role}")

    user = User.query.filter_by(username=username).first()
    
    if user.check_password(password_hash):
        print (requested_role)
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
        db.drop_all()  # Drop all tables
        db.create_all()
        # Check if default users exist and add them if not
        if not User.query.filter_by(username='mainman').first():
            user1=User(username='mainman', role='CEO')
            user1.password_hash='mkubwawaCGM'
            db.session.add(user1)
        if not User.query.filter_by(username='houseman').first():
            user2=User(username='houseman', role='Tenant')
            user2.password_hash='rentyaCGM'
            db.session.add(user2)
        if not User.query.filter_by(username='pesawoman').first():
            user3=User(username='pesawoman', role='Finance Manager')
            user3.password_hash='pesayaCGM'
            db.session.add(user3)
        if not User.query.filter_by(username='weraman').first():
            user4=User(username='weraman', role='Procurement Manager')
            user4.password_hash='nikoCGM'
            db.session.add(user4)
        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
