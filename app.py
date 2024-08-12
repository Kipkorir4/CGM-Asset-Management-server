from dotenv import load_dotenv
load_dotenv()

import os
from flask import Flask, request, jsonify, session, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_restful import Api, Resource
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Complaint, Budget
from datetime import date
import json
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)

environment = os.environ.get("ENVIRONMENT")

if environment == "development":
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cgm.db'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'aiileonikumotomanze'

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Flask-Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = (
    os.environ.get('MAIL_DEFAULT_SENDER_NAME'), 
    os.environ.get('MAIL_DEFAULT_SENDER_EMAIL')
)

# Initialize the extensions
db.init_app(app)
migrate = Migrate(app, db)
CORS(app, supports_credentials=True)
api = Api(app)
mail = Mail(app)

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

# reset password routes
def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except:
        return None
    return email

# reset password route
def send_password_reset_email(to_email, reset_link):
    msg = Message(subject="Password Reset Request",
                  sender=('CGM Properties', 'ceocgm@gmail.com'),
                  recipients=[to_email])
    msg.body = f'''To reset your password, visit the following link:
{reset_link}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

# for new users to set new password
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        return jsonify({'message': 'The token is invalid or has expired'}), 400

    if request.method == 'POST':
        data = request.get_json()
        new_password = data.get('password')
        
        if not new_password:
            return jsonify({'message': 'Please provide a new password'}), 400

        user = User.query.filter_by(email=email).first()
        if user:
            user.password_hash = new_password  # Ensure password is hashed
            db.session.commit()
            return jsonify({'message': 'Your password has been updated successfully'}), 200
        else:
            return jsonify({'message': 'User not found'}), 404

    # If it's a GET request
    return jsonify({'message': 'Please provide a new password'}), 200

# for existing users
@app.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Email not found'}), 404

    # Generate token
    token = generate_reset_token(user.email)
    
    
    # Reset link with token
    reset_link = f"https://cgm-staging-g4m95dpei-kipkorir4s-projects.vercel.app/reset-password?token={token}"
    
    send_password_reset_email(user.email, reset_link)
    
    
    return jsonify({'message': 'Password reset email sent successfully. Redirecting you to homepage in 5 seconds.'}), 200


# Login verific
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
        userObjs =  {
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
        }
        # Ensure the session is marked as modified
        print("SESSION AFTER LOGIN:", session)
        return jsonify({'message': f'Welcome, {user.role}', 'role': user.role, "user": userObjs}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/complaints/<int:user_id>', methods=['GET'])
def get_complaints(user_id):
    # if 'user_id' not in session or session['user_id'] != user_id:
    #     print("SESSION IN COMPLAINTS: ", session)
    #     print("USER_ID IN COMPLAINTS: ", session['user_id'])
    #     return jsonify({'message': 'Unauthorized'}), 403

    complaints = Complaint.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'id': c.id,
        'category': c.category,
        'description': c.description,
        'date': c.date.isoformat(),
        'status': c.status
    } for c in complaints])


@app.route('/complaints', methods=['POST'])
def handle_complaints():
    if request.method == 'POST':
        data = request.get_json()

        print("DATA", data)
        category = data.get('category')
        user_id = data.get('userId')
        description = data.get('description')
        complaint_date = date.today()


        if user_id is None:
            return jsonify({'error': 'User ID is required'}), 400

        new_complaint = Complaint(
            user_id=user_id,
            category=category,
            description=description,
            date=complaint_date,
            status='Pending'  # Set the default status to Pending
        )
        db.session.add(new_complaint)
        db.session.commit()

        # Generate complaint number
        new_complaint.complaint_number = f"CMP{new_complaint.id:05d}"  # CMP00001, CMP00002, etc.
        db.session.commit()

        return jsonify({'success': True, 'complaint_number': new_complaint.complaint_number})


# @app.route('/users/<role>', methods=['GET'])
# def get_users_by_role(role):
#     if 'user_id' not in session:
#         return jsonify({'message': 'Unauthorized'}), 403
    
#     users = User.query.filter_by(role=role).all()
#     return jsonify([user.to_dict() for user in users])


@app.route('/all-users', methods=['GET'])
def get_all_users():
    # if 'user_id' not in session:
    #     return jsonify({'message': 'Unauthorized'}), 403

    users = User.query.all()
    return jsonify([{
        'username': user.username,
        'role': user.role
    } for user in users])



@app.route('/users/<username>', methods=['GET'])
def get_user_by_username(username):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403
    
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify(user.to_dict())
    else:
        return jsonify({'message': 'User not found'}), 404


@app.route('/all-complaints', methods=['GET'])
def get_all_complaints():
    # if 'user_id' not in session:
    #     return jsonify({'message': 'Unauthorized'}), 403

    complaints = Complaint.query.all()
    return jsonify([{
        'tenant': c.user.username,
        'complaint_number': c.id,
        'category': c.category,
        'description': c.description,
        'status': 'Approved' if c.amount_allocated > 0 else 'Denied',
        'amount_allocated': c.amount_allocated
    } for c in complaints])

# @app.route('/setup_budget', methods=['POST'])
# def setup_budget():
#     data = request.get_json()
#     category = data.get('category')
#     total_budget = data.get('total_budget')
#     balance = total_budget

#     new_budget = Budget(category=category, total_budget=total_budget, balance=balance)
#     db.session.add(new_budget)
#     db.session.commit()

#     return jsonify({'message': 'Budget set up successfully'}), 201

@app.route('/allocate_budget/<int:complaint_id>', methods=['POST'])
def allocate_budget(complaint_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    allocation_amount = data.get('amount')

    complaint = Complaint.query.get(complaint_id)
    if not complaint:
        return jsonify({'message': 'Complaint not found'}), 404

    budget = Budget.query.filter_by(category=complaint.category).first()
    if not budget:
        return jsonify({'message': f'No budget found for category {complaint.category}'}), 404

    if allocation_amount > budget.balance:
        return jsonify({'message': 'Insufficient budget balance'}), 400

    # Update the complaint and budget balance
    complaint.amount_allocated = allocation_amount
    complaint.status = 'Approved'
    budget.balance -= allocation_amount

    db.session.commit()

    return jsonify({'success': True, 'complaint_number': complaint.complaint_number, 'new_balance': budget.balance})


@app.route('/enroll', methods=['POST'])
def enroll_user():
    data = request.get_json()
    role = data.get('role')
    username = data.get('username')
    email = data.get('email')

    temp_password = 'Temp1234'  # Or generate a random one

    user = User.query.filter((User.username == username) | (User.email == email)).first()
    if user:
        user.role = role
        user.password_hash = temp_password
        user.email = email
        db.session.commit()
        message = 'User updated successfully'
        status_code = 200
    else:
        user = User(username=username, role=role, email=email)
        user.password_hash = temp_password
        db.session.add(user)
        db.session.commit()
        message = 'User created successfully and an email sent to the user'
        status_code = 201

    token = generate_reset_token(email)
    
    # Adjust the reset link to include the role for new users
    reset_link = f"https://cgm-staging-g4m95dpei-kipkorir4s-projects.vercel.app/{role}/reset_password/{token}"
    
    send_enrollment_email(email, username, reset_link)

    return jsonify({'message': message}), status_code

def send_enrollment_email(recipient_email, username, reset_link):
    msg = Message("Complete Your Enrollment", recipients=[recipient_email])
    msg.body = (
    f"Dear {username},\n\n"
    "You have been enrolled successfully.\n\n"
    "To set your password, please visit the following link:\n"
    f"{reset_link}\n\n"
    f"Use the username, {username}, then the password you'll set to login.\n\n"
    "Best Regards,\n"
    "CGM Properties"
)
    mail.send(msg)
# the end


# this is where a logged in p.manger fetches complaints
@app.route('/fetch_all_complaints', methods=['GET'])
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
        'date': c.date.isoformat(),
        'status': c.status  # Include status in the response
    } for c in complaints])

@app.route('/complaints/<int:complaint_id>/<action>', methods=['POST'])
def handle_complaint_action(complaint_id, action):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    complaint = Complaint.query.get(complaint_id)
    if not complaint:
        return jsonify({'message': 'Complaint not found'}), 404

    if action == 'accept':
        complaint.status = 'Accepted'
    elif action == 'decline':
        complaint.status = 'Declined'
    else:
        return jsonify({'message': 'Invalid action'}), 400

    db.session.commit()

    return jsonify({'message': f'Complaint {action}ed successfully'})


@app.route('/accept-complaint/<int:complaint_id>', methods=['POST'])
def accept_complaint(complaint_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    complaint = Complaint.query.get(complaint_id)
    if not complaint:
        return jsonify({'message': 'Complaint not found'}), 404

    complaint.status = 'Accepted'
    db.session.commit()

    return jsonify({'success': True, 'complaint_number': complaint.complaint_number})

@app.route('/decline-complaint/<int:complaint_id>', methods=['POST'])
def decline_complaint(complaint_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    complaint = Complaint.query.get(complaint_id)
    if not complaint:
        return jsonify({'message': 'Complaint not found'}), 404

    complaint.status = 'Declined'
    db.session.commit()

    return jsonify({'success': True, 'complaint_number': complaint.complaint_number})

@app.route('/accepted-complaints', methods=['GET'])
def get_accepted_complaints():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    complaints = Complaint.query.filter_by(status='Accepted').all()
    return jsonify([{
        'id': c.id,
        'complaintNumber': c.complaint_number,
        'category': c.category,
        # 'budgetBalance': c.budget_balance,
        'amountAllocated': c.amount_allocated,
        'date': c.date.isoformat()
    } for c in complaints])


@app.route('/allocated-complaints', methods=['GET'])
def get_allocated_complaints():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    complaints = Complaint.query.filter(Complaint.amount_allocated > 0).all()
    allocated_complaints = [{
        'complaint_number': complaint.complaint_number,
        'category': complaint.category,
        'amount_allocated': complaint.amount_allocated
    } for complaint in complaints]

    return jsonify(allocated_complaints)


@app.route('/current-budget-balances', methods=['GET'])
def current_budget_balances():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403

    budgets = Budget.query.all()
    if not budgets:
        return jsonify({'message': 'No budget information available'}), 404

    # Create a list of dictionaries for each budget
    budget_data = [{'category': budget.category, 'balance_amount': budget.balance} for budget in budgets]

    return jsonify(budget_data)

# for user POST request of new password after 'forgot password'
def hash_password(password):
    """
    Hashes the provided password using a secure algorithm.
    
    :param password: The plain-text password to hash.
    :return: A hashed password that can be safely stored in the database.
    """
    return generate_password_hash(password)

def verify_password(stored_password_hash, provided_password):
    """
    Verifies a provided password against the stored hash.
    
    :param stored_password_hash: The hashed password stored in the database.
    :param provided_password: The plain-text password provided by the user.
    :return: True if the password matches the hash, otherwise False.
    """
    return check_password_hash(stored_password_hash, provided_password)

@app.route('/api/reset-password', methods=['POST'])
def reset1_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('newPassword')

    if not token or not new_password:
        return jsonify({'message': 'Token and new password are required.'}), 400

    # Verify the token
    email = verify_reset_token(token)
    if not email:
        return jsonify({'message': 'Invalid or expired token.'}), 400

    # Find the user and update their password
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404

    user.password_hash = new_password  # This will automatically hash the password using the setter method
    db.session.commit()
    
    role = user.role  # Adjust according to your user model
    return jsonify({'message': 'Password reset successfully.', 'role': role}), 200



    




def init_db():
    with app.app_context():
        db.create_all()
        
        # Upsert logic for default users
        users_data = [
            {'username': 'mainman', 'role': 'CEO', 'email': 'mainman@example.com', 'password': 'mkubwawaCGM'},
            {'username': 'houseman', 'role': 'Tenant', 'email': 'houseman@example.com', 'password': 'rentyaCGM'},
            {'username': 'pesawoman', 'role': 'Finance Manager', 'email': 'kimagetk@gmail.com', 'password': 'pesayaCGM'},
            {'username': 'weraman', 'role': 'Procurement Manager', 'email': 'weraman@example.com', 'password': 'nikoCGM'}
        ]
        
        for user_data in users_data:
            user = User.query.filter_by(username=user_data['username']).first() or User.query.filter_by(email=user_data['email']).first()
            if user:
                user.role = user_data['role']
                user.password_hash = user_data['password']
            else:
                user = User(
                    username=user_data['username'], 
                    role=user_data['role'], 
                    email=user_data['email']
                )
                user.password_hash = user_data['password']
                db.session.add(user)

        db.session.commit()



if __name__ == '__main__':
    init_db()
    app.run(debug=True)
