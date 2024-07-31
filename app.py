from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
CORS(app)  # Enable CORS for all routes

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Log incoming data for debugging
    app.logger.info(f"Login attempt: {username}")

    user = User.query.filter_by(username=username, password=password).first()
    if user:
        return jsonify({'message': f'Welcome, {user.role}'}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

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
