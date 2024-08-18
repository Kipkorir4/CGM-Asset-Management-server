from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.ext.hybrid import hybrid_property
from datetime import date
from werkzeug.utils import secure_filename
import os

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Add email column
    role = db.Column(db.String(80), nullable=False)
    _password_hash = db.Column('password_hash', db.String(128), nullable=False)

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password is not readable.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    def to_dict(self):
        return {
            'id': self.id, 
            'username': self.username, 
            'email': self.email,  # Include email in the to_dict method
            'role': self.role
        }

    def __repr__(self):
        return f'<User {self.username}>'


class Complaint(db.Model):
    __tablename__ = 'complaints'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    amount_allocated = db.Column(db.Float, default=0.0, nullable=True)
    complaint_number = db.Column(db.String(20), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='Pending')  # Default status
    image_path = db.Column(db.String(200), nullable=True)  # New field for image path

    __table_args__ = (
        db.UniqueConstraint('complaint_number', name='uq_complaint_number'),
    )

    user = db.relationship('User', backref=db.backref('complaints', lazy=True))

    def __repr__(self):
        return f'<Complaint {self.complaint_number} - {self.category}>'

    def allocate_amount(self, amount):
        budget = Budget.query.filter_by(category=self.category).first()
        if budget and budget.balance >= amount:
            self.amount_allocated = amount
            budget.balance -= amount
            self.status = 'Approved'
        else:
            self.status = 'Denied'
        db.session.commit()


class Budget(db.Model):
    __tablename__ = 'budgets'
    
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), unique=True, nullable=False)
    total_budget = db.Column(db.Float, nullable=False)
    balance = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<Budget {self.category} - Total: {self.total_budget}, Balance: {self.balance}>'

    def update_balance(self, amount):
        self.balance -= amount
        db.session.commit()
