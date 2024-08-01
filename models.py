from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.ext.hybrid import hybrid_property

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False)
    _password_hash = db.Column('password_hash', db.String(128), nullable=False)

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password is not readable.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash=bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    def to_dict(self):
        return {'id': self.id,'username': self.username}
    
    def __repr__(self):
        return f'<User {self.username}>'
