from flask_sqlalchemy import SQLAlchemy
from app import app  # Make sure to import your Flask app

# Initialize the database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Define the User model (if not already imported)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Query all users
users = User.query.all()

# Print user details
for user in users:
    print(f"ID: {user.id}, Username: {user.username}, Password (hashed): {user.password}")
