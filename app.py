from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import joblib
import pandas as pd
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re
import os


# Initialize Flask app, bcrypt, SQLAlchemy, and login manager
app = Flask(__name__)
app.config['SECRET_KEY'] = 'yoursecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database configuration
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Load the pre-trained model from a file
tuned_model = joblib.load('tuned_model.pkl')

# User model for the database
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Updated to use Session.get()

# Password validation regex
PASSWORD_REGEX = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$'

def validate_password(password):
    return re.match(PASSWORD_REGEX, password)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validate password
        if not validate_password(password):
            flash('Password must contain at least 1 capital letter, 1 special character, 1 number, and be at least 8 characters long.', 'error')
            return redirect(url_for('signup'))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Save user to database
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        flash('Account created successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/projects')
@login_required
def projects():
    return render_template('projects.html')

@app.route('/prediction')
@login_required
def prediction():
    return render_template('prediction.html')

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    # Get user input from the submitted form
    user_input = {
        'age': request.form['age'],
        'job': request.form['job'],
        'marital': request.form['marital'],
        'education': request.form['education'],
        'isDefault': request.form['isDefault'],
        'hasHousingLoan': request.form['hasHousingLoan'],
        'hasPersonalLoan': request.form['hasPersonalLoan'],
        'contact': request.form['contact'],
        'month': request.form['month'],
        'dayOfWeek': request.form['dayOfWeek'],
        'duration': request.form['duration'],
        'campaign': request.form['campaign'],
        'pdays': request.form['pdays'],
        'previous': request.form['previous'],
        'previousAttempt': request.form['previousAttempt']
    }

    # Validate and convert user input to integers
    validated_input = {}
    for key, value in user_input.items():
        try:
            validated_input[key] = int(value)
        except ValueError:
            return jsonify({'error': f'Invalid input for {key}'}), 400

    # Create DataFrame with user input
    new_data = pd.DataFrame(validated_input, index=[0])

    # Make prediction using the tuned model
    try:
        prediction = tuned_model.predict(new_data)
    except Exception as e:
        return jsonify({'error': 'Model prediction failed'}), 500

    # Convert prediction to label
    prediction_label = 'Yes' if prediction[0] == 1 else 'No'

    # Return prediction as JSON response
    return jsonify({
        'prediction': prediction_label,
        'input_data': validated_input
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This creates the 'users.db' file and the 'User' tabl
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
 # Run the application in debug mode
