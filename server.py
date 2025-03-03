from flask import Flask, request, redirect, url_for, render_template_string, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import signal

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# HTML template for the login page
signup_template = '''
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Sign Up</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: black; color: gold; }
        .container { width: 300px; margin: auto; padding: 20px; border: 1px solid gold; border-radius: 10px; }
        h2 { text-align: center; color: gold; }
        form { display: flex; flex-direction: column; }
        input { margin-bottom: 10px; padding: 8px; border: 1px solid gold; background-color: black; color: gold; }
        .button { background-color: gold; color: black; border: none; padding: 10px; cursor: pointer; }
        .button:hover { background-color: #d4af37; } /* Slightly darker gold */
        .error { color: red; text-align: center; }
        .link { text-align: center; margin-top: 10px; color: gold; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Sign Up</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="button">Sign Up</button>
        </form>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        <p class="link"><a href="{{ url_for('login') }}" style="color: gold;">Already have an account? Log in</a></p>
    </div>
</body>
</html>
'''

login_template = '''
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: black; color: gold; }
        .container { width: 300px; margin: auto; padding: 20px; border: 1px solid gold; border-radius: 10px; }
        h2 { text-align: center; color: gold; }
        form { display: flex; flex-direction: column; }
        input { margin-bottom: 10px; padding: 8px; border: 1px solid gold; background-color: black; color: gold; }
        .button { background-color: gold; color: black; border: none; padding: 10px; cursor: pointer; }
        .button:hover { background-color: #d4af37; }
        .error { color: red; text-align: center; }
        .link { text-align: center; margin-top: 10px; color: gold; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Login</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="button">Login</button>
        </form>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        <p class="link"><a href="{{ url_for('passwordChange') }}" style="color: gold;">Change Password</a></p>
        <p class="link"><a href="{{ url_for('signup') }}" style="color: gold;">Don't have an account? Sign up</a></p>
    </div>
</body>
</html>
'''

# Add this near the top of the file, with other templates
password_change_template = '''
<!doctype html>
<html lang="en">
<head>
    <title>Change Password</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: black; color: gold; }
        .container { width: 300px; margin: auto; padding: 20px; border: 1px solid gold; border-radius: 10px; }
        h2 { text-align: center; color: gold; }
        form { display: flex; flex-direction: column; }
        input { margin-bottom: 10px; padding: 8px; border: 1px solid gold; background-color: black; color: gold; }
        .button { background-color: gold; color: black; border: none; padding: 10px; cursor: pointer; }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Change Password</h2>
        <form method="post">
            <input type="password" name="current_password" placeholder="Current Password" required>
            <input type="password" name="new_password" placeholder="New Password" required>
            <input type="password" name="confirm_password" placeholder="Confirm New Password" required>
            <button type="submit" class="button">Change Password</button>
        </form>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
'''
# HTML template for the home page
home_template = '''
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Home Page</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: black; color: gold; }
        .container { width: 300px; margin: auto; padding: 20px; border: 1px solid gold; border-radius: 10px; }
        h2 { text-align: center; color: gold; }
        .button { background-color: gold; color: black; border: none; padding: 10px; cursor: pointer; text-decoration: none; display: inline-block; margin-top: 10px; }
        .button.delete { background-color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Welcome to your home page!</h2>
        <p>You have successfully logged in.</p>
        <a href="{{ url_for('logout') }}" class="button">Logout</a>
        <a href="{{ url_for('delete_account') }}" class="button delete">Delete Account</a>
    </div>
</body>
</html>
'''

# Add this template for the admin page
admin_template = '''
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Admin Page</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: black; color: gold; }
        .container { width: 300px; margin: auto; padding: 20px; border: 1px solid gold; border-radius: 10px; }
        h2 { text-align: center; color: gold; }
        .button { background-color: #dc3545; color: white; border: none; padding: 10px; cursor: pointer; display: block; width: 100%; text-align: center; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Admin Page</h2>
        <a href="{{ url_for('stop_program') }}" class="button">Stop Program</a>
    </div>
</body>
</html>
'''

login_credentials = {
    'username': 'user',
    'password': 'pass'
}
# Route for the signup page
@app.route('/', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template_string(signup_template, error='Username already exists')
        
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    return render_template_string(signup_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Set user session
            if user.is_admin:
                return redirect(url_for('admin'))
            return redirect(url_for('home'))
        else:
            return render_template_string(login_template, error='Invalid credentials')
    return render_template_string(login_template)

@app.route('/change-password', methods=['GET', 'POST'])
def passwordChange():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        user = User.query.get(session['user_id'])
        if not user or not check_password_hash(user.password, current_password):
            return render_template_string(password_change_template, error='Current password is incorrect.')
        
        if new_password != confirm_password:
            return render_template_string(password_change_template, error='New passwords do not match.')
        
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template_string(password_change_template)

@app.route('/logout')
def logout():
    session.clear()  # Clear the session
    return redirect(url_for('login'))

# Route for the home page
@app.route('/home')
def home():
    return render_template_string(home_template)

# Add a new template for account deletion
delete_account_template = '''
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Delete Account</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: black; color: gold; }
        .container { width: 300px; margin: auto; padding: 20px; border: 1px solid gold; border-radius: 10px; }
        h2 { text-align: center; color: gold; }
        form { display: flex; flex-direction: column; }
        input { margin-bottom: 10px; padding: 8px; border: 1px solid gold; background-color: black; color: gold; }
        .button { background-color: #dc3545; color: white; border: none; padding: 10px; cursor: pointer; }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Delete Account</h2>
        <form method="post">
            <input type="password" name="password" placeholder="Enter your password" required>
            <button type="submit" class="button">Delete Account</button>
        </form>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
'''

# Add a new route for account deletion
@app.route('/delete-account', methods=['GET', 'POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        user = User.query.get(session['user_id'])

        if user and check_password_hash(user.password, password):
            db.session.delete(user)
            db.session.commit()
            session.clear()
            return redirect(url_for('signup'))
        else:
            return render_template_string(delete_account_template, error='Invalid password')

    return render_template_string(delete_account_template)

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return redirect(url_for('home'))
    return render_template_string(admin_template)

@app.route('/stop-program')
def stop_program():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return redirect(url_for('home'))
    os.kill(os.getpid(), signal.SIGINT)
    return 'Program is shutting down...'

def init_db():
    db.drop_all()
    db.create_all()
    admin = User(username='admin', password=generate_password_hash('admin'), is_admin=True)
    db.session.add(admin)
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)