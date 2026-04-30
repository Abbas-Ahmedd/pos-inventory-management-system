#python
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'pos_secret_key_change_in_production')

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'pos_db')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue.', 'warning')
            return redirect(url_for('login'))

        if session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT * FROM users WHERE username=%s AND is_active=1",
            (username,)
        )
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['role'] = user['role']

            flash(f"Welcome back, {user['full_name']}!", 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) as cnt FROM users")
    count = cur.fetchone()

    if count['cnt'] > 0:
        flash('Setup already completed.', 'info')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        full_name = request.form['full_name'].strip()
        password = request.form['password']

        hashed = generate_password_hash(password)

        cur.execute(
            "INSERT INTO users (username, password_hash, full_name, role) VALUES (%s,%s,%s,'admin')",
            (username, hashed, full_name)
        )

        mysql.connection.commit()
        cur.close()

        flash('Admin account created! Please login.', 'success')
        return redirect(url_for('login'))

    cur.close()
    return render_template('setup.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
#```
