"""
Secure User Authentication & Application Security Demo
Project 4 - Application Security

This application demonstrates core web application security concepts:
1. Input validation (server-side regex and length rules)
2. Authentication (secure credentials checking)
3. Authorization (role-based access control for 'user' and 'admin')
4. Secure password handling (Werkzeug password hashing - never plain text)
5. Basic security checks (SQL injection protection via parameterized queries,
   XSS protection via Jinja2 auto-escaping, anti-cache headers)
6. Error handling (custom friendly error pages without exposing stack traces)
7. Security recommendations (production-readiness guide)
"""

import os
import re
import sqlite3
from functools import wraps
from datetime import datetime
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    g
)
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask application
app = Flask(__name__)

# Security: Set a secret key for session signing.
# In production, this should be a cryptographically secure random string stored in an environment variable.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'app-security-demo-secret-key-2026-safe-local')

# Session security configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True    # Mitigate XSS cookie theft
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # Mitigate Cross-Site Request Forgery (CSRF)

DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.db')


# ============================================================================
# DATABASE HELPER FUNCTIONS
# ============================================================================

def get_db():
    """
    Establish a connection to the SQLite database.
    Using row_factory = sqlite3.Row allows column access by name.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Safely close database connection at the end of each request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """
    Initialize SQLite database tables and seed local demo admin account.
    Safe parameterized SQL is used throughout.
    """
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Check if demo admin account already exists
    # Using parameterized query (?) prevents SQL Injection
    cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    admin_user = cursor.fetchone()

    if not admin_user:
        # SECURITY CONCEPT: Secure password handling
        # Passwords are hashed before storage and are never stored in plain text.
        demo_admin_password = "Admin@12345"
        hashed_admin_password = generate_password_hash(
            demo_admin_password,
            method='scrypt'
        )

        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "admin",
                "admin@example.com",
                hashed_admin_password,
                "admin",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        )
        conn.commit()
        print("[Security Demo] Initialized database and seeded demo admin account.")

    conn.commit()
    conn.close()


# ============================================================================
# SECURITY HEADERS & CACHE CONTROL
# ============================================================================

@app.after_request
def add_security_headers(response):
    """
    Add security headers to responses:
    - Prevent browser caching of protected views (so 'Back' button won't expose data after logout)
    - Set standard defensive headers (X-Content-Type-Options, X-Frame-Options)
    """
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response


# ============================================================================
# AUTHORIZATION & AUTHENTICATION DECORATORS
# ============================================================================

def login_required(f):
    """
    SECURITY CONCEPT: Authentication check
    Ensures user is logged in before accessing protected routes.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    SECURITY CONCEPT: Server-side role-based authorization
    Ensures user has 'admin' role. Rejects regular users with 403 Forbidden.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            # Abort with 403 Forbidden if not an administrator
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# INPUT VALIDATION UTILITIES
# ============================================================================

def validate_registration_input(username, email, password, confirm_password):
    """
    SECURITY CONCEPT: Server-side input validation
    Validates user input against length, format, and complexity rules.
    Returns (is_valid, error_message).
    """
    # 1. Check for empty fields
    if not username or not email or not password or not confirm_password:
        return False, "All fields are required. Please fill in all fields."

    username = username.strip()
    email = email.strip()

    # 2. Username validation (3-30 characters, alphanumeric and underscores only)
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters long."

    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username can only contain letters, numbers, and underscores."

    # 3. Email validation (basic standard format)
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(email_regex, email) or len(email) > 100:
        return False, "Please provide a valid email address."

    # 4. Password length validation (at least 8 characters)
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    # 5. Password complexity validation (must contain at least one number)
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one numeric digit (0-9)."

    # 6. Confirm password check
    if password != confirm_password:
        return False, "Passwords do not match. Please re-enter passwords."

    return True, None


# ============================================================================
# APPLICATION ROUTES
# ============================================================================

@app.route('/')
def home():
    """Home Page explaining the demo and providing quick navigation."""
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    User Registration:
    - Performs server-side input validation
    - Hashes password using Werkzeug before storage
    - Uses parameterized SQL queries to prevent SQL injection
    - Prevents duplicate usernames or emails
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Server-side input validation
        is_valid, error_msg = validate_registration_input(username, email, password, confirm_password)
        if not is_valid:
            flash(error_msg, "danger")
            return render_template('register.html', username=username, email=email)

        db = get_db()

        # Check for duplicate username or email
        # Parameterized query protects against SQL injection
        existing_user = db.execute(
            "SELECT id, username, email FROM users WHERE username = ? OR email = ?",
            (username, email)
        ).fetchone()

        if existing_user:
            if existing_user['username'].lower() == username.lower():
                flash("Username is already taken. Please choose another.", "danger")
            else:
                flash("Email address is already registered. Please use another email or log in.", "danger")
            return render_template('register.html', username=username, email=email)

        # SECURITY CONCEPT: Secure password handling
        # Passwords are hashed before storage and are never stored in plain text.
        password_hash = generate_password_hash(password, method='scrypt')

        try:
            db.execute(
                """
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, 'user', ?)
                """,
                (username, email, password_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            db.commit()
            flash("Registration successful! You can now log in securely.", "success")
            return redirect(url_for('login'))
        except sqlite3.Error:
            # Friendly error without exposing database internals
            flash("An error occurred during account creation. Please try again.", "danger")
            return render_template('register.html', username=username, email=email)

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User Login / Authentication:
    - Accepts username or email
    - Verifies password using check_password_hash()
    - Uses generic error message ("Invalid username or password.")
      to avoid user enumeration attacks
    """
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')

        if not identifier or not password:
            flash("Please enter both username/email and password.", "danger")
            return render_template('login.html', identifier=identifier)

        db = get_db()
        # Parameterized query: find user by username OR email
        user = db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier)
        ).fetchone()

        # SECURITY CONCEPT: Authentication & secure password checking
        # check_password_hash safely validates hashed password against input.
        if user and check_password_hash(user['password_hash'], password):
            # Regenerate/set session variables
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            flash(f"Welcome back, {user['username']}! You have logged in successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            # SECURITY CONCEPT: Generic error message to prevent user enumeration
            # Do NOT reveal whether username or password was incorrect.
            flash("Invalid username or password.", "danger")
            return render_template('login.html', identifier=identifier)

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """
    User Dashboard:
    - Protected by @login_required
    - Displays authenticated user details (no password hashes!)
    - Displays application security checklist status
    """
    db = get_db()
    user = db.execute(
        "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()

    if not user:
        session.clear()
        flash("Session invalid. Please log in again.", "warning")
        return redirect(url_for('login'))

    return render_template('dashboard.html', user=user)


@app.route('/admin')
@admin_required
def admin_dashboard():
    """
    Admin Dashboard:
    - Protected by @admin_required (server-side role check)
    - Only users with role 'admin' can access
    - Shows list of registered users (WITHOUT password hashes)
    - Shows application security checks breakdown
    """
    db = get_db()

    # Query all users - note that password_hash is deliberately NOT selected or displayed
    users = db.execute(
        "SELECT id, username, email, role, created_at FROM users ORDER BY id ASC"
    ).fetchall()

    user_count = len(users)

    return render_template('admin.html', users=users, user_count=user_count)


@app.route('/security')
def security_recommendations():
    """
    Security Recommendations Page:
    Comprehensive explanations of 11 essential application security concepts
    and best practices for production web systems.
    """
    return render_template('security.html')


@app.route('/logout')
def logout():
    """
    Logout:
    - Clears all session data
    - Redirects to login page
    - Cache headers prevent re-viewing protected pages via browser Back button
    """
    session.clear()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for('login'))


# ============================================================================
# CUSTOM ERROR HANDLERS
# SECURITY CONCEPT: Friendly error handling without stack traces
# ============================================================================

@app.errorhandler(400)
def bad_request_error(error):
    return render_template('400.html'), 400


@app.errorhandler(401)
def unauthorized_error(error):
    return render_template('401.html'), 401


@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500


# ============================================================================
# APPLICATION ENTRYPOINT
# ============================================================================

if __name__ == '__main__':
    # Initialize database tables and seed demo admin account on startup
    init_db()
    # In production, debug must be False to prevent execution of arbitrary code via debugger
    app.run(host='127.0.0.1', port=5000, debug=False)
