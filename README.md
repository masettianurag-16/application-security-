# 🔒 Secure User Authentication & Application Security Demo

An educational web application demonstrating defensive programming and core web application security concepts using Python, Flask, and SQLite.

---

## 📌 1. Project Title & Overview

**Project Title:** Secure User Authentication & Application Security Demo  
**Project Type:** Cybersecurity / Web Application Security Demonstration  
**Target Audience:** Computer Science Students, Academic Evaluators, and Junior Security Engineers / Developers  

### Overview
Modern web applications face constant threats such as SQL Injection (SQLi), Cross-Site Scripting (XSS), credential stuffing, brute force attacks, and privilege escalation. This project demonstrates how fundamental security principles can be implemented from the ground up in a lightweight Python and Flask web stack without relying on heavy external enterprise frameworks.

The application implements a full authentication and role-based authorization lifecycle:
- Secure account registration with defensive input validation.
- One-way password hashing using the modern `scrypt` key derivation function via Werkzeug.
- Unified login interface (supporting username or email) that defends against account enumeration attacks.
- Server-side Session Management configured with strict cookie flags (`HttpOnly`, `SameSite=Lax`).
- Role-Based Access Control (RBAC) separating regular users from administrative staff using server-side Python decorators.
- Defensive response headers preventing unauthorized cache re-entry upon logout.
- Parameterized database operations that neutralize SQL injection vulnerabilities.
- Custom user-friendly HTTP error pages (400, 401, 403, 404, 500) preventing information disclosure via stack traces.

---

## ❓ 2. Problem Statement

Many beginner-level web applications store user credentials in plain text or using obsolete cryptographic algorithms (such as MD5 or SHA-1). Furthermore, security is often mistakenly treated as a cosmetic concern handled exclusively on the client side (e.g., hiding HTML buttons or relying purely on browser form checks). 

Such insecure design patterns expose systems to:
1. **Credential Exposure:** Attackers dumping databases can read plain-text passwords immediately.
2. **Client-Side Bypass:** Attackers intercepting or crafting raw HTTP requests easily bypass browser-based input checks.
3. **Privilege Escalation:** Unprivileged users navigating directly to administrative endpoints (e.g., `/admin`) can view or alter sensitive data if the server fails to verify user roles.
4. **Information Leakage:** Detailed system stack traces returned on runtime errors reveal internal directory paths, database engines, and library versions to adversaries.
5. **Session Hijacking & Replay:** Stale browser caches and unprotected session cookies leave active sessions exposed to unauthorized access on shared devices.

This project addresses these challenges by building an explicit, auditable, and pedagogical reference implementation of secure authentication and authorization mechanics.

---

## 🎯 3. Objectives

The primary objectives of this project are:
- **Demonstrate Cryptographic Password Storage:** Illustrate why and how passwords must be converted into irreversible salted hashes (`scrypt`) before entering a database.
- **Implement Server-Side Input Validation:** Enforce strict length, format, and complexity rules on the backend where client tampering is impossible.
- **Enforce Server-Side Role-Based Authorization:** Secure high-privilege endpoints using Python decorators so unauthorized access attempts trigger an immediate `HTTP 403 Forbidden`.
- **Prevent SQL Injection & XSS:** Employ parameterized queries for every database operation and leverage Jinja2 contextual auto-escaping for HTML output.
- **Implement Defensive Session and Header Controls:** Configure cookies with protective security flags and instruct browser caches not to store sensitive pages.
- **Prevent User Enumeration:** Provide uniform, generic authentication feedback so malicious actors cannot infer whether a username or email is registered.
- **Deliver Safe Error Handling:** Replace default framework debug stack traces with sanitized, user-friendly error templates.

---

## ✨ 4. Features Actually Implemented

The application includes the following working features:

| Feature | Description | Implementation Details |
|---|---|---|
| **User Registration** | Public registration form with complete validation and collision detection. | Checks field presence, character constraints, email formatting, and password complexity; prevents duplicate usernames or emails. |
| **Password Hashing** | One-way hashing of user credentials before database storage. | Uses Werkzeug's `generate_password_hash(..., method='scrypt')`. Plain text passwords are never stored or logged. |
| **Flexible Authentication** | Secure login supporting either username or registered email address. | Queries credentials via parameterized SQL; verifies passwords using `check_password_hash()`. |
| **Anti-Enumeration Login** | Generic login error reporting. | Always outputs *"Invalid username or password."* on failure, regardless of whether the account exists or the password was incorrect. |
| **Session Management** | Server-side user session tracking. | Stores user ID, username, and role inside a signed Flask session cookie. Applies `HttpOnly=True` and `SameSite='Lax'`. |
| **Role-Based Authorization** | Separation between standard `user` and privileged `admin` accounts. | Custom `@login_required` and `@admin_required` decorators verify permissions on the server before executing route logic. |
| **User Dashboard** | Protected profile screen for authenticated users. | Displays username, email, assigned role, account creation timestamp, and a live security protection status checklist. |
| **Admin Dashboard** | High-privilege management panel accessible only to administrators. | Lists registered users (ID, username, email, role, date) while strictly omitting password hashes. Includes a security checks overview. |
| **Unauthorized Access Defense** | Server-side boundary protection. | Returns `HTTP 403 Forbidden` if a regular user navigates to `/admin`. Redirects unauthenticated users to `/login`. |
| **Defensive Cache Control** | HTTP response header enforcement. | Appends `Cache-Control: no-store, no-cache, must-revalidate` to prevent back-button viewing of protected pages after logout. |
| **Secure Logout** | Immediate session termination. | Clears the Flask session dictionary (`session.clear()`) and redirects the user to the login screen. |
| **Security Recommendations Page** | Dedicated educational reference guide. | Documents 12 production-grade security practices (MFA, HTTPS, secrets management, rate limiting, etc.) for real-world software. |
| **Sanitized Error Pages** | Custom HTTP exception views. | Dedicated templates for HTTP 400 (Bad Request), 401 (Unauthorized), 403 (Forbidden), 404 (Not Found), and 500 (Internal Server Error). |
| **Automatic Database Seeding** | Zero-configuration initial startup. | Automatically creates the SQLite database table schema and seeds a test admin account on first launch. |

---

## 🛠️ 5. Technologies & Libraries Used

### Backend Stack
- **Python (3.10+)**: Core programming language used for route handling, validation logic, and server execution.
- **Flask (>= 3.0.0)**: Lightweight WSGI web application micro-framework used to handle HTTP routing, request/response cycles, and session management.
- **Werkzeug (>= 3.0.0)**: Comprehensive WSGI utility library used specifically for password hashing and verification (`scrypt`).
- **SQLite3 (Python Standard Library)**: Embedded, serverless relational database engine used for local data persistence.
- **re (Python Standard Library)**: Regular expression engine used for server-side string validation rules.
- **functools (Python Standard Library)**: Used for route decorators (`@wraps`) to implement clean authorization wrappers.

### Frontend Stack
- **HTML5**: Semantic web markup structuring forms, tables, badges, and feedback blocks.
- **Jinja2**: Server-side template engine integrated into Flask, providing dynamic layout inheritance and automatic output escaping to protect against Reflected XSS.
- **CSS3 (Custom)**: Fully custom responsive stylesheet (`static/style.css`) incorporating modern CSS variables, accessible color schemes, cards, data tables, and mobile-friendly layouts without external UI dependencies.

---

## 📂 6. Project Folder Structure

```text
Application Security/
│
├── app.py                  # Main Flask application file (routes, security logic, DB setup)
├── database.db             # Local SQLite database file (created automatically on startup)
├── requirements.txt        # Python package dependencies (Flask, Werkzeug)
├── README.md               # Complete project documentation
│
├── static/
│   └── style.css           # Custom responsive stylesheet (layout, typography, components)
│
└── templates/
    ├── base.html           # Master layout template (navigation, flash messages, footer)
    ├── index.html          # Public home page and feature overview
    ├── register.html       # User registration interface with input requirements
    ├── login.html          # Authentication interface with local demo notice
    ├── dashboard.html      # Protected user profile and security status checklist
    ├── admin.html          # Protected administrator dashboard with user audit table
    ├── security.html       # Security recommendations and production checklist
    ├── 400.html            # Custom error template: HTTP 400 Bad Request
    ├── 401.html            # Custom error template: HTTP 401 Unauthorized
    ├── 403.html            # Custom error template: HTTP 403 Access Denied
    ├── 404.html            # Custom error template: HTTP 404 Page Not Found
    └── 500.html            # Custom error template: HTTP 500 Internal Server Error
```

---

## ⚙️ 7. Installation & Setup Instructions

Follow these steps to set up the project locally on your machine:

### Prerequisites
- Python 3.10 or higher installed. Verify by running:
  ```bash
  python --version
  ```
- `pip` package manager installed.

### Step 1: Clone or Download the Project
Navigate to the directory where the project files reside:
```bash
cd "Application Security"
```

### Step 2: Create a Virtual Environment (Recommended)
Creating an isolated virtual environment prevents library version conflicts across projects:

- **On Windows (Command Prompt or PowerShell):**
  ```powershell
  python -m venv venv
  .\venv\Scripts\activate
  ```

- **On macOS / Linux:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### Step 3: Install Required Dependencies
Install the required packages using the project's `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## 🚀 8. How to Run the Project

### Step 1: Start the Flask Server
Run the primary application script:
```bash
python app.py
```

Upon startup, the console will output:
```text
[Security Demo] Initialized database and seeded demo admin account.
 * Serving Flask app 'app'
 * Debug mode: off
 * Running on http://127.0.0.1:5000
```

### Step 2: Access the Application
Open any web browser and navigate to:
```text
http://127.0.0.1:5000
```

### Step 3: Test Accounts & Verification

#### Default Local Administrator Account
A demonstration administrator account is automatically generated for local testing purposes:
- **Username:** `admin`
- **Password:** `Admin@12345`
- **Role:** `admin`

> ⚠️ **Notice:** This credential is created solely for local offline evaluation. It must never be utilized in a public or production system.

#### Creating a Standard User Account
1. Click **Register** on the navigation bar.
2. Enter a valid username (e.g., `student_user`), valid email (e.g., `student@example.com`), and a password containing at least 8 characters and at least one numeric digit (e.g., `SecureCode2026`).
3. Upon registration, log in to access the **User Dashboard**.
4. Attempting to manually navigate to `http://127.0.0.1:5000/admin` using this standard user account will trigger the custom **403 Forbidden Access Denied** page.

---

## 🧠 9. Explanation of How the Code Works

The architecture of `app.py` is organized into distinct security layers:

```text
[ Incoming HTTP Request ]
          │
          ▼
┌──────────────────────────────────────────────┐
│  1. Defensive Routing & Parameter Parsing    │
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│  2. Server-Side Input Validation (Regex)     │
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│  3. Access Control Layer (@login / @admin)   │
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│  4. Cryptographic & Database Layer (scrypt)  │
│     - Parameterized SQL Operations (?)       │
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│  5. Jinja2 Contextual Auto-Escaping (Anti-XSS)│
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│  6. Security Headers Hook (Cache & Frame)    │
└──────────────────────────────────────────────┘
          │
          ▼
[ Outgoing HTTP Response ]
```

### 1. Database Initialization & Connection Safety (`get_db`, `init_db`)
- Database connections are scoped to the Flask request lifecycle using Flask's application context global `g`. 
- The `@app.teardown_appcontext` hook ensures that open database cursors and connections are cleanly terminated when a request finishes, preventing resource leaks.
- The `init_db()` routine defines a `users` table:
  ```sql
  CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  ```
- If the `admin` account is missing, it is created with an `scrypt` password hash.

### 2. Password Hashing Strategy
- Rather than storing plain text or using deprecated algorithms like MD5 or SHA-256, the application utilizes:
  - `generate_password_hash(password, method='scrypt')`
  - `check_password_hash(stored_hash, password)`
- `scrypt` is a memory-hard and computationally intensive key derivation function designed to make hardware-accelerated brute-force attacks (e.g., via GPUs or ASICs) prohibitively expensive.

### 3. Server-Side Input Validation (`validate_registration_input`)
Validation takes place on the backend before any database query is issued:
- **Empty Field Check:** Ensures none of the mandatory fields are omitted or composed solely of whitespace.
- **Username Length & Character Set:** Restricts usernames to 3–30 characters and permits only alphanumeric characters and underscores (`^[a-zA-Z0-9_]+$`).
- **Email Validation:** Evaluates address syntax using standard pattern matching (`^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$`) and limits length to 100 characters.
- **Password Complexity:** Enforces a minimum length of 8 characters and requires at least one numeric digit (`0-9`).
- **Confirmation Check:** Verifies that `password` and `confirm_password` match exactly.

### 4. Authentication & Anti-Enumeration Logic (`/login`)
- Accepts either a username or an email address in a single identifier input.
- Database lookup uses a parameterized query:
  ```python
  user = db.execute(
      "SELECT * FROM users WHERE username = ? OR email = ?",
      (identifier, identifier)
  ).fetchone()
  ```
- If the user does not exist or if `check_password_hash` evaluates to `False`, the application returns the identical error message:
  ```python
  flash("Invalid username or password.", "danger")
  ```
- This prevents **Username Enumeration**, where an attacker uses error message variations to discover valid usernames on a system.

### 5. Server-Side Authorization Decorators (`@login_required`, `@admin_required`)
Access controls are implemented as reusable Python function decorators:
- **`@login_required`**: Intercepts requests to ensure `'user_id'` exists within the session. Unauthenticated users are redirected to `/login`.
- **`@admin_required`**: First verifies that the user is authenticated, then inspects `session.get('role')`. If the role is not `'admin'`, execution stops immediately with `abort(403)`, rendering the custom 403 Forbidden template.
- This guarantees authorization is enforced on the server rather than relying on whether an administrative link is visible in the HTML.

### 6. Mitigation of SQL Injection & Cross-Site Scripting (XSS)
- **SQL Injection Defense:** All SQL operations throughout `app.py` utilize parameterized query syntax (the `?` placeholder). User values are passed separately as tuple parameters to the database driver, preventing user input from altering query structure.
- **XSS Defense:** Variables rendered into HTML templates (such as `{{ user.username }}`) are automatically processed through Jinja2's contextual escaping, rendering injected `<script>` tags or malicious HTML entities harmless as literal text.

### 7. Defensive HTTP Response Headers (`@app.after_request`)
The `add_security_headers` function runs after every request to apply defensive HTTP headers:
- `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`: Instructs browsers and proxies not to store rendered pages. If a user logs out and presses the browser's "Back" button, the browser is forced to re-request the page, triggering the authentication check rather than displaying cached sensitive data.
- `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing.
- `X-Frame-Options: SAMEORIGIN`: Protects pages against clickjacking attacks in embedded iframes.

---

## 🖼️ 10. Screenshots

*(Screenshots can be added here when presenting the project in a portfolio or report)*

### 1. Home Page & Security Overview
<img width="1890" height="961" alt="Screenshot 2026-10-28 212336" src="https://github.com/user-attachments/assets/a5fa5bc3-b53c-4482-8177-da70f94266fe" />
<img width="1902" height="893" alt="Screenshot 2026-10-28 212351" src="https://github.com/user-attachments/assets/9f6c4eb0-78a7-45ad-a6ac-7c1dff24f0ef" />
<img width="1896" height="938" alt="Screenshot 2026-10-28 212409" src="https://github.com/user-attachments/assets/2fef53e7-7259-4ca7-8280-1b0ded4c58d3" />


### 2. User Registration & Validation
<img width="1886" height="910" alt="Screenshot 2026-10-28 212501" src="https://github.com/user-attachments/assets/90686b3a-9bb3-43b2-b26c-7ef1e35f9aa0" />
<img width="1887" height="947" alt="Screenshot 2026-10-28 212512" src="https://github.com/user-attachments/assets/3cbfa99e-4829-4e00-b7a7-94786639e028" />
<img width="1887" height="905" alt="Screenshot 2026-10-28 212709" src="https://github.com/user-attachments/assets/83bca2e0-ece1-4e00-827a-3e97bd21d20d" />


### 3. User Dashboard & Security Checklist
<img width="1896" height="882" alt="Screenshot 2026-10-28 212737" src="https://github.com/user-attachments/assets/b0851a68-8866-44dd-a3d9-42eec817c170" />
<img width="1875" height="902" alt="Screenshot 2026-10-28 212920" src="https://github.com/user-attachments/assets/05d40b00-54b5-4d1b-9873-13f4b632e254" />
<img width="1865" height="902" alt="Screenshot 2026-10-28 212934" src="https://github.com/user-attachments/assets/499aa024-5482-4b87-be86-36aac0bc7957" />


### 4. Admin Dashboard (Role-Based Access)
<img width="1892" height="897" alt="Screenshot 2026-10-28 213106" src="https://github.com/user-attachments/assets/521cd505-2783-4996-b4a0-570ea87e1eec" />
<img width="947" height="723" alt="Screenshot 2026-10-28 213120" src="https://github.com/user-attachments/assets/b6a917f8-e955-4d29-a256-0f4fca0f0421" />
<img width="1900" height="915" alt="Screenshot 2026-10-28 213209" src="https://github.com/user-attachments/assets/c55a8731-c9c0-4fa5-997d-82273bda8f4a" />


### 5. Custom 403 Forbidden (Access Denied)
<img width="1881" height="951" alt="Screenshot 2026-10-28 213410" src="https://github.com/user-attachments/assets/e445e3ff-072b-4c58-b450-eaefdddd9f3f" />


## 🛡️ 11. Security Considerations & Limitations

While this project implements robust introductory security measures, it is designed as an educational demonstration. In the interest of full transparency and academic honesty, the following considerations and limitations apply:

| Category | Current Implementation | Real-World Production Requirement |
|---|---|---|
| **Transport Encryption** | Runs locally over unencrypted HTTP. | Production must enforce **HTTPS/TLS** to prevent eavesdropping of credentials and cookies over the wire. |
| **CSRF Defense** | Utilizes `SameSite=Lax` cookie attribute. | Real applications should incorporate anti-CSRF challenge tokens (e.g., using `Flask-WTF`). |
| **Rate Limiting** | No request throttling implemented. | Production requires rate limiting (e.g., Flask-Limiter or API Gateways) to mitigate automated brute-force attacks. |
| **Account Lockout** | Users can attempt passwords indefinitely. | Production systems lock or throttle accounts after a set number of consecutive failed attempts. |
| **Secrets Management** | Default local fallback secret key in code. | Secret keys must be loaded exclusively from secure environment variables or vault services. |
| **Database Engine** | Local embedded SQLite database. | Production architectures require managed relational databases (e.g., PostgreSQL) with least-privilege database user permissions. |
| **Multi-Factor Auth (MFA)** | Single-factor authentication (password). | High-assurance systems require TOTP/MFA or hardware security keys (WebAuthn). |

---

## 🔮 12. Future Improvements

To expand this application into an enterprise-grade platform, the following enhancements are planned:
1. **CSRF Protection:** Integrate `Flask-WTF` to generate and validate unique anti-forgery tokens for all state-changing `POST` requests.
2. **Rate Limiting & IP Throttling:** Add `Flask-Limiter` with Redis to prevent brute-force attacks on `/login` and automated registration spam.
3. **Multi-Factor Authentication (MFA):** Add time-based one-time password (TOTP) generation and verification compatible with Google Authenticator or Microsoft Authenticator.
4. **Password Reset Flow via Timed Tokens:** Implement secure password recovery utilizing cryptographic, time-limited tokens sent via verified email channels.
5. **Centralized Security Audit Logging:** Implement structured application logging capturing timestamps, client IP addresses, user agents, failed login attempts, and authorization rejections.
6. **Containerization:** Package the application using a `Dockerfile` and `docker-compose.yml` configured with a production WSGI server (Gunicorn) and a reverse proxy (Nginx).

---

## 📄 License & Academic Integrity

This project is developed for educational and portfolio demonstration purposes. It is structured to help students and developers understand practical web application security fundamentals.

Feel free to study, reference, and build upon this codebase for your coursework and academic projects.
