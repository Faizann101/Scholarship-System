import os
import sqlite3
import uuid
import smtplib
from email.message import EmailMessage
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
MAX_FILE_SIZE = 2 * 1024 * 1024
STATUSES = ["Draft", "Pending Verification", "Verification Rejected", "Verified", "Approved", "Rejected", "Disbursed"]


def valid_email(email):
    email = (email or "").strip()
    return "@" in email and "." in email.rsplit("@", 1)[-1] and " " not in email


def valid_gpa(value):
    try:
        return 0 <= float(value) <= 10
    except (TypeError, ValueError):
        return False


def allowed_file(filename):
    return bool(filename and "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS)


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret-key"),
        DATABASE=os.path.join(app.instance_path, "scholarship.sqlite"),
        UPLOAD_FOLDER=os.path.join(app.instance_path, "uploads"),
        MAX_CONTENT_LENGTH=MAX_FILE_SIZE + 256 * 1024,
        GPA_CUTOFF=float(os.environ.get("SCHOLARSHIP_GPA_CUTOFF", "7.5")),
        INCOME_LIMIT=float(os.environ.get("SCHOLARSHIP_INCOME_LIMIT", "250000")),
        SMTP_HOST=os.environ.get("SMTP_HOST", ""),
        SMTP_PORT=int(os.environ.get("SMTP_PORT", "587")),
        SMTP_USERNAME=os.environ.get("SMTP_USERNAME", ""),
        SMTP_PASSWORD=os.environ.get("SMTP_PASSWORD", ""),
        SMTP_FROM=os.environ.get("SMTP_FROM", ""),
        SMTP_USE_TLS=os.environ.get("SMTP_USE_TLS", "1") == "1",
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    def connect_db():
        db = sqlite3.connect(app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def init_db():
        with connect_db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('student','officer','admin')),
                    phone TEXT DEFAULT '', address TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS applications (
                    id TEXT PRIMARY KEY,
                    student_id INTEGER NOT NULL REFERENCES users(id),
                    full_name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    address TEXT NOT NULL,
                    institution TEXT NOT NULL,
                    course TEXT NOT NULL,
                    year_of_study TEXT NOT NULL,
                    gpa REAL NOT NULL,
                    annual_income REAL NOT NULL,
                    document_name TEXT,
                    document_path TEXT,
                    status TEXT NOT NULL DEFAULT 'Draft',
                    verification_remarks TEXT DEFAULT '',
                    decision_remarks TEXT DEFAULT '',
                    eligible INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    verified_at TEXT,
                    decided_at TEXT,
                    disbursed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS supporting_documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
                    document_name TEXT NOT NULL,
                    document_path TEXT NOT NULL,
                    uploaded_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS application_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
                    actor_id INTEGER REFERENCES users(id),
                    status TEXT NOT NULL,
                    remarks TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_read INTEGER NOT NULL DEFAULT 0
                );
            """)
            # Add missing columns when upgrading the original testing-assignment database.
            existing = {row[1] for row in db.execute("PRAGMA table_info(applications)")}
            additions = {
                "student_id": "INTEGER REFERENCES users(id)",
                "verification_remarks": "TEXT DEFAULT ''",
                "decision_remarks": "TEXT DEFAULT ''",
                "eligible": "INTEGER",
                "verified_at": "TEXT",
                "decided_at": "TEXT",
                "disbursed_at": "TEXT",
            }
            for column, definition in additions.items():
                if column not in existing:
                    db.execute(f"ALTER TABLE applications ADD COLUMN {column} {definition}")
            # Development/demo staff accounts; override passwords using environment variables before deployment.
            for name, email, env_key, default_password, role in [
                ("Verification Officer", os.environ.get("DEMO_OFFICER_EMAIL", "officer@scholarship.local"), "DEMO_OFFICER_PASSWORD", "Officer123!", "officer"),
                ("System Administrator", os.environ.get("DEMO_ADMIN_EMAIL", "admin@scholarship.local"), "DEMO_ADMIN_PASSWORD", "Admin123!", "admin"),
            ]:
                if not db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
                    db.execute("INSERT INTO users(full_name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                               (name, email, generate_password_hash(os.environ.get(env_key, default_password)), role, now()))

    def now():
        return datetime.now().isoformat(timespec="seconds")

    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        with connect_db() as db:
            return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped

    def roles_required(*roles):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                user = current_user()
                if user is None:
                    flash("Please log in to continue.", "warning")
                    return redirect(url_for("login"))
                if user["role"] not in roles:
                    abort(403)
                return view(*args, **kwargs)
            return wrapped
        return decorator

    def get_application(application_id):
        with connect_db() as db:
            row = db.execute("""SELECT a.*, u.full_name AS account_name, u.email AS account_email
                                FROM applications a JOIN users u ON u.id=a.student_id WHERE a.id=?""",
                             (application_id,)).fetchone()
        if row is None:
            abort(404)
        user = current_user()
        if user["role"] == "student" and row["student_id"] != user["id"]:
            abort(403)
        return row

    def notify_status(application_id, status, remarks=""):
        with connect_db() as db:
            app_row = db.execute("SELECT student_id,email FROM applications WHERE id=?", (application_id,)).fetchone()
            if not app_row:
                return
            message = f"Your scholarship application {application_id} status changed to {status}."
            if remarks:
                message += f" Remarks: {remarks}"
            db.execute("INSERT INTO notifications(user_id,application_id,message,created_at) VALUES(?,?,?,?)",
                       (app_row["student_id"], application_id, message, now()))
        # Email is sent when SMTP settings are configured; in-app notification always remains available.
        if app.config["SMTP_HOST"] and app.config["SMTP_FROM"]:
            try:
                email = EmailMessage()
                email["Subject"] = f"Scholarship application update: {status}"
                email["From"] = app.config["SMTP_FROM"]
                email["To"] = app_row["email"]
                email.set_content(message)
                with smtplib.SMTP(app.config["SMTP_HOST"], app.config["SMTP_PORT"], timeout=10) as server:
                    if app.config["SMTP_USE_TLS"]:
                        server.starttls()
                    if app.config["SMTP_USERNAME"]:
                        server.login(app.config["SMTP_USERNAME"], app.config["SMTP_PASSWORD"])
                    server.send_message(email)
            except Exception as exc:
                app.logger.warning("Could not send status email: %s", exc)

    def change_status(application_id, status, remarks="", actor_id=None, field=None, field_value=None):
        timestamp = now()
        with connect_db() as db:
            if field:
                db.execute(f"UPDATE applications SET status=?, updated_at=?, {field}=? WHERE id=?",
                           (status, timestamp, field_value, application_id))
            else:
                db.execute("UPDATE applications SET status=?, updated_at=? WHERE id=?",
                           (status, timestamp, application_id))
            db.execute("INSERT INTO application_history(application_id,actor_id,status,remarks,created_at) VALUES(?,?,?,?,?)",
                       (application_id, actor_id, status, remarks or "", timestamp))
        notify_status(application_id, status, remarks)

    with app.app_context():
        init_db()

    @app.context_processor
    def inject_globals():
        user = current_user()
        unread = 0
        if user:
            with connect_db() as db:
                unread = db.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", (user["id"],)).fetchone()[0]
        return {"current_user": user, "unread_notifications": unread, "gpa_cutoff": app.config["GPA_CUTOFF"], "income_limit": app.config["INCOME_LIMIT"]}

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", message="You do not have permission to access this page."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", message="The requested page or application could not be found."), 404

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("error.html", message="The uploaded request is too large. Each supporting document must be 2 MB or smaller."), 413

    @app.route("/")
    def index():
        user = current_user()
        if not user:
            return render_template("landing.html")
        if user["role"] == "student":
            return redirect(url_for("student_dashboard"))
        if user["role"] == "officer":
            return redirect(url_for("officer_dashboard"))
        return redirect(url_for("admin_dashboard"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            errors = []
            if not name or not email or not password:
                errors.append("Complete all required fields.")
            if email and not valid_email(email):
                errors.append("Enter a valid email address.")
            if len(password) < 8:
                errors.append("Password must contain at least 8 characters.")
            if password != confirm:
                errors.append("Passwords do not match.")
            with connect_db() as db:
                if email and db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
                    errors.append("An account with this email already exists.")
                if errors:
                    return render_template("register.html", errors=errors, data=request.form), 400
                db.execute("INSERT INTO users(full_name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                           (name, email, generate_password_hash(password), "student", now()))
                user_id = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()[0]
            session.clear()
            session["user_id"] = user_id
            flash("Your student account has been created.", "success")
            return redirect(url_for("profile"))
        return render_template("register.html", errors=[], data={})

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            with connect_db() as db:
                user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if not user or not check_password_hash(user["password_hash"], password):
                flash("Email or password is incorrect.", "danger")
                return render_template("login.html", email=email), 401
            session.clear()
            session["user_id"] = user["id"]
            flash(f"Welcome back, {user['full_name']}.", "success")
            if user["role"] == "student":
                return redirect(url_for("student_dashboard"))
            return redirect(url_for("officer_dashboard" if user["role"] == "officer" else "admin_dashboard"))
        return render_template("login.html", email="")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("index"))

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    @roles_required("student")
    def profile():
        user = current_user()
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            phone = request.form.get("phone", "").strip()
            address = request.form.get("address", "").strip()
            if not name or not valid_email(email):
                flash("Enter your name and a valid email address.", "danger")
            else:
                with connect_db() as db:
                    duplicate = db.execute("SELECT id FROM users WHERE email=? AND id<>?", (email, user["id"])).fetchone()
                    if duplicate:
                        flash("That email is already registered to another account.", "danger")
                    else:
                        db.execute("UPDATE users SET full_name=?,email=?,phone=?,address=? WHERE id=?",
                                   (name, email, phone, address, user["id"]))
                        flash("Profile updated.", "success")
                        return redirect(url_for("profile"))
            user = current_user()
        return render_template("profile.html", user=user)

    @app.route("/student")
    @login_required
    @roles_required("student")
    def student_dashboard():
        user = current_user()
        with connect_db() as db:
            applications = db.execute("SELECT * FROM applications WHERE student_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
            notifications = db.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 5", (user["id"],)).fetchall()
        return render_template("student_dashboard.html", applications=applications, notifications=notifications)

    @app.route("/apply", methods=["GET", "POST"])
    @login_required
    @roles_required("student")
    def apply():
        user = current_user()
        if request.method == "POST":
            data = request.form
            fields = ["full_name", "email", "phone", "address", "institution", "course", "year_of_study", "gpa", "annual_income"]
            errors = []
            if any(not data.get(field, "").strip() for field in fields):
                errors.append("Complete all required application fields.")
            if data.get("email") and not valid_email(data["email"]):
                errors.append("Enter a valid email address.")
            if not valid_gpa(data.get("gpa")):
                errors.append("GPA must be a number between 0 and 10.")
            try:
                income = float(data.get("annual_income", ""))
                if income < 0:
                    errors.append("Annual family income cannot be negative.")
            except ValueError:
                errors.append("Enter a valid annual family income.")
                income = 0
            uploads = [f for f in request.files.getlist("documents") if f and f.filename]
            if not uploads:
                legacy_upload = request.files.get("document")
                if legacy_upload and legacy_upload.filename:
                    uploads = [legacy_upload]
            if not uploads:
                errors.append("Upload at least one supporting document.")
            for upload in uploads:
                if not allowed_file(upload.filename):
                    errors.append(f"Unsupported document type for {secure_filename(upload.filename)}. Use PDF, PNG, JPG, or JPEG.")
                elif len(upload.read()) > MAX_FILE_SIZE:
                    errors.append(f"{secure_filename(upload.filename)} must be 2 MB or smaller.")
                upload.stream.seek(0)
            if errors:
                return render_template("application.html", errors=errors, data=data, user=user), 400
            application_id = "SCH-" + uuid.uuid4().hex[:8].upper()
            saved_files = []
            timestamp = now()
            try:
                for upload in uploads:
                    safe_name = secure_filename(upload.filename)
                    stored_name = application_id + "_" + uuid.uuid4().hex[:6] + "_" + safe_name
                    saved_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
                    upload.save(saved_path)
                    saved_files.append((safe_name, saved_path))
                primary_name, primary_path = saved_files[0]
                with connect_db() as db:
                    db.execute("""INSERT INTO applications
                        (id,student_id,full_name,email,phone,address,institution,course,year_of_study,gpa,annual_income,
                         document_name,document_path,status,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'Pending Verification',?,?)""",
                        (application_id,user["id"],data["full_name"].strip(),data["email"].strip(),data["phone"].strip(),
                         data["address"].strip(),data["institution"].strip(),data["course"].strip(),data["year_of_study"].strip(),
                         float(data["gpa"]),income,primary_name,primary_path,timestamp,timestamp))
                    for document_name, document_path in saved_files:
                        db.execute("INSERT INTO supporting_documents(application_id,document_name,document_path,uploaded_at) VALUES(?,?,?,?)",
                                   (application_id,document_name,document_path,timestamp))
                    db.execute("INSERT INTO application_history(application_id,actor_id,status,remarks,created_at) VALUES(?,?,?,?,?)",
                               (application_id,user["id"],"Pending Verification","Application submitted",timestamp))
            except Exception:
                for _, saved_path in saved_files:
                    if os.path.exists(saved_path):
                        os.remove(saved_path)
                raise
            notify_status(application_id, "Pending Verification")
            flash("Application submitted successfully.", "success")
            return redirect(url_for("application_detail", application_id=application_id))
        return render_template("application.html", errors=[], data={"full_name": user["full_name"], "email": user["email"], "phone": user["phone"], "address": user["address"]}, user=user)

    @app.route("/applications/<application_id>")
    @login_required
    def application_detail(application_id):
        application = get_application(application_id)
        with connect_db() as db:
            history = db.execute("SELECT h.*,u.full_name AS actor_name FROM application_history h LEFT JOIN users u ON u.id=h.actor_id WHERE application_id=? ORDER BY h.created_at DESC", (application_id,)).fetchall()
            documents = db.execute("SELECT * FROM supporting_documents WHERE application_id=? ORDER BY id", (application_id,)).fetchall()
        return render_template("application_detail.html", application=application, history=history, documents=documents)

    @app.route("/applications/<application_id>/edit", methods=["GET", "POST"])
    @login_required
    @roles_required("student")
    def edit_application(application_id):
        application = get_application(application_id)
        if application["status"] not in ("Pending Verification", "Verification Rejected"):
            flash("This application can no longer be edited at its current stage.", "warning")
            return redirect(url_for("application_detail", application_id=application_id))
        if request.method == "POST":
            data = request.form
            required = ["full_name", "email", "phone", "address", "institution", "course", "year_of_study", "gpa", "annual_income"]
            errors = []
            if any(not data.get(k, "").strip() for k in required): errors.append("Complete all required fields.")
            if not valid_email(data.get("email")): errors.append("Enter a valid email address.")
            if not valid_gpa(data.get("gpa")): errors.append("GPA must be between 0 and 10.")
            try:
                income = float(data.get("annual_income", ""))
                if income < 0: errors.append("Income cannot be negative.")
            except ValueError:
                income = 0
                errors.append("Enter a valid annual income.")
            upload = request.files.get("document")
            if upload and upload.filename:
                if not allowed_file(upload.filename): errors.append("Unsupported document type.")
                elif len(upload.read()) > MAX_FILE_SIZE: errors.append("Document must be 2 MB or smaller.")
                upload.stream.seek(0)
            if errors: return render_template("edit_application.html", application=application, errors=errors, data=data), 400
            document_name, document_path = application["document_name"], application["document_path"]
            if upload and upload.filename:
                document_name = secure_filename(upload.filename)
                document_path = os.path.join(app.config["UPLOAD_FOLDER"], application_id + "_" + document_name)
                upload.save(document_path)
            with connect_db() as db:
                db.execute("""UPDATE applications SET full_name=?,email=?,phone=?,address=?,institution=?,course=?,year_of_study=?,gpa=?,annual_income=?,document_name=?,document_path=?,verification_remarks='',status='Pending Verification',updated_at=? WHERE id=?""",
                           (data["full_name"].strip(),data["email"].strip(),data["phone"].strip(),data["address"].strip(),data["institution"].strip(),data["course"].strip(),data["year_of_study"].strip(),float(data["gpa"]),income,document_name,document_path,now(),application_id))
                db.execute("INSERT INTO application_history(application_id,actor_id,status,remarks,created_at) VALUES(?,?,?,?,?)", (application_id,current_user()["id"],"Pending Verification","Student updated and resubmitted application",now()))
            notify_status(application_id, "Pending Verification", "Application updated and resubmitted")
            flash("Application updated and resubmitted for verification.", "success")
            return redirect(url_for("application_detail", application_id=application_id))
        return render_template("edit_application.html", application=application, errors=[], data=application)

    @app.route("/applications/<application_id>/documents/<int:document_id>")
    @login_required
    def download_supporting_document(application_id, document_id):
        from flask import send_file
        get_application(application_id)
        with connect_db() as db:
            document = db.execute("SELECT * FROM supporting_documents WHERE id=? AND application_id=?", (document_id, application_id)).fetchone()
        if not document or not os.path.isfile(document["document_path"]):
            abort(404)
        return send_file(document["document_path"], as_attachment=True, download_name=document["document_name"])

    @app.route("/applications/<application_id>/document")
    @login_required
    def download_document(application_id):
        from flask import send_file
        application = get_application(application_id)
        user = current_user()
        if user["role"] not in ("student", "officer", "admin"): abort(403)
        if not application["document_path"] or not os.path.isfile(application["document_path"]): abort(404)
        return send_file(application["document_path"], as_attachment=True, download_name=application["document_name"] or "supporting-document")

    @app.route("/officer")
    @login_required
    @roles_required("officer")
    def officer_dashboard():
        with connect_db() as db:
            applications = db.execute("SELECT * FROM applications WHERE status IN ('Pending Verification','Verification Rejected') ORDER BY created_at ASC").fetchall()
        return render_template("officer_dashboard.html", applications=applications)

    @app.route("/officer/applications/<application_id>", methods=["GET", "POST"])
    @login_required
    @roles_required("officer")
    def verify_application(application_id):
        application = get_application(application_id)
        if application["status"] not in ("Pending Verification", "Verification Rejected"):
            flash("This application has already passed the verification stage.", "warning")
            return redirect(url_for("officer_dashboard"))
        if request.method == "POST":
            action = request.form.get("action")
            remarks = request.form.get("remarks", "").strip()
            if action == "reject" and not remarks:
                flash("Enter remarks when rejecting an application.", "danger")
                return redirect(url_for("verify_application", application_id=application_id))
            if action == "verify":
                change_status(application_id, "Verified", remarks, current_user()["id"], "verified_at", now())
                flash("Application verified and forwarded to the administrator.", "success")
            elif action == "reject":
                with connect_db() as db:
                    db.execute("UPDATE applications SET verification_remarks=? WHERE id=?", (remarks, application_id))
                change_status(application_id, "Verification Rejected", remarks, current_user()["id"], "verified_at", now())
                flash("Application rejected at verification stage.", "success")
            else:
                abort(400)
            return redirect(url_for("officer_dashboard"))
        with connect_db() as db:
            history = db.execute("SELECT * FROM application_history WHERE application_id=? ORDER BY created_at DESC", (application_id,)).fetchall()
            documents = db.execute("SELECT * FROM supporting_documents WHERE application_id=? ORDER BY id", (application_id,)).fetchall()
        return render_template("verify_application.html", application=application, history=history, documents=documents)

    @app.route("/admin")
    @login_required
    @roles_required("admin")
    def admin_dashboard():
        with connect_db() as db:
            applications = db.execute("SELECT * FROM applications WHERE status IN ('Verified','Approved','Rejected','Disbursed') ORDER BY updated_at DESC").fetchall()
            counts = {row["status"]: row["count"] for row in db.execute("SELECT status,COUNT(*) AS count FROM applications GROUP BY status").fetchall()}
        return render_template("admin_dashboard.html", applications=applications, counts=counts)

    @app.route("/admin/applications/<application_id>", methods=["GET", "POST"])
    @login_required
    @roles_required("admin")
    def decide_application(application_id):
        application = get_application(application_id)
        if application["status"] not in ("Verified", "Approved"):
            flash("Only verified applications can receive an administrator decision.", "warning")
            return redirect(url_for("admin_dashboard"))
        eligible = application["gpa"] >= app.config["GPA_CUTOFF"] and application["annual_income"] <= app.config["INCOME_LIMIT"]
        if request.method == "POST":
            action = request.form.get("action")
            remarks = request.form.get("remarks", "").strip()
            if action in ("approve", "reject") and application["status"] == "Verified":
                if action == "approve" and not eligible:
                    flash("The applicant does not meet the configured GPA and income criteria and cannot be approved.", "danger")
                    return redirect(url_for("decide_application", application_id=application_id))
                status = "Approved" if action == "approve" else "Rejected"
                with connect_db() as db:
                    db.execute("UPDATE applications SET eligible=?,decision_remarks=? WHERE id=?", (int(eligible), remarks, application_id))
                change_status(application_id, status, remarks, current_user()["id"], "decided_at", now())
                flash(f"Application {status.lower()}.", "success")
                return redirect(url_for("admin_dashboard"))
            if action == "disburse" and application["status"] == "Approved":
                change_status(application_id, "Disbursed", remarks or "Scholarship marked as disbursed", current_user()["id"], "disbursed_at", now())
                flash("Scholarship marked as disbursed.", "success")
                return redirect(url_for("admin_dashboard"))
            abort(400)
        with connect_db() as db:
            history = db.execute("SELECT h.*,u.full_name AS actor_name FROM application_history h LEFT JOIN users u ON u.id=h.actor_id WHERE application_id=? ORDER BY h.created_at DESC", (application_id,)).fetchall()
        return render_template("decide_application.html", application=application, eligible=eligible, history=history)

    @app.route("/admin/reports")
    @login_required
    @roles_required("admin")
    def reports():
        with connect_db() as db:
            rows = db.execute("SELECT status,COUNT(*) AS total FROM applications GROUP BY status ORDER BY status").fetchall()
            applications = db.execute("SELECT id,full_name,email,gpa,annual_income,status,created_at,updated_at FROM applications ORDER BY created_at DESC").fetchall()
        return render_template("reports.html", rows=rows, applications=applications)

    @app.route("/notifications")
    @login_required
    def notifications():
        user = current_user()
        with connect_db() as db:
            rows = db.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
            db.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (user["id"],))
        return render_template("notifications.html", notifications=rows)

    @app.route("/health")
    def health():
        return {"status": "ok"}

    return app


if __name__ == "__main__":
    create_app().run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
