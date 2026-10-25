# Multi-Stage Scholarship and Financial Aid Application & Verification System

A Flask + SQLite implementation of the functional workflow described in the project's SRS: student registration and profile management, scholarship application submission and editing, supporting-document upload, verification by a Verification Officer, GPA/income eligibility evaluation, administrator decision and disbursement, status history, notifications, and status reports.

## Technology
- Python 3.11+
- Flask
- SQLite
- HTML and CSS
- Werkzeug password hashing

## Run locally (Windows / VS Code)
1. Extract this folder and open it in VS Code.
2. Open **Terminal → New Terminal**.
3. Create and activate a virtual environment:
   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass`, then activate again.
4. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
5. Start the app:
   ```powershell
   python app.py
   ```
6. Open `http://127.0.0.1:5000` in your browser. Stop the server with `Ctrl+C`.

## Demo staff accounts
For local demonstration only, the application seeds these staff accounts on first run:

| Role | Email | Password |
|---|---|---|
| Verification Officer | `officer@scholarship.local` | `Officer123!` |
| Administrator | `admin@scholarship.local` | `Admin123!` |

Students create their own accounts using the registration page. Demo staff passwords can be changed using `DEMO_OFFICER_PASSWORD` and `DEMO_ADMIN_PASSWORD` environment variables before the database is first initialized. Do not use the default credentials or development secret in a public deployment.

## Configurable eligibility criteria
The SRS requires eligibility to be evaluated using GPA and annual family income, but does not specify numeric cutoffs. The app therefore uses clearly configurable demonstration defaults:
- GPA cutoff: `7.5` (applicant GPA must be greater than or equal to this value)
- Annual family income limit: `250000` (income must be less than or equal to this value)

Set `SCHOLARSHIP_GPA_CUTOFF` and `SCHOLARSHIP_INCOME_LIMIT` environment variables to change them. Confirm the intended values with your instructor if specific institutional criteria are expected.

## Optional email notifications
In-app notifications and status history work without extra configuration. To send actual email, configure SMTP environment variables before starting the app:
- `SMTP_HOST`
- `SMTP_PORT` (defaults to `587`)
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_FROM`
- `SMTP_USE_TLS` (`1` by default)

If SMTP is not configured, status changes are still recorded in the application's notification centre. Email delivery has not been configured for a real mail account in this project.

## Main workflow
1. Register as a student and submit a scholarship application with one PDF/JPG/PNG supporting document (maximum 2 MB).
2. Log out and sign in as the Verification Officer. Review the application and verify it or reject it with remarks.
3. If rejected at verification, the student can edit and resubmit it.
4. Sign in as the Administrator. View verified applications, inspect the calculated eligibility, approve eligible applications or reject them, and mark approved applications as disbursed.
5. The student can see status updates, remarks, and the recorded history from the dashboard.
6. The Administrator can view and print application status reports.

## Data and uploads
SQLite database and uploaded files are created under `instance/` on first run. Do not commit the runtime database, uploaded student documents, secrets, or credentials to a public repository. This is a coursework/demo application and should not be deployed publicly without additional production security and privacy review.
