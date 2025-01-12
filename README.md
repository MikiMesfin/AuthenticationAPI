# Django Authentication System

A comprehensive authentication system with:
- Custom User Model
- Role-Based Access Control (RBAC)
- Two-Factor Authentication
- Email Verification
- Password Reset Functionality

## Setup
1. Clone the repository
2. Create virtual environment: `python -m venv venv`
3. Install dependencies: `pip install -r requirements.txt`
4. Run migrations: `python manage.py migrate`
5. Initialize RBAC: `python manage.py init_rbac`
6. Run server: `python manage.py runserver`
