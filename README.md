# Flask JWT Authentication Example

This is a simple Flask web application demonstrating user registration, login, and JWT-based authentication. It provides both web routes for user interaction and API routes for handling user data and authentication via JWT.

## Features

- **User Registration** (`/register`): Allows users to register with an email and password.
- **User Login** (`/login`): Allows users to log in with email and password and receive a JWT token.
- **JWT Protected Routes**:
  - **Dashboard** (`/dashboard`): Requires a valid JWT token to access the dashboard.
  - **API Routes**: 
    - **Register** (`/api/register`): Registers a user through an API.
    - **Login** (`/api/login`): Logs in a user through an API and returns a JWT token.
    - **Home** (`/api/home`): Protected API route that requires JWT authentication.

## Requirements

- Python 3.x
- Flask
- Flask-SQLAlchemy
- Werkzeug
- PyJWT

## Installation

### 1. Clone the Repository

Clone the repository to your local machine:
```bash
git clone <repository_url>


```bash
cd <project-folder>
pip install -r requirements.txt

```bash
python
>>> from app import db
>>> db.create_all()
>>> exit()


```bash
python app.py
