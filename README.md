!!!!!! THIS IS A NON SECURE VERSION FOR DEMONSTRATIO/SUBMISSION REASONS DO NOT USE IN A REAL PROJECT!!!!!




# Communication_LTD - Cybersecurity Project

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-latest-green.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)
![MySQL](https://img.shields.io/badge/MySQL-8.0-orange.svg?logo=mysql&logoColor=white)
![Security](https://img.shields.io/badge/security-enhanced-brightgreen.svg)
![HMAC-SHA256](https://img.shields.io/badge/HMAC--SHA256-password_hashing-red.svg)
![JWT](https://img.shields.io/badge/JWT-authentication-yellow.svg)
![XSS](https://img.shields.io/badge/XSS-protected-brightgreen.svg)
![SQLi](https://img.shields.io/badge/SQL_Injection-protected-brightgreen.svg)
![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

## Project Overview
A comprehensive cybersecurity project implementing secure web development principles for an Internet Service Provider management system. This project demonstrates enterprise-grade security measures and protection against common web vulnerabilities for educational purposes.

Communication_LTD is a secure Internet Service Provider management system developed as a comprehensive cybersecurity final project. The system demonstrates both secure coding practices and protection mechanisms against common web vulnerabilities including XSS and SQL Injection attacks.

The project implements enterprise-grade security measures while maintaining educational value by providing examples of both secure and vulnerable code patterns for learning purposes.


## Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Security Implementation Details](#security-implementation-details)
- [Installation Guide](#installation-guide)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)

## Key Features

### 🔐 **Enterprise-Grade Authentication & Authorization**
- **User Registration** with comprehensive email validation and policy enforcement
- **Complex Password Requirements** with configurable YAML-based policy management
- **HMAC-SHA256 Password Hashing** with per-user cryptographic salt (32-byte random salt)
- **Multi-Layer Account Security** with progressive lockout protection
- **JWT Token Authentication** with secure session management
- **Password Reset Flow** using SHA-1 verification codes (per project requirements)
- **Password History Tracking** preventing reuse of last N passwords
- **Dictionary-Based Password Blacklist** protection

### 🛡️ **Comprehensive Security Measures**
- **XSS Protection** through systematic HTML character encoding and input sanitization
- **SQL Injection Prevention** using parameterized queries and SQLModel ORM
- **HTTP Security Headers** including CSP, X-Frame-Options, and X-Content-Type-Options
- **CORS Configuration** with strict origin validation
- **Input Validation** with Pydantic models and custom field validators
- **Audit Logging** with comprehensive UserEvent tracking system

### 👥 **Customer Management System**
- **Secure Customer Creation** with validated information and duplicate prevention
- **Customer Data Display** with proper encoding and XSS protection
- **Plan Management** with referential integrity and validation
- **Database Relationships** with proper foreign key constraints

### 🐳 **Production-Ready Deployment**
- **Docker Containerization** with multi-service architecture
- **MySQL Database** with health checks and automatic initialization
- **Environment Configuration** with comprehensive settings management
- **Logging & Monitoring** with structured error handling

## Technology Stack

### Backend
- **FastAPI**: Modern Python web framework with automatic API documentation
- **SQLModel**: Type-safe ORM with Pydantic integration for data validation
- **PyMySQL**: MySQL database connector with connection pooling
- **Uvicorn**: High-performance ASGI server
- **Python-JOSE**: JWT token handling with cryptographic signatures

### Frontend
- **Flask**: Lightweight Python web framework for UI
- **Jinja2**: Template engine with automatic HTML escaping
- **HTML5/CSS3**: Modern responsive web interface

### Database
- **MySQL 8.0**: Production-grade relational database
- **Database Migration**: Automatic schema creation and seeding

### Infrastructure
- **Docker**: Containerization with multi-stage builds
- **Docker Compose**: Multi-service orchestration with health checks
- **Alpine Linux**: Lightweight container base images

## Architecture

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│                     │    │                     │    │                     │
│   Flask Frontend    │◄──►│   FastAPI Backend   │◄──►│   MySQL Database    │
│   (Port 5173)       │    │    (Port 8000)      │    │    (Port 3306)      │
│                     │    │                     │    │                     │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
          ▲                           ▲                           ▲
          │                           │                           │
          │                           │                           │
          │         ┌─────────────────┐                           │
          └────────►│  JWT Auth &     │◄───────────────────────── ┘
                    │  Session Mgmt   │
                    └─────────────────┘
                              ▲
                              │
                    ┌─────────────────  ┐
                    │  Security Layer   │
                    │  - XSS Protection │
                    │  - SQL Injection  │
                    │  -Input Validation│
                    │  - Audit Logging  │
                    └─────────────────  ┘
```

### Project Structure
```
Communication_LTD/
├── Server/                    # FastAPI Backend Application
│   ├── core/                 # Core security and utility modules
│   │   ├── security.py       # XSS protection, password hashing
│   │   ├── password_validator.py # Password policy management
│   │   ├── jwt_handler.py    # JWT token management
│   │   └── email_service.py  # Email notifications
│   ├── db/                   # Database layer
│   │   ├── models/           # SQLModel data models
│   │   ├── session.py        # Database session management
│   │   └── init_db.py        # Database initialization
│   ├── routers/              # API route handlers
│   │   ├── auth.py           # Authentication endpoints
│   │   ├── customer.py       # Customer management
│   │   └── plans.py          # Service plan management
│   ├── main.py               # FastAPI application entry point
│   ├── settings.py           # Configuration management
│   └── Dockerfile            # Backend container configuration
├── Client/                   # Flask Frontend Application
│   ├── templates/            # Jinja2 HTML templates
│   ├── static/               # CSS, JavaScript assets
│   ├── app.py                # Flask application
│   └── Dockerfile            # Frontend container configuration
├── config/                   # Configuration files
│   └── password_policy.yaml  # Security policy configuration
├── docker-compose.yaml       # Multi-service orchestration
└── .env.example              # Environment template
```

**Application URLs:**
- **Backend API**: http://localhost:8000 (FastAPI with auto-docs at `/docs`)
- **Frontend UI**: http://localhost:5173 (Flask web interface)
- **MySQL Database**: localhost:3306

## Installation Guide

### Prerequisites

- **Docker & Docker Compose** (v20.10+)
- **Git** for repository cloning
- **Modern Web Browser** (Chrome, Firefox, Edge, or Safari)

### Complete Installation Steps

#### 1. Repository Setup

```bash
# Clone the repository
git clone <https://github.com/0merD/CommunicationLTD_Secure> #to run the unsecure version clone this: git clone <https://github.com/0merD/CommunicationLTD_Secure>
cd CommunicationLTD_Secure

```

#### 2. Environment Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit configuration (required)
nano .env  # or use your preferred editor
```

**Required Environment Variables:**
```bash
# Application Settings
APP_NAME=CommunicationLTD
APP_VERSION=1.0.0
SECRET_KEY=your_secure_secret_key_here

# Database Configuration (MySQL)
DB_HOST=db
DB_PORT=3306
DB_USER=secure_user_name
MYSQL_USER=secure_user_name
DB_PASSWORD=secure_password_here
MYSQL_PASSWORD=secure_password_here
MYSQL_ROOT_PASSWORD=root_password_here
DB_NAME=CommunicationLTD

# Email Configuration (for password reset)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your_email@gmail.com
SENDER_PASSWORD=your_app_password
SENDER_NAME="Communication LTD"
USE_TLS=true

# Security Configuration
CONFIG_DIR=./config
PASSWORD_POLICY_FILE=password_policy.yaml
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
API_BASE_URL=http://app:8000

```

#### 3. Docker Deployment

```bash
# Build and start all services
docker-compose up --build -d

```

## Security Implementation Details

This section demonstrates the comprehensive security measures implemented to protect against common web vulnerabilities as required by the cybersecurity project specifications.

### XSS Protection Through Character Encoding

The system implements systematic HTML character encoding to prevent Cross-Site Scripting (XSS) attacks through manual escaping of special characters.

#### Secure Implementation

**Core Sanitization Function (`Server/core/security.py`):**
```python
def sanitize_input(value: str) -> str:
    """
    HTML escaping with quote=True prevents XSS attacks by encoding special characters
    """
    if value is None:
        return ""
    return html.escape(value.strip(), quote=True)
```

**Security Features:**
- Uses Python's built-in `html.escape()` function for reliable character encoding
- `quote=True` parameter ensures quotation marks are also escaped (`"` → `&quot;`, `'` → `&#x27;`)
- Converts dangerous characters: `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`
- Applied systematically across all user input validation points

#### Vulnerable Implementation

<!-- PLACEHOLDER: Insert vulnerable XSS code here -->
```python
def sanitize_input(value: str) -> str:
    """
    VULNERABLE VERSION - No HTML escaping allows XSS attacks
    """
    if value is None:
        return ""
    return value.strip()
```

#### Test Case: Stored XSS Attack

**Malicious Payload:**

(insert in add customer in the name field and after this, click on the customer name in dashboard)
```html
<script>alert('XSS Attack!')</script> 


```
### SQL Injection Prevention Through Parameterized Queries

The system uses SQLModel ORM which automatically implements parameterized queries (prepared statements) to prevent SQL Injection attacks.

#### Secure Implementation

**Database Query Security (`Server/routers/auth.py`):**
```python
# Secure user lookup with parameterized query
user = db.exec(select(User).where(User.username == data.username)).first()

# Secure password record retrieval
pwd = db.exec(select(Password).where(Password.user_id == user.id)).first()

# Secure user existence check during registration
if db.exec(select(User).where(User.username == data.username)).first():
    raise HTTPException(status_code=400, detail="Choose another username")
if db.exec(select(User).where(User.email == data.email)).first():
    raise HTTPException(status_code=400, detail="Email already exists")
```
These database operations use SQLModel ORM's automatic parameterized queries to prevent SQL injection attacks by treating user input as data parameters rather than executable SQL code. The .where() clauses automatically bind values like data.username as safe parameters, ensuring that malicious payloads such as admin'; DROP TABLE users; -- are treated as literal strings instead of SQL commands. This approach provides comprehensive SQL injection protection without requiring manual input sanitization since the ORM handles all parameterization automatically.

#### Vulnerable Implementation
one of the examples:

```python
def @router.get("/search-vulnerable/{name}")
def search_customer_vulnerable(name: str, current_user: User = Depends(get_current_user)):
    try:
        with insecure_connection.cursor() as db:

            query = f"SELECT * FROM customers WHERE full_name LIKE '{name}'"
            print(f"Executing query: {query}")

            db.execute(query)
            results = db.fetchall()
            sleep(0.01)
            return results

    except MySQLError as e:
        print(f"SQL error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"SQL error: {str(e)}")
```

```python
@router.post("/login")
def login(data: LoginIn, request: Request, db: Session = Depends(get_session)):
    ip = request.client.host if request.client else None

    try:
        query = f"SELECT * FROM users WHERE username = '{data.username}'"
        print(f"Executing query: {query}")

        with insecure_connection.cursor() as cursor:
            cursor.execute(query)
        user = cursor.fetchone()
        sleep(0.2)
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
    except MySQLError as e:
        print(f"MySQL Error: {e}")
        raise HTTPException(status_code=500, detail=f"SQL Error: {e}")
```



```python
@router.post("/register")
def register(data: RegisterIn, background_tasks: BackgroundTasks, db: Session = Depends(get_session)):
    try:
        query = f"SELECT * FROM users WHERE username = '{data.username}'"
        print(f"Executing query: {query}")
        with insecure_connection.cursor() as cursor:
            cursor.execute(query)
        result = cursor.fetchone()
        sleep(0.1)
        if result:
            raise HTTPException(status_code=400, detail="Username already taken")

        query = f"SELECT * FROM users WHERE email = '{data.email}'"
        print(f"Executing query: {query}")
        with insecure_connection.cursor() as cursor:
            cursor.execute(query)
        result = cursor.fetchone()
        sleep(0.1)
        if result:
            raise HTTPException(status_code=400, detail="Email already exists")
    except MySQLError as e:
        print(f"MySQL Error: {e}")
        raise HTTPException(status_code=500, detail=f"SQL Error: {e}")

```

#### Test Case: SQL Injection Attack

**Malicious Payload:**

(insert in search customer/login/register field)
```sql
 test'; SET FOREIGN_KEY_CHECKS = 0; DROP TABLE plans; -- .
```


**Database Connection Security (`Server/db/session.py`):**
```python
# SQLModel engine with security features
engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,        # Connection health checks
    pool_recycle=3600,         # Prevent stale connections
)

def get_session():
    with Session(engine) as session:  # Context manager ensures cleanup
        yield session
```

**Security Mechanisms:**
- **Automatic Parameterization**: SQLModel ORM converts all queries to prepared statements by design
- **Type Safety**: Pydantic models enforce strict data typing preventing type confusion attacks
- **Context Management**: Database sessions are properly closed preventing connection leaks

### Additional Security Implementations

#### Password Security Architecture

The system implements enterprise-grade password protection using HMAC-SHA256 with per-user cryptographic salts. Each password receives a unique 32-byte random salt generated using `os.urandom()` for cryptographic security. Password verification uses constant-time comparison functions to prevent timing attacks that could reveal information about stored password hashes. All salts are stored alongside password hashes in the database for verification purposes.

#### Account Lockout Protection

Progressive lockout protection prevents brute force attacks through configurable attempt thresholds and lockout durations. The system tracks failed login attempts per user account and automatically locks accounts after exceeding the maximum attempts (default: 3). Locked accounts remain inaccessible for a configurable duration (default: 15 minutes) before automatic unlock. All authentication attempts are logged with timestamps and IP addresses for audit purposes.

#### HTTP Security Headers

Comprehensive HTTP security headers protect against common web attacks including clickjacking, MIME type confusion, and cross-site scripting. The middleware automatically applies security headers to all responses: X-Content-Type-Options prevents MIME sniffing attacks, X-Frame-Options blocks iframe embedding, Content Security Policy restricts resource loading, and X-XSS-Protection enables browser-level XSS filtering. Special CSP rules are configured for API documentation endpoints while maintaining strict policies for application pages.

#### JWT Token Security

Secure JWT token management provides stateless authentication with cryptographic signature verification. Tokens are signed using HMAC-SHA256 with a secret key and include configurable expiration times (default: 1 hour). The system validates token signatures, expiration times, and payload integrity on each request. Invalid or expired tokens are rejected with appropriate error responses to prevent unauthorized access.

#### Audit Logging System

Comprehensive security event logging tracks all authentication activities and security-relevant actions. The UserEvent system records login attempts, password changes, account lockouts, and policy violations with timestamps, IP addresses, and event descriptions. This audit trail supports security monitoring, incident investigation, and compliance requirements.



**Configuration Options:**
- **min_length**: Minimum password length (default: 10)
- **uppercase/lowercase/digits/special**: Character class requirements
- **history_count**: Number of previous passwords to prevent reuse
- **max_login_attempts**: Failed login attempts before lockout
- **lockout_duration_minutes**: Account lockout duration
- **blacklist**: Common passwords to reject
- **custom_regex**: Optional custom password validation pattern


## API Documentation

The system provides comprehensive REST API documentation with automatic OpenAPI/Swagger integration accessible at http://localhost:8000/docs.

### API Endpoints Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| **Authentication** |
| POST | `/api/v1/auth/register` | Register a new user account with username, email, and password validation |
| POST | `/api/v1/auth/login` | Authenticate user credentials and return JWT access token |
| POST | `/api/v1/auth/change-password` | Change user password with current password verification required |
| POST | `/api/v1/auth/forgot-password` | Initiate password reset flow by sending verification token to email |
| POST | `/api/v1/auth/reset-password` | Complete password reset using email verification token |
| POST | `/api/v1/auth/refresh-token` | Refresh JWT access token for authenticated users |
| GET | `/api/v1/auth/me` | Retrieve current authenticated user information and profile |
| **Customer Management** |
| POST | `/api/v1/customers` | Create new customer record with contact information and service plan |
| GET | `/api/v1/customers` | Retrieve list of all customers with their subscription details |
| GET | `/api/v1/customers/{id}` | Get specific customer information by customer ID |
| PUT | `/api/v1/customers/{id}` | Update existing customer information and service plan |
| DELETE | `/api/v1/customers/{id}` | Remove customer record from the system |
| GET | `/api/v1/customers/search/{name}` | Search customers by name with input sanitization and validation |
| GET | `/api/v1/customers/search-vulnerable/{name}` | Search customers by name - vulnerable endpoint for security demonstrations |
| **Service Plans** |
| GET | `/api/v1/plans` | Retrieve all available internet service plans with pricing and speeds |

### Authentication Requirements

Most endpoints require JWT authentication via the `Authorization: Bearer <token>` header. Public endpoints include user registration, login, password reset initiation, and service plan viewing.

### Response Format

All API responses follow standard JSON format with appropriate HTTP status codes. Error responses include detailed validation messages and error codes for debugging purposes.

