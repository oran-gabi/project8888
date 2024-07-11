Flask Library Management System
This is a Flask-based library management system that provides functionality for managing books, customers, and loans. The system includes user authentication, role-based access control, and file upload capabilities.

Features
User registration and login with JWT-based authentication.
Role-based access control (admin and client roles).
CRUD operations for books, customers, and loans.
File upload functionality for book images.
Logging for monitoring and debugging.
CORS support for cross-origin requests.
Requirements
Python 3.6 or later
Flask 2.3.2
Flask-CORS 3.0.10
Flask-JWT-Extended 4.4.4
Flask-Migrate 4.0.4
Flask-SQLAlchemy 3.0.3
SQLAlchemy 2.0.31
Setup
Clone the repository:

bash
Copy code
git clone https://github.com/your-repo/library-management-system.git
cd library-management-system
Create and activate a virtual environment:

bash
Copy code
python3 -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
Install the required packages:

bash
Copy code
pip install -r requirements.txt
Set up the database:

bash
Copy code
flask db init
flask db migrate
flask db upgrade
Run the application:

bash
Copy code
python app.py
Access the application:
Open your browser and go to http://127.0.0.1:5000.

API Endpoints
User Authentication
Register a new user

URL: /api/register
Method: POST
Payload:
json
Copy code
{
  "username": "string",
  "password": "string",
  "role": "admin|client"
}
Login

URL: /login
Method: POST
Payload:
json
Copy code
{
  "username": "string",
  "password": "string"
}
Books
Get all books

URL: /books
Method: GET
Add a new book

URL: /books
Method: POST
Payload: Multipart form data with name, author, year, type, and file.
Update a book

URL: /api/books/<int:book_id>
Method: PUT
Payload:
json
Copy code
{
  "name": "string",
  "author": "string",
  "year": "int",
  "type": "int",
  "image_filename": "string"
}
Delete a book

URL: /api/books/<int:book_id>
Method: DELETE
Customers
Get all customers

URL: /api/customers
Method: GET
Add a new customer

URL: /api/customers
Method: POST
Payload:
json
Copy code
{
  "name": "string",
  "city": "string",
  "age": "int"
}
Update a customer

URL: /api/customers/<int:customer_id>
Method: PUT
Payload:
json
Copy code
{
  "name": "string",
  "city": "string",
  "age": "int"
}
Delete a customer

URL: /api/customers/<int:customer_id>
Method: DELETE
Loans
Get all loans

URL: /api/loans
Method: GET
Add a new loan

URL: /api/loans
Method: POST
Payload:
json
Copy code
{
  "cust_id": "int",
  "book_id": "int",
  "returndate": "datetime"
}
Update a loan

URL: /api/loans/<int:loan_id>
Method: PUT
Payload:
json
Copy code
{
  "cust_id": "int",
  "book_id": "int",
  "loandate": "datetime",
  "returndate": "datetime"
}
Delete a loan

URL: /api/loans/<int:loan_id>
Method: DELETE
File Uploads
Upload a file
URL: /upload
Method: POST
Payload: Multipart form data with file.
Static Files
Access uploaded files
URL: /uploads/<filename>
Method: GET
Logging
Logs are stored in the logs directory with the file name library_management.log. The application logs important events, errors, and other significant actions.

# Library Management System

This project is a Library Management System built using Flask for the backend and HTML, CSS, and JavaScript for the frontend. The system allows clients to view available books, manage loans, and provides an admin interface for managing books and user accounts.

## Features

- User Registration and Login
- Token-based Authentication
- Client Interface for Viewing and Selecting Books
- Admin Interface for Managing Books and Users
- Loan Management for Clients
- Secure File Uploads for Book Images

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/library-management-system.git
   cd library-management-system


2. **Set Up a Virtual Environment:**

bash
Copy code
python -m venv venv
source venv/bin/activate # On Windows, use `venv\Scripts\activate`
Install Dependencies:

bash
Copy code
pip install -r requirements.txt
Set Up the Database:

Initialize the SQLite database and create the necessary tables.

bash
Copy code
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
Run the Application:

bash
Copy code
flask run
The backend server will start at http://127.0.0.1:5000.

Open the Frontend:

Open index.html in your browser, typically by navigating to http://127.0.0.1:5500/index.html.

File Structure
app.py - Main Flask application file.
models.py - Defines the database models.
static/ - Contains static files (CSS, JavaScript).
templates/ - Contains HTML templates.
migrations/ - Database migrations.
library.db - SQLite database file.
requirements.txt - Python dependencies.

Security
Ensure to change the JWT_SECRET_KEY to a secure and unique value before deploying the application to production.
Validate and sanitize all user inputs to prevent SQL injection and other attacks.
Implement rate limiting to prevent abuse of the API endpoints.
Contributing
Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

License
This project is licensed under the MIT License.

