from flask import Flask, jsonify, request, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from logging.handlers import RotatingFileHandler
import os
import logging

''''
Imports: Import necessary modules and classes for Flask, SQLAlchemy
 (for database management), JWTManager (for JSON Web Token handling),
CORS (for Cross-Origin Resource Sharing), Werkzeug (for security and file handling),
 logging (for logging events), and other standard Python libraries.

'''
''''
setup_logging: Sets up logging for the Flask application, creating a log directory if it doesn't exist,
 defining log file properties, and logging startup information.

'''
# Function to set up logging
def setup_logging(app):
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/library_management.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Library management startup')


'''
Flask Configuration: Initializes the Flask application,
sets up CORS to allow requests from http://127.0.0.1:5500,
and calls setup_logging to configure logging.
'''    

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://127.0.0.1:5500"}}, supports_credentials=True)
setup_logging(app)

# Configuration 
'''
App Configuration: Sets up various configurations including file upload settings, database URI (sqlite:///project.db), JWT secret key (with a fallback to a default key),
CORS headers, maximum content length for file uploads,
and SQLAlchemy engine options.
'''
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')  # Change this in production
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB max file size
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'check_same_thread': False}}

# Initialize extensions
'''
Extensions Initialization: Initializes SQLAlchemy for database operations (db) and JWTManager
 for handling JWT authentication (jwt).
'''
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
"""
Models: Defines SQLAlchemy models for Book, Customer,
Loan, and User, representing tables in the database
with specific fields and relationships.
"""
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    year = db.Column(db.Integer)
    type = db.Column(db.Integer)
    image_filename = db.Column(db.String(255))
    deleted = db.Column(db.Boolean, default=False)

    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'author': self.author,
            'year': self.year,
            'type': self.type,
            'image_filename': self.image_filename,
            'deleted': self.deleted
        }

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(255))
    age = db.Column(db.Integer)
    deleted = db.Column(db.Boolean, default=False)
    users = db.relationship('User', backref='customer', lazy=True)

    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'city': self.city,
            'age': self.age,
            'deleted': self.deleted
        }

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cust_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    loandate = db.Column(db.DateTime, default=datetime.utcnow)
    returndate = db.Column(db.DateTime)
    deleted = db.Column(db.Boolean, default=False)

    def serialize(self):
        return {
            'id': self.id,
            'cust_id': self.cust_id,
            'book_id': self.book_id,
            'loandate': self.loandate.isoformat(),
            'returndate': self.returndate.isoformat() if self.returndate else None,
            'deleted': self.deleted
        }

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))
    deleted = db.Column(db.Boolean, default=False)

    def __init__(self, username, password, role, customer_id=None):
        self.username = username
        self.password = generate_password_hash(password, method='sha256')
        self.role = role
        self.customer_id = customer_id

    def __repr__(self):
        return f'<User {self.username}>'
# admin:
''''
Utility Functions: admin_required decorator to
enforce admin role requirement for endpoints,
and allowed_file function to check if uploaded
file extensions are allowed.
'''

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

def allowed_file(filename):     # Function to check if a file has an allowed extension
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/upload', methods=['POST'])
@jwt_required()
@admin_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File uploaded successfully', 'filename': filename}), 201
    else:
        return jsonify({'error': 'File type not allowed'}), 400

# Error handling
@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return jsonify({'error': str(e)}), e.code
    app.logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({'error': 'An unexpected error occurred'}), 500

# User Registration
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    name = data.get('name')
    city = data.get('city')
    age = data.get('age')

    if not username or not password or not role or not name:
        return jsonify({'error': 'Missing required fields'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 400

    if role not in ['admin', 'client']:
        return jsonify({'error': 'Invalid role'}), 400

    new_customer = Customer(name=name, city=city, age=age)
    db.session.add(new_customer)
    db.session.commit()

    new_user = User(username=username, password=password, role=role, customer_id=new_customer.id)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'user': new_user.username}), 201


# User Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token}), 200

# Books CRUD
@app.route('/api/books', methods=['GET', 'POST'])
@jwt_required()
@admin_required   # Decorator function to enforce admin role requirement
def handle_books():
    if request.method == 'GET':
        books = Book.query.filter_by(deleted=False).all()
        books_data = [{'id': book.id, 'name': book.name, 'author': book.author, 'year': book.year, 'type': book.type, 'image_filename': book.image_filename} for book in books]
        return jsonify({'books': books_data}), 200

    elif request.method == 'POST':
        data = request.json
        name = data.get('name')
        author = data.get('author')
        year = data.get('year')
        book_type = data.get('type')
        image_filename = data.get('image_filename')

        if not name or not author:
            return jsonify({'error': 'Missing book name or author'}), 400

        new_book = Book(name=name, author=author, year=year, type=book_type, image_filename=image_filename)
        db.session.add(new_book)
        db.session.commit()
        return jsonify({'message': 'Book added successfully', 'book': new_book.serialize()}), 201

    elif request.method == 'POST':
        data = request.json
        name = data.get('name')
        author = data.get('author')
        year = data.get('year')
        book_type = data.get('type')
        image_filename = data.get('image_filename')

        if not name or not author:
            return jsonify({'error': 'Missing book name or author'}), 400

        new_book = Book(name=name, author=author, year=year, type=book_type, image_filename=image_filename)
        db.session.add(new_book)
        db.session.commit()
        return jsonify({'message': 'Book added successfully', 'book': new_book.serialize()}), 201

@app.route('/api/books/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@admin_required
def handle_book(id):
    book = Book.query.get_or_404(id)

    if request.method == 'GET':
        if book.deleted:
            return jsonify({'error': 'Book not found'}), 404
        return jsonify(book.serialize()), 200

    elif request.method == 'PUT':
        data = request.json
        book.name = data.get('name', book.name)
        book.author = data.get('author', book.author)
        book.year = data.get('year', book.year)
        book.type = data.get('type', book.type)
        book.image_filename = data.get('image_filename', book.image_filename)
        db.session.commit()
        return jsonify({'message': 'Book updated successfully', 'book': book.serialize()}), 200

    elif request.method == 'DELETE':
        book.deleted = True
        db.session.commit()
        return jsonify({'message': 'Book deleted successfully'}), 200

# Customers CRUD
@app.route('/api/customers', methods=['GET', 'POST'])
@jwt_required()
@admin_required
def handle_customers():
    if request.method == 'GET':
        customers = Customer.query.filter_by(deleted=False).all()
        return jsonify({'customers': [customer.serialize() for customer in customers]}), 200

    elif request.method == 'POST':
        data = request.json
        name = data.get('name')
        city = data.get('city')
        age = data.get('age')

        if not name:
            return jsonify({'error': 'Missing customer name'}), 400

        new_customer = Customer(name=name, city=city, age=age)
        db.session.add(new_customer)
        db.session.commit()
        return jsonify({'message': 'Customer added successfully', 'customer': new_customer.serialize()}), 201

@app.route('/api/customers/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@admin_required
def handle_customer(id):
    customer = Customer.query.get_or_404(id)

    if request.method == 'GET':
        if customer.deleted:
            return jsonify({'error': 'Customer not found'}), 404
        return jsonify(customer.serialize()), 200

    elif request.method == 'PUT':
        data = request.json
        customer.name = data.get('name', customer.name)
        customer.city = data.get('city', customer.city)
        customer.age = data.get('age', customer.age)
        db.session.commit()
        return jsonify({'message': 'Customer updated successfully', 'customer': customer.serialize()}), 200

    elif request.method == 'DELETE':
        customer.deleted = True
        db.session.commit()
        return jsonify({'message': 'Customer deleted successfully'}), 200

# Loans CRUD
@app.route('/api/loans', methods=['GET', 'POST'])
@jwt_required()
@admin_required
def handle_loans():
    if request.method == 'GET':
        loans = Loan.query.filter_by(deleted=False).all()
        return jsonify({'loans': [loan.serialize() for loan in loans]}), 200

    elif request.method == 'POST':
        data = request.json
        cust_id = data.get('cust_id')
        book_id = data.get('book_id')

        if not cust_id or not book_id:
            return jsonify({'error': 'Missing customer ID or book ID'}), 400

        new_loan = Loan(cust_id=cust_id, book_id=book_id)
        db.session.add(new_loan)
        db.session.commit()
        return jsonify({'message': 'Loan added successfully', 'loan': new_loan.serialize()}), 201

@app.route('/api/loans/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@admin_required
def handle_loan(id):
    loan = Loan.query.get_or_404(id)

    if request.method == 'GET':
        if loan.deleted:
            return jsonify({'error': 'Loan not found'}), 404
        return jsonify(loan.serialize()), 200

    elif request.method == 'PUT':
        data = request.json
        loan.cust_id = data.get('cust_id', loan.cust_id)
        loan.book_id = data.get('book_id', loan.book_id)
        loan.returndate = data.get('returndate', loan.returndate)
        db.session.commit()
        return jsonify({'message': 'Loan updated successfully', 'loan': loan.serialize()}), 200

    elif request.method == 'DELETE':
        loan.deleted = True
        db.session.commit()
        return jsonify({'message': 'Loan deleted successfully'}), 200


# Serve uploaded files: Endpoints: Defines Flask endpoints (/upload, error handler)
#  for handling file uploads (restricted to admins) and global exception handling.
@app.route('/api/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Run the app

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)