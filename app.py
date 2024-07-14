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

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://127.0.0.1:5500"}}, supports_credentials=True)
setup_logging(app)

# Configuration 
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
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
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

# Admin check decorator
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

# Function to check if a file has an allowed extension
def allowed_file(filename):
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
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
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

    existing_customer = Customer.query.filter_by(name=name).first()
    if existing_customer:
        return jsonify({'error': 'Customer already exists'}), 400

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
@admin_required
def manage_books():
    if request.method == 'GET':
        books = Book.query.filter_by(deleted=False).all()
        return jsonify([book.serialize() for book in books]), 200

    if request.method == 'POST':
        data = request.form
        name = data.get('name')
        author = data.get('author')
        year = data.get('year')
        type = data.get('type')
        file = request.files.get('image')
        if not name or not author or not year or not type:
            return jsonify({'error': 'Missing required fields'}), 400
        image_filename = None
        if file and allowed_file(file.filename):
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            image_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        new_book = Book(name=name, author=author, year=int(year), type=int(type), image_filename=image_filename)
        db.session.add(new_book)
        db.session.commit()
        return jsonify({'message': 'Book added successfully', 'book': new_book.serialize()}), 201

@app.route('/api/books/<int:book_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@admin_required
def book_details(book_id):
    book = Book.query.get_or_404(book_id)

    if request.method == 'GET':
        return jsonify(book.serialize()), 200

    if request.method == 'PUT':
        data = request.form
        book.name = data.get('name', book.name)
        book.author = data.get('author', book.author)
        book.year = data.get('year', book.year)
        book.type = data.get('type', book.type)
        file = request.files.get('image')
        if file and allowed_file(file.filename):
            image_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            book.image_filename = image_filename
        db.session.commit()
        return jsonify({'message': 'Book updated successfully', 'book': book.serialize()}), 200

    if request.method == 'DELETE':
        book.deleted = True
        db.session.commit()
        return jsonify({'message': 'Book deleted successfully'}), 200

# Customers CRUD
@app.route('/api/customers', methods=['GET', 'POST'])
@jwt_required()
@admin_required
def manage_customers():
    if request.method == 'GET':
        customers = Customer.query.filter_by(deleted=False).all()
        return jsonify([customer.serialize() for customer in customers]), 200

    if request.method == 'POST':
        data = request.json
        name = data.get('name')
        city = data.get('city')
        age = data.get('age')
        if not name or not city or not age:
            return jsonify({'error': 'Missing required fields'}), 400
        new_customer = Customer(name=name, city=city, age=int(age))
        db.session.add(new_customer)
        db.session.commit()
        return jsonify({'message': 'Customer added successfully', 'customer': new_customer.serialize()}), 201

@app.route('/api/customers/<int:customer_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@admin_required
def customer_details(customer_id):
    customer = Customer.query.get_or_404(customer_id)

    if request.method == 'GET':
        return jsonify(customer.serialize()), 200

    if request.method == 'PUT':
        data = request.json
        customer.name = data.get('name', customer.name)
        customer.city = data.get('city', customer.city)
        customer.age = data.get('age', customer.age)
        db.session.commit()
        return jsonify({'message': 'Customer updated successfully', 'customer': customer.serialize()}), 200

    if request.method == 'DELETE':
        customer.deleted = True
        db.session.commit()
        return jsonify({'message': 'Customer deleted successfully'}), 200

# Loans CRUD
@app.route('/api/loans', methods=['GET', 'POST'])
@jwt_required()
@admin_required
def manage_loans():
    if request.method == 'GET':
        loans = Loan.query.filter_by(deleted=False).all()
        return jsonify([loan.serialize() for loan in loans]), 200

    if request.method == 'POST':
        data = request.json
        cust_id = data.get('cust_id')
        book_id = data.get('book_id')
        if not cust_id or not book_id:
            return jsonify({'error': 'Missing required fields'}), 400
        new_loan = Loan(cust_id=cust_id, book_id=book_id)
        db.session.add(new_loan)
        db.session.commit()
        return jsonify({'message': 'Loan added successfully', 'loan': new_loan.serialize()}), 201

# Route to handle creating new loans
@app.route('/api/loans', methods=['POST'])
@jwt_required()
@admin_required
def create_loan():
    data = request.json
    if not data or not all(k in data for k in ("cust_id", "book_id", "loan_date", "returndate")):
        return jsonify({"error": "Missing required fields"}), 400

    new_loan = Loan(
        cust_id=data['cust_id'],
        book_id=data['book_id'],
        loan_date=data['loan_date'],
        returndate=data['returndate']
    )
    db.session.add(new_loan)
    db.session.commit()
    return jsonify(new_loan.serialize()), 201

# Route to handle loan details (GET, PUT, DELETE)
@app.route('/api/loans/<int:loan_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
@admin_required
def loan_details(loan_id):
    loan = Loan.query.get_or_404(loan_id)

    if request.method == 'GET':
        return jsonify(loan.serialize()), 200

    if request.method == 'PUT':
        data = request.json
        if not data or not all(k in data for k in ("cust_id", "book_id", "returndate")):
            return jsonify({"error": "Missing required fields"}), 400
        loan.returndate = data.get('returndate', loan.returndate)
        loan.cust_id = data.get('cust_id', loan.cust_id)
        loan.book_id = data.get('book_id', loan.book_id)
        db.session.commit()
        return jsonify({'message': 'Loan updated successfully', 'loan': loan.serialize()}), 200

    if request.method == 'DELETE':
        loan.deleted = True
        db.session.commit()
        return jsonify({'message': 'Loan deleted successfully'}), 200


# Client user loan management
@app.route('/api/client/loans', methods=['GET'])
@jwt_required()
def client_loans():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    loans = Loan.query.filter_by(cust_id=user.customer_id, deleted=False).all()
    return jsonify([loan.serialize() for loan in loans]), 200

# Route for serving uploaded images
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    with app.app_context():
     db.create_all()
     app.run(debug=True)
