from flask import Flask, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from datetime import datetime
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import os

# Function to set up logging
def setup_logging(app):
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/library_management.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Library management startup')

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5500"}}, supports_credentials=True)
setup_logging(app)

# Configuration

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this in production
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

    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'author': self.author,
            'year': self.year,
            'type': self.type,
            'image_filename': self.image_filename
        }

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(255))
    age = db.Column(db.Integer)
    users = db.relationship('User', backref='customer', lazy=True)

    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'city': self.city,
            'age': self.age
        }

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cust_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    loandate = db.Column(db.DateTime, default=datetime.utcnow)
    returndate = db.Column(db.DateTime)

    def serialize(self):
        return {
            'id': self.id,
            'cust_id': self.cust_id,
            'book_id': self.book_id,
            'loandate': self.loandate.isoformat(),
            'returndate': self.returndate.isoformat() if self.returndate else None
        }

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))

    def __init__(self, username, password, role, customer_id=None):
        self.username = username
        self.password = generate_password_hash(password, method='sha256')
        self.role = role
        self.customer_id = customer_id

    def __repr__(self):
        return f'<User {self.username}>'

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper


# Routes
@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return jsonify({'error': str(e)}), e.code
    app.logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not username or not password or not role:
        return jsonify({'error': 'Missing username, password, or role'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 400

    if role not in ['admin', 'client']:
        return jsonify({'error': 'Invalid role'}), 400

    new_user = User(
        username=username,
        password=password,
        role=role
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully', 'user': new_user.username}), 201

@app.route('/login', methods=['POST'])
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




@app.route('/api/admin-only', methods=['GET'])
@jwt_required()
@admin_required
def admin_only():
    return jsonify({'message': 'You have admin access'}), 200    

@app.route('/books', methods=['GET', 'POST', 'OPTIONS'])
def handle_books():
    if request.method == 'OPTIONS':
        return '', 200  # Preflight request response
    elif request.method == 'GET':
        books = Book.query.all()
        return jsonify({'books': [book.serialize() for book in books]}), 200
    elif request.method == 'POST':
        data = request.json
        name = data.get('name')
        author = data.get('author')
        year = data.get('year')
        type = data.get('type')
        image_filename = data.get('image_filename')

        if not name or not author or not year or not type:
            return jsonify({'error': 'Missing required fields'}), 400

        new_book = Book(
            name=name,
            author=author,
            year=year,
            type=type,
            image_filename=image_filename
        )
        db.session.add(new_book)
        db.session.commit()

        return jsonify({'message': 'Book added successfully', 'book': new_book.serialize()}), 201


@app.route('/api/books/<int:book_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_book(book_id):
    book = Book.query.get_or_404(book_id)
    data = request.json
    book.name = data.get('name', book.name)
    book.author = data.get('author', book.author)
    book.year = data.get('year', book.year)
    book.type = data.get('type', book.type)
    book.image_filename = data.get('image_filename', book.image_filename)
    db.session.commit()
    return jsonify({'message': 'Book updated successfully', 'book': book.serialize()}), 200

@app.route('/api/books/<int:book_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    return jsonify({'message': 'Book deleted successfully'}), 200

@app.route('/api/customers', methods=['GET'])
@jwt_required()
@admin_required
def get_customers():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    customers = Customer.query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'customers': [customer.serialize() for customer in customers.items],
        'total': customers.total,
        'pages': customers.pages,
        'current_page': customers.page
    }), 200

@app.route('/api/customers', methods=['POST'])
@jwt_required()
@admin_required
def add_customer():
    data = request.json
    new_customer = Customer(
        name=data['name'],
        city=data.get('city'),
        age=data.get('age')
    )
    db.session.add(new_customer)
    db.session.commit()
    return jsonify({'message': 'Customer added successfully', 'customer': new_customer.serialize()}), 201

@app.route('/api/customers/<int:customer_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    data = request.json
    customer.name = data.get('name', customer.name)
    customer.city = data.get('city', customer.city)
    customer.age = data.get('age', customer.age)
    db.session.commit()
    return jsonify({'message': 'Customer updated successfully', 'customer': customer.serialize()}), 200

@app.route('/api/customers/<int:customer_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    db.session.delete(customer)
    db.session.commit()
    return jsonify({'message': 'Customer deleted successfully'}), 200

@app.route('/api/loans', methods=['GET'])
@jwt_required()
def get_loans():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    loans = Loan.query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'loans': [loan.serialize() for loan in loans.items],
        'total': loans.total,
        'pages': loans.pages,
        'current_page': loans.page
    }), 200

@app.route('/api/loans', methods=['POST'])
@jwt_required()
def add_loan():
    data = request.json
    cust_id = data.get('cust_id')
    book_id = data.get('book_id')

    # Check if the customer and book exist
    customer = Customer.query.get(cust_id)
    book = Book.query.get(book_id)
    if not customer or not book:
        return jsonify({'error': 'Customer or book not found'}), 404

    new_loan = Loan(
        cust_id=cust_id,
        book_id=book_id,
        loandate=datetime.utcnow(),
        returndate=data.get('returndate')
    )
    db.session.add(new_loan)
    db.session.commit()
    return jsonify({'message': 'Loan added successfully', 'loan': new_loan.serialize()}), 201

@app.route('/api/loans/<int:loan_id>', methods=['PUT'])
@jwt_required()
def update_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    data = request.json
    loan.cust_id = data.get('cust_id', loan.cust_id)
    loan.book_id = data.get('book_id', loan.book_id)
    loan.loandate = datetime.fromisoformat(data.get('loandate', loan.loandate.isoformat()))
    loan.returndate = datetime.fromisoformat(data.get('returndate', loan.returndate.isoformat())) if data.get('returndate') else None
    db.session.commit()
    return jsonify({'message': 'Loan updated successfully', 'loan': loan.serialize()}), 200

@app.route('/api/loans/<int:loan_id>', methods=['DELETE'])
@jwt_required()
def delete_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    db.session.delete(loan)
    db.session.commit()
    return jsonify({'message': 'Loan deleted successfully'}), 200

# Static files route for serving uploaded images
@app.route('/uploads/<filename>', methods=['GET'])
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Main entry point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
