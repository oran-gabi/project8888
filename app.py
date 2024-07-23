from flask import Flask, jsonify, request, send_from_directory, url_for
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import logging

# Initialize the Flask app
app = Flask(__name__)


@app.after_request
def add_csp_header(response):
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self';"
    response.headers['Content-Security-Policy'] = csp
    return response

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'backend', 'static')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB max file size
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'check_same_thread': False}}

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5500"}}, supports_credentials=True)

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check if a file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ensure the upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Define the models
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    genre = db.Column(db.String(50))
    published_date = db.Column(db.String(20))
    is_deleted = db.Column(db.Boolean, default=False)
    image_filename = db.Column(db.String(255))
    loans = db.relationship('Loan', backref='book', lazy=True)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20))
    email = db.Column(db.String(100))
    address = db.Column(db.String(200))
    is_deleted = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('customer', uselist=False))
    loans = db.relationship('Loan', backref='customer', lazy=True)

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    loan_date = db.Column(db.String(20))
    return_date = db.Column(db.String(20))
    due_date = db.Column(db.String(20))
    returned = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

# Helper method to convert model instances to dictionary
def as_dict(self):
    return {c.name: getattr(self, c.name) for c in self.__table__.columns}

# Add as_dict method to models
Book.as_dict = as_dict
Customer.as_dict = as_dict
Loan.as_dict = as_dict
User.as_dict = as_dict

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'customer')

    logger.debug(f"Registering user with username: {username}, role: {role}")

    if User.query.filter_by(username=username).first():
        return jsonify(message="Username already exists"), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    logger.debug(f"User {username} registered successfully with ID: {new_user.id}")

    if role == 'customer':
        new_customer = Customer(
            user_id=new_user.id,
            name=data.get('name'),
            phone_number=data.get('phone_number'),
            email=data.get('email'),
            address=data.get('address')
        )
        db.session.add(new_customer)
        db.session.commit()

        logger.debug(f"Customer created successfully for user ID: {new_user.id}")

    return jsonify(message="User registered successfully"), 201

# Registration endpoint for admin
@app.route('/register_admin', methods=['POST'])
def register_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify(message="Username already exists"), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role='admin')
    db.session.add(new_user)
    db.session.commit()

    return jsonify(message="Admin registered successfully"), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify(message="Invalid credentials"), 401

    access_token = create_access_token(identity={'username': user.username, 'role': user.role})
    return jsonify(access_token=access_token)

# Role-based access control decorator
def role_required(role):
    def wrapper(fn):
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt_identity()
            if claims['role'] != role:
                return jsonify(message="You are not authorized to access this resource"), 403
            return fn(*args, **kwargs)
        decorator.__name__ = fn.__name__
        return decorator
    return wrapper

# CRUD operations for Books
@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        books_query = Book.query.filter_by(is_deleted=False).paginate(page=page, per_page=per_page, error_out=False)
        
        books_with_images = []
        for book in books_query.items:
            book_dict = book.as_dict()
            if book.image_filename:
                book_dict['image_url'] = url_for('uploaded_file', filename=book.image_filename, _external=True)
            books_with_images.append(book_dict)
        
        response = {
            'books': books_with_images,
            'total': books_query.total,
            'pages': books_query.pages,
            'current_page': books_query.page
        }
        
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error in get_books: {str(e)}")
        return jsonify(message="An error occurred"), 500

@app.route('/books/<int:id>', methods=['GET'])
@jwt_required()
def get_book(id):
    book = Book.query.get_or_404(id)
    if book.is_deleted:
        return jsonify(error="Book not found"), 404
    book_dict = book.as_dict()
    if book.image_filename:
        book_dict['image_url'] = url_for('uploaded_file', filename=book.image_filename, _external=True)
    return jsonify(book_dict)

@app.route('/books', methods=['POST'])
@role_required('admin')
def add_book():
    if 'image' not in request.files:
        return jsonify(message="No image part in the request"), 400

    image = request.files['image']
    if image.filename == '':
        return jsonify(message="No image selected for uploading"), 400

    if not allowed_file(image.filename):
        return jsonify(message="File type is not allowed"), 400

    # Get other form data
    title = request.form.get('title')
    author = request.form.get('author')

    if not title or not author:
        return jsonify(message="Title and author are required"), 400

    try:
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        book = Book(
            title=title,
            author=author,
            genre=request.form.get('genre'),
            published_date=request.form.get('published_date'),
            image_filename=filename
        )
        db.session.add(book)
        db.session.commit()
        return jsonify(message="Book added successfully", book=book.as_dict()), 201
    except Exception as e:
        logger.error(f"Error adding book: {str(e)}")
        return jsonify(message="An error occurred while adding the book"), 500

@app.route('/books/<int:id>', methods=['PUT'])
@role_required('admin')
def update_book(id):
    book = Book.query.get_or_404(id)
    if book.is_deleted:
        return jsonify(error="Book not found"), 404

    data = request.form.to_dict()
    for key, value in data.items():
        setattr(book, key, value)
    
    if 'image' in request.files:
        image = request.files['image']
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            book.image_filename = filename
    
    db.session.commit()
    return jsonify(message="Book updated successfully", book=book.as_dict())

@app.route('/books/<int:id>', methods=['DELETE'])
@role_required('admin')
def delete_book(id):
    book = Book.query.get_or_404(id)
    if book.is_deleted:
        return jsonify(error="Book not found"), 404
    book.is_deleted = True
    db.session.commit()
    return jsonify(message="Book deleted successfully")

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# CRUD operations for Customers
@app.route('/customers', methods=['GET'])
@jwt_required()
def get_customers():
    page = request.args.get('page', type=int, default=1)
    per_page = request.args.get('per_page', type=int, default=10)

    if page < 1 or per_page < 1:
        return jsonify({'msg': 'Invalid page or per_page values'}), 422

    customers = Customer.query.paginate(page, per_page, False)
    total_items = customers.total
    total_pages = customers.pages
    current_page = customers.page

    data = {
        'customers': [customer.as_dict() for customer in customers.items],
        'total_items': total_items,
        'total_pages': total_pages,
        'current_page': current_page
    }

    return jsonify(data)

@app.route('/customers', methods=['POST'])
@role_required('admin')
def add_customer():
    data = request.get_json()
    customer = Customer(**data)
    db.session.add(customer)
    db.session.commit()
    return jsonify(message="Customer added successfully", customer=customer.as_dict()), 201

@app.route('/customers/<int:id>', methods=['PUT'])
@role_required('admin')
def update_customer(id):
    customer = Customer.query.get_or_404(id)
    if customer.is_deleted:
        return jsonify(error="Customer not found"), 404

    data = request.get_json()
    for key, value in data.items():
        setattr(customer, key, value)
    db.session.commit()
    return jsonify(message="Customer updated successfully", customer=customer.as_dict())

@app.route('/customers/<int:id>', methods=['DELETE'])
@role_required('admin')
def delete_customer(id):
    customer = Customer.query.get_or_404(id)
    if customer.is_deleted:
        return jsonify(error="Customer not found"), 404
    customer.is_deleted = True
    db.session.commit()
    return jsonify(message="Customer deleted successfully")

# CRUD operations for Loans
@app.route('/loans', methods=['GET'])
@jwt_required()
def get_loans():
    loans = Loan.query.filter_by(is_deleted=False).all()
    loans_with_details = []
    for loan in loans:
        loan_dict = loan.as_dict()
        loan_dict['book_title'] = loan.book.title
        loan_dict['customer_name'] = loan.customer.name
        loans_with_details.append(loan_dict)
    return jsonify(loans_with_details)

@app.route('/loans/<int:id>', methods=['GET'])
@jwt_required()
def get_loan(id):
    loan = Loan.query.get_or_404(id)
    if loan.is_deleted:
        return jsonify(error="Loan not found"), 404
    loan_dict = loan.as_dict()
    loan_dict['book_title'] = loan.book.title
    loan_dict['customer_name'] = loan.customer.name
    return jsonify(loan_dict)

@app.route('/loans', methods=['POST'])
@role_required('admin')
def add_loan():
    data = request.get_json()
    loan = Loan(**data)
    db.session.add(loan)
    db.session.commit()
    return jsonify(message="Loan added successfully", loan=loan.as_dict()), 201

@app.route('/loans/<int:id>', methods=['PUT'])
@role_required('admin')
def update_loan(id):
    loan = Loan.query.get_or_404(id)
    if loan.is_deleted:
        return jsonify(error="Loan not found"), 404

    data = request.get_json()
    for key, value in data.items():
        setattr(loan, key, value)
    db.session.commit()
    return jsonify(message="Loan updated successfully", loan=loan.as_dict())

@app.route('/loans/<int:id>', methods=['DELETE'])
@role_required('admin')
def delete_loan(id):
    loan = Loan.query.get_or_404(id)
    if loan.is_deleted:
        return jsonify(error="Loan not found"), 404
    loan.is_deleted = True
    db.session.commit()
    return jsonify(message="Loan deleted successfully")


# Client-specific loan operations

@app.route('/client/loans', methods=['GET'])
@jwt_required()
def get_client_loans():
    current_user = get_jwt_identity()
    customer = Customer.query.filter_by(user_id=current_user['username']).first()
    if not customer:
        return jsonify(message="Customer not found"), 404

    loans = Loan.query.filter_by(customer_id=customer.id, is_deleted=False).all()
    loans_with_details = []
    for loan in loans:
        loan_dict = loan.as_dict()
        loan_dict['book_title'] = loan.book.title
        loan_dict['loan_date'] = loan.loan_date
        loan_dict['return_date'] = loan.return_date
        loans_with_details.append(loan_dict)
    return jsonify(loans_with_details)

@app.post('/client/loans')
@jwt_required()
def post_loan():
    data = request.get_json()
    book_id = data.get('book_id')
    loan_date = data.get('loan_date')
    customer_id = data.get('customer_id')

    # Validate input
    if not book_id or not loan_date or not customer_id:
        return jsonify({"msg": "Missing data"}), 400

    # Create a new loan record
    new_loan = Loan(book_id=book_id, loan_date=loan_date, customer_id=customer_id)

    # Add loan to the database
    db.session.add(new_loan)
    db.session.commit()

    return jsonify({"msg": "Loan created successfully"}), 201

@app.route('/client/loan_requests', methods=['POST'])
@jwt_required()
def request_loan():
    current_user = get_jwt_identity()
    customer = Customer.query.filter_by(user_id=current_user['username']).first()
    if not customer:
        return jsonify(message="Customer not found"), 404

    data = request.get_json()
    loan = Loan(customer_id=customer.id, **data)
    db.session.add(loan)
    db.session.commit()
    return jsonify(message="Loan requested successfully", loan=loan.as_dict()), 201

@app.route('/client/loans/<int:id>', methods=['PUT'])
@jwt_required()
def return_loan(id):
    current_user = get_jwt_identity()
    customer = Customer.query.filter_by(user_id=current_user['username']).first()
    if not customer:
        return jsonify(message="Customer not found"), 404

    loan = Loan.query.get_or_404(id)
    if loan.customer_id != customer.id or loan.is_deleted:
        return jsonify(error="Loan not found or access denied"), 404

    data = request.get_json()
    for key, value in data.items():
        setattr(loan, key, value)
    loan.returned = True
    db.session.commit()
    return jsonify(message="Loan updated successfully", loan=loan.as_dict())




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)