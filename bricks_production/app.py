import os
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import stripe
from datetime import datetime
import secrets
import decimal
import hashlib
import hmac
import base64

# Custom password hashing functions compatible with Python 3.13
def custom_generate_password_hash(password):
    """Generate a secure password hash."""
    salt = os.urandom(16)  # Generate a random salt
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return f"pbkdf2:sha256:100000${base64.b64encode(salt).decode('utf-8')}${base64.b64encode(pwdhash).decode('utf-8')}"

def custom_check_password_hash(pwhash, password):
    """Check if the password matches the hash."""
    try:
        print(f"Password hash format: {pwhash[:20]}...")  # Debug info
        
        # Check if it's a simple SHA-256 hash (64 hex characters)
        if len(pwhash) == 64 and all(c in '0123456789abcdef' for c in pwhash.lower()):
            print("Using simple SHA-256 hash")  # Debug info
            # Compute SHA-256 hash of the password
            computed_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            # Compare hashes
            result = pwhash.lower() == computed_hash.lower()
            print(f"Simple hash comparison result: {result}")  # Debug info
            return result
        # For compatibility with werkzeug's format
        elif pwhash.startswith('pbkdf2:sha256:'):
            print("Using pbkdf2 format")  # Debug info
            # Parse the hash string
            try:
                algorithm, iterations, salt_hash = pwhash.split('$', 2)
                method, salt_algo, iterations = algorithm.split(':')
                iterations = int(iterations)
                salt = base64.b64decode(salt_hash.split('$')[0])
                stored_hash = base64.b64decode(salt_hash.split('$')[1])
                
                # Compute hash with the same parameters
                computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
                
                # Compare using constant-time comparison
                result = hmac.compare_digest(computed_hash, stored_hash)
                print(f"Hash comparison result: {result}")  # Debug info
                return result
            except Exception as e:
                print(f"Error parsing pbkdf2 hash: {e}")  # Debug info
                return False
        else:
            # Fall back to werkzeug's implementation for other formats
            # This might still fail on Python 3.13 for some hash formats
            print("Falling back to werkzeug's check_password_hash")  # Debug info
            try:
                result = check_password_hash(pwhash, password)
                print(f"Werkzeug check result: {result}")  # Debug info
                return result
            except Exception as e:
                print(f"Werkzeug check_password_hash error: {e}")  # Debug info
                return False
    except Exception as e:
        print(f"Password check error: {e}")  # Debug info
        return False

# Helper function to convert Decimal to float
def decimal_to_float(obj):
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: decimal_to_float(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [decimal_to_float(item) for item in obj]
    return obj

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['UPLOAD_FOLDER'] = 'static/images/products'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Add context processor for datetime
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Stripe configuration
stripe_keys = {
    'secret_key': os.getenv('STRIPE_SECRET_KEY', 'your_stripe_secret_key'),
    'publishable_key': os.getenv('STRIPE_PUBLISHABLE_KEY', 'your_stripe_publishable_key')
}
stripe.api_key = stripe_keys['secret_key']

# Database connection function
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('MYSQL_HOST', 'localhost'),
            user=os.getenv('MYSQL_USER', 'root'),
            password=os.getenv('MYSQL_PASSWORD', 'Varunloni@12'),
            database=os.getenv('MYSQL_DATABASE', 'bricks_production')
        )
        if connection.is_connected():
            return connection
        else:
            print("Failed to connect to MySQL database")
            return None
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user_data:
            return User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role']
            )
    return None

# Routes for customer side
@app.route('/')
def home():
    # Get featured products
    conn = get_db_connection()
    products = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products WHERE featured = 1 LIMIT 6")
        products = cursor.fetchall()
        cursor.close()
        conn.close()
    return render_template('customer/home.html', products=products)

@app.route('/products')
def products():
    # Get all products
    conn = get_db_connection()
    products = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        cursor.close()
        conn.close()
    return render_template('customer/products.html', products=products)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        cursor.close()
        conn.close()
        if product:
            return render_template('customer/product_detail.html', product=product)
    flash('Product not found', 'danger')
    return redirect(url_for('products'))

@app.route('/cart')
def cart():
    cart_items = session.get('cart', {})
    products = []
    total = 0
    
    if cart_items:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            for product_id, quantity in cart_items.items():
                cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
                product = cursor.fetchone()
                if product:
                    # Convert all Decimal values to float
                    product = decimal_to_float(product)
                    product['quantity'] = quantity
                    product['subtotal'] = product['price'] * quantity
                    total += product['subtotal']
                    products.append(product)
            cursor.close()
            conn.close()
    
    return render_template('customer/cart.html', cart_items=products, total=total)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    quantity = int(request.form.get('quantity', 1))
    
    # Initialize cart if it doesn't exist
    if 'cart' not in session:
        session['cart'] = {}
    
    # Add to cart or update quantity
    if str(product_id) in session['cart']:
        session['cart'][str(product_id)] += quantity
    else:
        session['cart'][str(product_id)] = quantity
    
    session.modified = True
    flash('Product added to cart', 'success')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/update_cart', methods=['POST'])
def update_cart():
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity'))
    
    if 'cart' in session and product_id in session['cart']:
        if quantity > 0:
            session['cart'][product_id] = quantity
        else:
            session['cart'].pop(product_id, None)
    
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<product_id>')
def remove_from_cart(product_id):
    if 'cart' in session and product_id in session['cart']:
        session['cart'].pop(product_id, None)
        session.modified = True
    
    return redirect(url_for('cart'))

@app.route('/checkout')
@login_required
def checkout():
    cart_items = session.get('cart', {})
    if not cart_items:
        flash('Your cart is empty', 'warning')
        return redirect(url_for('cart'))
    
    products = []
    total = 0
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        for product_id, quantity in cart_items.items():
            cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
            product = cursor.fetchone()
            if product:
                # Convert all Decimal values to float
                product = decimal_to_float(product)
                product['quantity'] = quantity
                product['subtotal'] = product['price'] * quantity
                total += product['subtotal']
                products.append(product)
        cursor.close()
        conn.close()
    
    return render_template('customer/checkout.html', 
                           cart_items=products, 
                           total=total, 
                           stripe_key=stripe_keys['publishable_key'])

@app.route('/create-payment-intent', methods=['POST'])
@login_required
def create_payment():
    try:
        data = request.json
        amount = int(float(data.get('amount', 0)) * 100)  # Convert to cents
        
        # Create a PaymentIntent with the order amount and currency
        intent = stripe.PaymentIntent.create(
            amount=amount,
            currency='usd',
            automatic_payment_methods={
                'enabled': True,
            },
        )
        
        return {
            'clientSecret': intent['client_secret']
        }
    except Exception as e:
        return {'error': str(e)}, 403

@app.route('/place-order', methods=['POST'])
@login_required
def place_order():
    # Get form data
    payment_method = request.form.get('payment_method')
    shipping_info = {
        'first_name': request.form.get('firstName'),
        'last_name': request.form.get('lastName'),
        'email': request.form.get('email'),
        'address': request.form.get('address'),
        'address2': request.form.get('address2'),
        'country': request.form.get('country'),
        'state': request.form.get('state'),
        'zip': request.form.get('zip'),
        'phone': request.form.get('phone')
    }
    
    # Store shipping info in session for order processing
    session['shipping_info'] = shipping_info
    
    # Create order in database
    if 'cart' in session and session['cart']:
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                
                # Create order
                order_id = secrets.token_hex(8)
                
                # Set status based on payment method
                status = 'Pending' if payment_method == 'cod' else 'Paid'
                
                cursor.execute(
                    "INSERT INTO orders (order_id, user_id, order_date, status) VALUES (%s, %s, %s, %s)",
                    (order_id, current_user.id, datetime.now(), status)
                )
                
                # Add order items
                for product_id, quantity in session['cart'].items():
                    cursor.execute(
                        "INSERT INTO order_items (order_id, product_id, quantity) VALUES (%s, %s, %s)",
                        (order_id, product_id, quantity)
                    )
                
                # Store shipping information in session for confirmation page
                session['last_order_id'] = order_id
                
                conn.commit()
                
                # Clear cart
                session.pop('cart', None)
                
                flash('Order placed successfully!', 'success')
                return redirect(url_for('order_confirmation'))
                
            except Error as e:
                conn.rollback()
                flash(f'Error processing order: {e}', 'danger')
                return redirect(url_for('checkout'))
            finally:
                cursor.close()
                conn.close()
    
    flash('Your cart is empty', 'warning')
    return redirect(url_for('cart'))

@app.route('/payment-success')
@login_required
def payment_success():
    # This route is called after successful Stripe payment
    # Create order in database
    if 'cart' in session and session['cart']:
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                
                # Create order
                order_id = secrets.token_hex(8)
                cursor.execute(
                    "INSERT INTO orders (order_id, user_id, order_date, status) VALUES (%s, %s, %s, %s)",
                    (order_id, current_user.id, datetime.now(), 'Paid')
                )
                
                # Add order items
                for product_id, quantity in session['cart'].items():
                    cursor.execute(
                        "INSERT INTO order_items (order_id, product_id, quantity) VALUES (%s, %s, %s)",
                        (order_id, product_id, quantity)
                    )
                
                # Store order ID for confirmation page
                session['last_order_id'] = order_id
                
                conn.commit()
                
                # Clear cart
                session.pop('cart', None)
                
                flash('Order placed successfully!', 'success')
            except Error as e:
                conn.rollback()
                flash(f'Error processing order: {e}', 'danger')
            finally:
                cursor.close()
                conn.close()
    
    return redirect(url_for('order_confirmation'))

@app.route('/order-confirmation')
@login_required
def order_confirmation():
    order_id = session.get('last_order_id')
    if not order_id:
        return redirect(url_for('profile'))
    
    conn = get_db_connection()
    order = None
    items = []
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        # Get order details
        cursor.execute("""
            SELECT * FROM orders WHERE order_id = %s AND user_id = %s
        """, (order_id, current_user.id))
        order = cursor.fetchone()
        
        if order:
            # Get order items
            cursor.execute("""
                SELECT oi.*, p.name, p.price, p.image_url
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                WHERE oi.order_id = %s
            """, (order_id,))
            items = cursor.fetchall()
            
            # Convert decimal values to float
            items = decimal_to_float(items)
        
        cursor.close()
        conn.close()
    
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('profile'))
    
    # Calculate order total
    total = sum(item['price'] * item['quantity'] for item in items)
    
    return render_template('customer/order_confirmation.html', 
                          order=order, 
                          items=items, 
                          total=total)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        terms = request.form.get('terms')
        
        # Validate form inputs
        if not username or not email or not password or not confirm_password:
            flash('All fields are required', 'danger')
            return render_template('customer/register.html')
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('customer/register.html')
            
        # Check if terms are accepted
        if not terms:
            flash('You must accept the Terms and Conditions', 'danger')
            return render_template('customer/register.html')
            
        # Check password length
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return render_template('customer/register.html')
        
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                
                # Check if user already exists
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                if cursor.fetchone():
                    flash('Email already registered', 'danger')
                    cursor.close()
                    conn.close()
                    return render_template('customer/register.html')
                
                # Create new user
                hashed_password = custom_generate_password_hash(password)
                cursor.execute(
                    "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
                    (username, email, hashed_password, 'customer')
                )
                conn.commit()
                
                # Get the new user
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                user_data = cursor.fetchone()
                cursor.close()
                conn.close()
                
                if user_data:
                    user = User(
                        id=user_data['id'],
                        username=user_data['username'],
                        email=user_data['email'],
                        role=user_data['role']
                    )
                    login_user(user)
                    flash('Registration successful!', 'success')
                    return redirect(url_for('home'))
            else:
                flash('Database connection error. Please try again later.', 'danger')
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'danger')
    
    return render_template('customer/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        print(f"Login attempt: {email}")  # Debug info
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user_data = cursor.fetchone()
            cursor.close()
            conn.close()
            
            print(f"User found: {user_data is not None}")  # Debug info
            
            if user_data:
                print(f"User role: {user_data['role']}")  # Debug info
                password_check = custom_check_password_hash(user_data['password'], password)
                print(f"Password check result: {password_check}")  # Debug info
                
                if password_check:
                    user = User(
                        id=user_data['id'],
                        username=user_data['username'],
                        email=user_data['email'],
                        role=user_data['role']
                    )
                    login_user(user)
                    
                    # Redirect based on role
                    if user.role == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('home'))
            
        flash('Invalid email or password', 'danger')
    
    return render_template('customer/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    orders = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT o.*, COUNT(oi.id) as item_count, SUM(p.price * oi.quantity) as total_amount
            FROM orders o
            JOIN order_items oi ON o.order_id = oi.order_id
            JOIN products p ON oi.product_id = p.id
            WHERE o.user_id = %s
            GROUP BY o.order_id
            ORDER BY o.order_date DESC
        """, (current_user.id,))
        orders = cursor.fetchall()
        
        # Convert decimal values to float
        orders = decimal_to_float(orders)
        
        cursor.close()
        conn.close()
    
    return render_template('customer/profile.html', orders=orders)

@app.route('/order/<order_id>')
@login_required
def order_detail(order_id):
    conn = get_db_connection()
    order = None
    items = []
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        # Get order details
        cursor.execute("""
            SELECT * FROM orders WHERE order_id = %s AND user_id = %s
        """, (order_id, current_user.id))
        order = cursor.fetchone()
        
        if order:
            # Get order items
            cursor.execute("""
                SELECT oi.*, p.name, p.price, p.image_url
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                WHERE oi.order_id = %s
            """, (order_id,))
            items = cursor.fetchall()
            
            # Convert decimal values to float
            items = decimal_to_float(items)
        
        cursor.close()
        conn.close()
    
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('profile'))
    
    return render_template('customer/order_detail.html', order=order, items=items)

# Admin routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    stats = {
        'total_orders': 0,
        'total_revenue': 0,
        'total_products': 0,
        'total_customers': 0
    }
    
    recent_orders = []
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        # Get statistics
        cursor.execute("SELECT COUNT(*) as count FROM orders")
        result = cursor.fetchone()
        stats['total_orders'] = result['count'] if result else 0
        
        cursor.execute("""
            SELECT SUM(p.price * oi.quantity) as total
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
        """)
        result = cursor.fetchone()
        stats['total_revenue'] = result['total'] if result and result['total'] else 0
        
        cursor.execute("SELECT COUNT(*) as count FROM products")
        result = cursor.fetchone()
        stats['total_products'] = result['count'] if result else 0
        
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE role = 'customer'")
        result = cursor.fetchone()
        stats['total_customers'] = result['count'] if result else 0
        
        # Get recent orders
        cursor.execute("""
            SELECT o.*, u.username, COUNT(oi.id) as item_count, SUM(p.price * oi.quantity) as total_amount
            FROM orders o
            JOIN users u ON o.user_id = u.id
            JOIN order_items oi ON o.order_id = oi.order_id
            JOIN products p ON oi.product_id = p.id
            GROUP BY o.order_id
            ORDER BY o.order_date DESC
            LIMIT 10
        """)
        recent_orders = cursor.fetchall()
        
        cursor.close()
        conn.close()
    
    return render_template('admin/dashboard.html', stats=stats, recent_orders=recent_orders)

@app.route('/admin/products')
@login_required
def admin_products():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    products = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products ORDER BY id DESC")
        products = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('admin/products.html', products=products)

@app.route('/admin/product/add', methods=['GET', 'POST'])
@login_required
def admin_add_product():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = float(request.form.get('price', 0))
        stock = int(request.form.get('stock', 0))
        featured = 1 if request.form.get('featured') else 0
        
        # Handle image upload
        image_url = 'default.jpg'  # Default image
        if 'image' in request.files:
            file = request.files['image']
            if file.filename:
                filename = secure_filename(file.filename)
                # Use absolute path with os.path.abspath
                file_path = os.path.join(os.path.abspath(app.config['UPLOAD_FOLDER']), filename)
                # Ensure directory exists
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                file.save(file_path)
                image_url = filename
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO products (name, description, price, stock, image_url, featured)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, description, price, stock, image_url, featured))
            conn.commit()
            cursor.close()
            conn.close()
            flash('Product added successfully', 'success')
            return redirect(url_for('admin_products'))
    
    return render_template('admin/add_product.html')

@app.route('/admin/product/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_product(product_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_products'))
    
    cursor = conn.cursor(dictionary=True)
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = float(request.form.get('price', 0))
        stock = int(request.form.get('stock', 0))
        featured = 1 if request.form.get('featured') else 0
        
        # Get current product to check if image is updated
        cursor.execute("SELECT image_url FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        image_url = product['image_url'] if product else 'default.jpg'
        
        # Handle image upload
        if 'image' in request.files:
            file = request.files['image']
            if file.filename:
                filename = secure_filename(file.filename)
                # Use absolute path with os.path.abspath
                file_path = os.path.join(os.path.abspath(app.config['UPLOAD_FOLDER']), filename)
                # Ensure directory exists
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                file.save(file_path)
                image_url = filename
        
        cursor.execute("""
            UPDATE products 
            SET name = %s, description = %s, price = %s, stock = %s, image_url = %s, featured = %s
            WHERE id = %s
        """, (name, description, price, stock, image_url, featured, product_id))
        conn.commit()
        flash('Product updated successfully', 'success')
        return redirect(url_for('admin_products'))
    
    # Get product for editing
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('admin_products'))
    
    return render_template('admin/edit_product.html', product=product)

@app.route('/admin/product/delete/<int:product_id>')
@login_required
def admin_delete_product(product_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Product deleted successfully', 'success')
    
    return redirect(url_for('admin_products'))

@app.route('/admin/orders')
@login_required
def admin_orders():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    orders = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT o.*, u.username, COUNT(oi.id) as item_count, SUM(p.price * oi.quantity) as total_amount
            FROM orders o
            JOIN users u ON o.user_id = u.id
            JOIN order_items oi ON o.order_id = oi.order_id
            JOIN products p ON oi.product_id = p.id
            GROUP BY o.order_id
            ORDER BY o.order_date DESC
        """)
        orders = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('admin/orders.html', orders=orders)

@app.route('/admin/order/<order_id>')
@login_required
def admin_order_detail(order_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    order = None
    items = []
    customer = None
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        # Get order details
        cursor.execute("""
            SELECT o.*, u.username, u.email
            FROM orders o
            JOIN users u ON o.user_id = u.id
            WHERE o.order_id = %s
        """, (order_id,))
        order = cursor.fetchone()
        
        if order:
            customer = {
                'username': order['username'],
                'email': order['email']
            }
            
            # Get order items
            cursor.execute("""
                SELECT oi.*, p.name, p.price, p.image_url
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                WHERE oi.order_id = %s
            """, (order_id,))
            items = cursor.fetchall()
        
        cursor.close()
        conn.close()
    
    if not order:
        flash('Order not found', 'danger')
        return redirect(url_for('admin_orders'))
    
    return render_template('admin/order_detail.html', order=order, items=items, customer=customer)

@app.route('/admin/order/update-status/<order_id>', methods=['POST'])
@login_required
def admin_update_order_status(order_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    status = request.form.get('status')
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE orders SET status = %s WHERE order_id = %s", (status, order_id))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Order status updated', 'success')
    
    return redirect(url_for('admin_order_detail', order_id=order_id))

@app.route('/admin/customers')
@login_required
def admin_customers():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    customers = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.*, COUNT(o.id) as order_count
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            WHERE u.role = 'customer'
            GROUP BY u.id
            ORDER BY u.id DESC
        """)
        customers = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('admin/customers.html', customers=customers)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('customer/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('customer/500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, port=5002) 