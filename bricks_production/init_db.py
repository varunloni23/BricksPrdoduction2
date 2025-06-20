import os
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import hashlib
import base64
import secrets

# Load environment variables
load_dotenv()

# Custom password hashing function compatible with Python 3.13
def custom_generate_password_hash(password):
    """Generate a secure password hash."""
    salt = os.urandom(16)  # Generate a random salt
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return f"pbkdf2:sha256:100000${base64.b64encode(salt).decode('utf-8')}${base64.b64encode(pwdhash).decode('utf-8')}"

def init_db():
    """Initialize the database with schema and sample data"""
    try:
        # Connect to MySQL server
        connection = mysql.connector.connect(
            host=os.getenv('MYSQL_HOST', 'localhost'),
            user=os.getenv('MYSQL_USER', 'root'),
            password=os.getenv('MYSQL_PASSWORD', 'Varunloni@12')
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Create database if it doesn't exist
            cursor.execute("CREATE DATABASE IF NOT EXISTS bricks_production")
            
            # Switch to the database
            cursor.execute("USE bricks_production")
            
            # Drop and recreate users table
            print("Dropping users table...")
            cursor.execute("DROP TABLE IF EXISTS order_items")
            cursor.execute("DROP TABLE IF EXISTS orders")
            cursor.execute("DROP TABLE IF EXISTS users")
            
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    email VARCHAR(100) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    role ENUM('admin', 'customer') NOT NULL DEFAULT 'customer',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Read schema SQL file for other tables
            with open('database/schema.sql', 'r') as f:
                sql_commands = f.read()
                
            # Skip the users table creation in the schema
            sql_commands = sql_commands.replace("""CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'customer') NOT NULL DEFAULT 'customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);""", "")
            
            # Execute schema commands
            for command in sql_commands.split(';'):
                if command.strip() and "CREATE TABLE IF NOT EXISTS users" not in command:
                    cursor.execute(command)
            
            # Create admin user with hashed password
            admin_password = custom_generate_password_hash('admin123')
            cursor.execute("""
                INSERT INTO users (username, email, password, role)
                VALUES ('admin', 'admin@example.com', %s, 'admin')
            """, (admin_password,))
            print("Admin user created successfully!")
            
            connection.commit()
            print("Database initialized successfully!")
            
    except Error as e:
        print(f"Error initializing database: {e}")
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection is closed")

if __name__ == "__main__":
    init_db() 