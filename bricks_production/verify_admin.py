import os
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import hashlib
import base64
import getpass

# Load environment variables
load_dotenv()

# Custom password hashing function compatible with Python 3.13
def custom_generate_password_hash(password):
    """Generate a secure password hash."""
    salt = os.urandom(16)  # Generate a random salt
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return f"pbkdf2:sha256:100000${base64.b64encode(salt).decode('utf-8')}${base64.b64encode(pwdhash).decode('utf-8')}"

def reset_admin_password():
    """Reset the admin password"""
    try:
        # Connect to MySQL server
        connection = mysql.connector.connect(
            host=os.getenv('MYSQL_HOST', 'localhost'),
            user=os.getenv('MYSQL_USER', 'root'),
            password=os.getenv('MYSQL_PASSWORD', 'Varunloni@12'),
            database=os.getenv('MYSQL_DATABASE', 'bricks_production')
        )
        
        if connection.is_connected():
            cursor = connection.cursor(dictionary=True)
            
            # Check if admin user exists
            cursor.execute("SELECT * FROM users WHERE email = 'admin@example.com'")
            admin = cursor.fetchone()
            
            if admin:
                print(f"Found admin user: ID={admin['id']}, Username={admin['username']}")
                
                # Generate a simple password hash for testing
                new_password = "admin123"
                simple_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
                
                # Update with simple hash for testing
                cursor.execute("""
                    UPDATE users SET password = %s WHERE email = 'admin@example.com'
                """, (simple_hash,))
                
                connection.commit()
                print(f"Admin password reset to '{new_password}' with simple SHA-256 hash")
                print(f"New hash: {simple_hash}")
            else:
                print("Admin user not found!")
                
                # Create admin user with simple hash
                new_password = "admin123"
                simple_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
                
                cursor.execute("""
                    INSERT INTO users (username, email, password, role)
                    VALUES ('admin', 'admin@example.com', %s, 'admin')
                """, (simple_hash,))
                
                connection.commit()
                print(f"Created admin user with password '{new_password}' and simple SHA-256 hash")
            
    except Error as e:
        print(f"Error: {e}")
    
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection is closed")

if __name__ == "__main__":
    reset_admin_password() 