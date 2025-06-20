import os
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import hashlib
import base64

# Load environment variables
load_dotenv()

# Custom password hashing function compatible with Python 3.13
def custom_generate_password_hash(password):
    """Generate a secure password hash."""
    salt = os.urandom(16)  # Generate a random salt
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return f"pbkdf2:sha256:100000${base64.b64encode(salt).decode('utf-8')}${base64.b64encode(pwdhash).decode('utf-8')}"

def update_admin_password():
    """Update the admin password"""
    try:
        # Connect to MySQL server
        connection = mysql.connector.connect(
            host=os.getenv('MYSQL_HOST', 'localhost'),
            user=os.getenv('MYSQL_USER', 'root'),
            password=os.getenv('MYSQL_PASSWORD', 'Varunloni@12'),
            database=os.getenv('MYSQL_DATABASE', 'bricks_production')
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Generate new admin password hash
            admin_password = custom_generate_password_hash('admin123')
            
            # Check if admin user exists
            cursor.execute("SELECT id FROM users WHERE email = 'admin@example.com'")
            admin_exists = cursor.fetchone()
            
            if admin_exists:
                # Update admin password
                cursor.execute("""
                    UPDATE users SET password = %s WHERE email = 'admin@example.com'
                """, (admin_password,))
                print("Admin password updated successfully!")
            else:
                # Create admin user
                cursor.execute("""
                    INSERT INTO users (username, email, password, role)
                    VALUES ('admin', 'admin@example.com', %s, 'admin')
                """, (admin_password,))
                print("Admin user created successfully!")
            
            connection.commit()
            
    except Error as e:
        print(f"Error updating admin password: {e}")
    
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection is closed")

if __name__ == "__main__":
    update_admin_password() 