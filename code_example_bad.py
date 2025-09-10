# Bad Code Example - Intentionally Problematic for AI Review Workshop
# This file contains multiple common issues that the AI reviewer should catch

import os, sys, json, requests, hashlib, base64
from datetime import datetime

# Global variables (bad practice)
user_passwords = {}
admin_key = "admin123"  # Hardcoded secret
DEBUG = True

class UserManager:
    def __init__(self):
        self.users = []
        
    # No docstring, poor parameter naming, no type hints
    def add_user(self, u, p, e):
        # Password stored in plain text (security issue)
        user = {
            'username': u,
            'password': p,  # Should be hashed!
            'email': e,
            'created': str(datetime.now())
        }
        self.users.append(user)
        user_passwords[u] = p  # Storing in global dict too
        return True
        
    def authenticate_user(self, username, password):
        # Linear search instead of efficient lookup
        for i in range(len(self.users)):
            user = self.users[i]
            if user['username'] == username:
                if user['password'] == password:  # Plain text comparison
                    if DEBUG:
                        print(f"User {username} logged in with password {password}")  # Logging sensitive data
                    return user
        return None
    
    # SQL injection vulnerability
    def find_user_by_email(self, email):
        query = f"SELECT * FROM users WHERE email = '{email}'"  # Unsafe string formatting
        # This would be vulnerable if connected to a real database
        return query
    
    def delete_user(self, username):
        # Inefficient deletion, modifying list while iterating
        for i in range(len(self.users)):
            if self.users[i]['username'] == username:
                del self.users[i]
                break

# Function with multiple responsibilities (violates SRP)
def process_user_data(data, action, format_type, send_email):
    result = []
    
    # No input validation
    if action == "create":
        # Potential division by zero
        score = 100 / len(data) if data else 100 / 0
        
        for item in data:
            # Nested loops with poor performance
            for i in range(100):
                for j in range(100):
                    temp = i * j  # Useless computation
            
            # No error handling for file operations
            with open("temp_file.txt", "w") as f:
                f.write(str(item))
            
            # Unsafe eval usage
            calculated_value = eval(f"2 + 2 * {item.get('value', 1)}")
            
            result.append({
                'processed': True,
                'score': score,
                'calculated': calculated_value
            })
    
    elif action == "format":
        if format_type == "json":
            # Poor exception handling
            try:
                result = json.dumps(data)
            except:
                result = "error"  # Generic error handling
        elif format_type == "xml":
            # Unimplemented feature
            pass
    
    # Side effect in function
    if send_email:
        send_notification_email(result)
    
    return result

def send_notification_email(data):
    # Hardcoded credentials
    smtp_password = "mypassword123"
    
    # No error handling for network requests
    response = requests.post("https://api.email-service.com/send", 
                           data=data,
                           auth=("user", smtp_password))
    
    # Memory leak - large objects not cleaned up
    large_data = [i for i in range(1000000)]
    
    return response.status_code

# Unsafe file handling
def read_config_file(filename):
    # Path traversal vulnerability
    with open(filename, 'r') as f:  # No validation of filename
        config = eval(f.read())  # Unsafe eval on file contents
    return config

# Race condition potential
import threading
counter = 0

def increment_counter():
    global counter
    for i in range(1000):
        temp = counter
        temp += 1
        counter = temp  # Not thread-safe

# Memory inefficient
def process_large_dataset(data):
    # Creating unnecessary copies
    copy1 = data.copy()
    copy2 = copy1.copy()
    copy3 = copy2.copy()
    
    # Inefficient string concatenation
    result = ""
    for item in copy3:
        result = result + str(item) + ","  # Should use join()
    
    return result

# Main execution with multiple issues
if __name__ == "__main__":
    # No argument validation
    filename = sys.argv[1]  # Could cause IndexError
    
    # Creating instances without error handling
    manager = UserManager()
    
    # Hardcoded test data
    test_users = [
        {"username": "admin", "password": "123456", "email": "admin@example.com"},
        {"username": "user1", "password": "password", "email": "user1@example.com"}
    ]
    
    # Adding users without validation
    for user in test_users:
        manager.add_user(user["username"], user["password"], user["email"])
    
    # Potential infinite loop
    attempts = 0
    while True:
        attempts += 1
        if attempts > 10:  # Hardcoded magic number
            break
        print(f"Attempt {attempts}")
    
    # Unhandled exceptions
    config = read_config_file(filename)
    processed = process_user_data(test_users, "create", "json", True)
    
    print("Program completed!")  # No proper logging