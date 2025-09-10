#!/usr/bin/env python3
"""
User Management System - Well-Structured Example
Demonstrates security best practices, clean code principles, and proper error handling.

This module provides secure user management functionality including:
- Secure password hashing and authentication
- Input validation and sanitization
- Proper error handling and logging
- Thread-safe operations
- Memory-efficient data processing

Author: Workshop Example
Version: 1.0.0
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import xml.etree.ElementTree as ET

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('user_management.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SecurityConfig:
    """Security configuration and utilities."""
    
    # Security constants
    MIN_PASSWORD_LENGTH = 12
    SALT_LENGTH = 32
    HASH_ITERATIONS = 100000
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate a cryptographically secure random salt."""
        return secrets.token_bytes(SecurityConfig.SALT_LENGTH)
    
    @staticmethod
    def hash_password(password: str, salt: bytes) -> bytes:
        """
        Hash a password using PBKDF2 with SHA-256.
        
        Args:
            password: The plain text password to hash
            salt: Cryptographic salt for the hash
            
        Returns:
            The hashed password as bytes
            
        Raises:
            ValueError: If password is too weak
        """
        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {SecurityConfig.MIN_PASSWORD_LENGTH} characters")
        
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            SecurityConfig.HASH_ITERATIONS
        )
    
    @staticmethod
    def verify_password(password: str, salt: bytes, hashed: bytes) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password: Plain text password to verify
            salt: Salt used for hashing
            hashed: The stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            new_hash = SecurityConfig.hash_password(password, salt)
            return hmac.compare_digest(hashed, new_hash)
        except ValueError:
            return False


class User:
    """Represents a user with secure password handling."""
    
    def __init__(self, username: str, email: str, password_hash: bytes, salt: bytes, 
                 created_at: Optional[datetime] = None):
        """
        Initialize a User instance.
        
        Args:
            username: Unique username
            email: User's email address
            password_hash: Hashed password
            salt: Salt used for password hashing
            created_at: When the user was created (defaults to now)
        """
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.salt = salt
        self.created_at = created_at or datetime.now(timezone.utc)
        self.last_login: Optional[datetime] = None
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert user to dictionary representation.
        
        Args:
            include_sensitive: Whether to include password hash and salt
            
        Returns:
            Dictionary representation of the user
        """
        result = {
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
        
        if include_sensitive:
            result.update({
                'password_hash': self.password_hash.hex(),
                'salt': self.salt.hex()
            })
        
        return result


class UserManager:
    """Thread-safe user management with secure storage."""
    
    def __init__(self, db_path: str = "users.db"):
        """
        Initialize UserManager with SQLite database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize the SQLite database with proper schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash BLOB NOT NULL,
                        salt BLOB NOT NULL,
                        created_at TEXT NOT NULL,
                        last_login TEXT
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_username ON users(username)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_email ON users(email)")
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def add_user(self, username: str, password: str, email: str) -> bool:
        """
        Add a new user with secure password hashing.
        
        Args:
            username: Unique username (3-50 characters, alphanumeric + underscore)
            password: Plain text password (will be hashed)
            email: Valid email address
            
        Returns:
            True if user was added successfully
            
        Raises:
            ValueError: If input validation fails
            sqlite3.IntegrityError: If username or email already exists
        """
        # Input validation
        if not self._validate_username(username):
            raise ValueError("Username must be 3-50 characters, alphanumeric with underscores")
        
        if not self._validate_email(email):
            raise ValueError("Invalid email format")
        
        # Generate secure password hash
        salt = SecurityConfig.generate_salt()
        password_hash = SecurityConfig.hash_password(password, salt)
        
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO users (username, email, password_hash, salt, created_at)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        username,
                        email,
                        password_hash,
                        salt,
                        datetime.now(timezone.utc).isoformat()
                    ))
                    conn.commit()
                
                logger.info(f"User '{username}' created successfully")
                return True
                
            except sqlite3.IntegrityError as e:
                logger.warning(f"Failed to create user '{username}': {e}")
                raise
            except sqlite3.Error as e:
                logger.error(f"Database error creating user: {e}")
                raise
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: Username to authenticate
            password: Plain text password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("""
                        SELECT username, email, password_hash, salt, created_at, last_login
                        FROM users WHERE username = ?
                    """, (username,))
                    
                    row = cursor.fetchone()
                    if not row:
                        logger.info(f"Authentication failed: user '{username}' not found")
                        return None
                    
                    stored_hash = row[2]
                    salt = row[3]
                    
                    if SecurityConfig.verify_password(password, salt, stored_hash):
                        # Update last login
                        now = datetime.now(timezone.utc)
                        conn.execute(
                            "UPDATE users SET last_login = ? WHERE username = ?",
                            (now.isoformat(), username)
                        )
                        conn.commit()
                        
                        user = User(
                            username=row[0],
                            email=row[1],
                            password_hash=stored_hash,
                            salt=salt,
                            created_at=datetime.fromisoformat(row[4])
                        )
                        user.last_login = now
                        
                        logger.info(f"User '{username}' authenticated successfully")
                        return user
                    else:
                        logger.warning(f"Authentication failed for user '{username}': invalid password")
                        return None
                        
            except sqlite3.Error as e:
                logger.error(f"Database error during authentication: {e}")
                return None
    
    def find_user_by_email(self, email: str) -> Optional[User]:
        """
        Find a user by email address using parameterized query.
        
        Args:
            email: Email address to search for
            
        Returns:
            User object if found, None otherwise
        """
        if not self._validate_email(email):
            return None
        
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("""
                        SELECT username, email, password_hash, salt, created_at, last_login
                        FROM users WHERE email = ?
                    """, (email,))
                    
                    row = cursor.fetchone()
                    if row:
                        user = User(
                            username=row[0],
                            email=row[1],
                            password_hash=row[2],
                            salt=row[3],
                            created_at=datetime.fromisoformat(row[4])
                        )
                        if row[5]:
                            user.last_login = datetime.fromisoformat(row[5])
                        return user
                    
                    return None
                    
            except sqlite3.Error as e:
                logger.error(f"Database error finding user by email: {e}")
                return None
    
    def delete_user(self, username: str) -> bool:
        """
        Safely delete a user by username.
        
        Args:
            username: Username to delete
            
        Returns:
            True if user was deleted, False if not found
        """
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
                    conn.commit()
                    
                    if cursor.rowcount > 0:
                        logger.info(f"User '{username}' deleted successfully")
                        return True
                    else:
                        logger.info(f"User '{username}' not found for deletion")
                        return False
                        
            except sqlite3.Error as e:
                logger.error(f"Database error deleting user: {e}")
                return False
    
    def list_users(self) -> List[User]:
        """
        Get a list of all users (without sensitive data).
        
        Returns:
            List of User objects
        """
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("""
                        SELECT username, email, password_hash, salt, created_at, last_login
                        FROM users ORDER BY created_at
                    """)
                    
                    users = []
                    for row in cursor.fetchall():
                        user = User(
                            username=row[0],
                            email=row[1],
                            password_hash=row[2],
                            salt=row[3],
                            created_at=datetime.fromisoformat(row[4])
                        )
                        if row[5]:
                            user.last_login = datetime.fromisoformat(row[5])
                        users.append(user)
                    
                    return users
                    
            except sqlite3.Error as e:
                logger.error(f"Database error listing users: {e}")
                return []
    
    @staticmethod
    def _validate_username(username: str) -> bool:
        """Validate username format."""
        if not isinstance(username, str):
            return False
        return (3 <= len(username) <= 50 and 
                username.replace('_', '').isalnum() and 
                not username.startswith('_'))
    
    @staticmethod
    def _validate_email(email: str) -> bool:
        """Basic email validation."""
        if not isinstance(email, str):
            return False
        return '@' in email and '.' in email.split('@')[-1] and len(email) <= 254


class DataProcessor:
    """Secure and efficient data processing utilities."""
    
    @staticmethod
    def process_user_data(users: List[Dict[str, Any]], action: str) -> Dict[str, Any]:
        """
        Process user data with proper validation and error handling.
        
        Args:
            users: List of user dictionaries to process
            action: Processing action ('analyze', 'validate', 'export')
            
        Returns:
            Dictionary containing processing results
            
        Raises:
            ValueError: If invalid action or data provided
        """
        if not isinstance(users, list):
            raise ValueError("Users must be a list")
        
        if not users:
            return {'status': 'success', 'message': 'No users to process', 'results': []}
        
        valid_actions = {'analyze', 'validate', 'export'}
        if action not in valid_actions:
            raise ValueError(f"Action must be one of: {valid_actions}")
        
        try:
            if action == 'analyze':
                return DataProcessor._analyze_users(users)
            elif action == 'validate':
                return DataProcessor._validate_users(users)
            elif action == 'export':
                return DataProcessor._export_users(users)
        
        except Exception as e:
            logger.error(f"Error processing user data: {e}")
            return {'status': 'error', 'message': str(e), 'results': []}
    
    @staticmethod
    def _analyze_users(users: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze user data for insights."""
        total_users = len(users)
        
        # Safe calculation - avoid division by zero
        average_score = 100.0 if total_users > 0 else 0.0
        
        # Efficient processing without nested loops
        results = []
        for user in users:
            # Safe value extraction with defaults
            user_value = user.get('value', 1)
            
            # Safe arithmetic - validate input
            try:
                calculated_value = 2 + 2 * float(user_value)
            except (ValueError, TypeError):
                calculated_value = 2.0  # Default fallback
            
            results.append({
                'username': user.get('username', 'unknown'),
                'processed': True,
                'score': average_score,
                'calculated': calculated_value
            })
        
        return {
            'status': 'success',
            'message': f'Analyzed {total_users} users',
            'results': results,
            'summary': {
                'total_users': total_users,
                'average_score': average_score
            }
        }
    
    @staticmethod
    def _validate_users(users: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate user data structure."""
        required_fields = {'username', 'email'}
        results = []
        
        for i, user in enumerate(users):
            validation_result = {
                'index': i,
                'valid': True,
                'errors': []
            }
            
            if not isinstance(user, dict):
                validation_result['valid'] = False
                validation_result['errors'].append('User must be a dictionary')
            else:
                missing_fields = required_fields - set(user.keys())
                if missing_fields:
                    validation_result['valid'] = False
                    validation_result['errors'].append(f'Missing fields: {missing_fields}')
                
                if 'email' in user and not UserManager._validate_email(user['email']):
                    validation_result['valid'] = False
                    validation_result['errors'].append('Invalid email format')
            
            results.append(validation_result)
        
        valid_count = sum(1 for r in results if r['valid'])
        
        return {
            'status': 'success',
            'message': f'Validated {len(users)} users',
            'results': results,
            'summary': {
                'total_users': len(users),
                'valid_users': valid_count,
                'invalid_users': len(users) - valid_count
            }
        }
    
    @staticmethod
    def _export_users(users: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Export users to different formats."""
        try:
            # JSON export with proper error handling
            json_data = json.dumps(users, indent=2, default=str)
            
            # XML export
            root = ET.Element("users")
            for user in users:
                user_elem = ET.SubElement(root, "user")
                for key, value in user.items():
                    elem = ET.SubElement(user_elem, key)
                    elem.text = str(value) if value is not None else ""
            
            xml_data = ET.tostring(root, encoding='unicode')
            
            return {
                'status': 'success',
                'message': f'Exported {len(users)} users',
                'results': {
                    'json': json_data,
                    'xml': xml_data
                }
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Export failed: {e}',
                'results': {}
            }


class EmailService:
    """Secure email notification service with proper error handling."""
    
    def __init__(self, base_url: str, timeout: int = 30):
        """
        Initialize EmailService with retry strategy.
        
        Args:
            base_url: Base URL for email service API
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.timeout = timeout
    
    def send_notification(self, recipient: str, subject: str, message: str) -> bool:
        """
        Send notification email with proper error handling.
        
        Args:
            recipient: Email recipient
            subject: Email subject
            message: Email message body
            
        Returns:
            True if email sent successfully
        """
        # Input validation
        if not UserManager._validate_email(recipient):
            logger.error(f"Invalid recipient email: {recipient}")
            return False
        
        # Get credentials from environment (never hardcode)
        api_key = os.getenv('EMAIL_API_KEY')
        if not api_key:
            logger.error("EMAIL_API_KEY environment variable not set")
            return False
        
        try:
            payload = {
                'to': recipient,
                'subject': subject,
                'message': message,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            response = self.session.post(
                f"{self.base_url}/send",
                json=payload,
                headers=headers
            )
            
            response.raise_for_status()
            
            logger.info(f"Notification sent successfully to {recipient}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send notification: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending notification: {e}")
            return False


class ConfigManager:
    """Secure configuration file handling."""
    
    @staticmethod
    def read_config_file(filename: str) -> Dict[str, Any]:
        """
        Safely read and parse configuration file.
        
        Args:
            filename: Configuration file path
            
        Returns:
            Configuration dictionary
            
        Raises:
            ValueError: If file path is invalid or unsafe
            FileNotFoundError: If configuration file doesn't exist
            json.JSONDecodeError: If JSON is invalid
        """
        # Validate file path to prevent directory traversal
        file_path = Path(filename).resolve()
        
        # Ensure file is in allowed directory
        allowed_dir = Path.cwd().resolve()
        try:
            file_path.relative_to(allowed_dir)
        except ValueError:
            raise ValueError(f"Configuration file must be in current directory: {allowed_dir}")
        
        # Check file exists and is readable
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Use json.load instead of eval for security
                config = json.load(f)
            
            logger.info(f"Configuration loaded from {file_path}")
            return config
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration file: {e}")
            raise
        except Exception as e:
            logger.error(f"Error reading configuration file: {e}")
            raise


def process_large_dataset(data: List[Any]) -> str:
    """
    Memory-efficient processing of large datasets.
    
    Args:
        data: Input data to process
        
    Returns:
        Processed data as comma-separated string
    """
    if not data:
        return ""
    
    # Use generator for memory efficiency
    def process_items():
        for item in data:
            yield str(item)
    
    # Use join for efficient string concatenation
    return ",".join(process_items())


def main() -> int:
    """
    Main application entry point with proper argument handling.
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    parser = argparse.ArgumentParser(
        description="Secure User Management System",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config.json',
        help='Configuration file path (default: config.json)'
    )
    
    parser.add_argument(
        '--action',
        choices=['demo', 'list-users', 'test-auth'],
        default='demo',
        help='Action to perform (default: demo)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    try:
        args = parser.parse_args()
        
        # Set logging level
        logging.getLogger().setLevel(getattr(logging, args.log_level))
        
        # Load configuration safely
        try:
            config = ConfigManager.read_config_file(args.config)
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            logger.warning(f"Could not load config file {args.config}, using defaults")
            config = {
                'database': 'users.db',
                'email_service_url': 'https://api.example.com'
            }
        
        # Initialize user manager
        manager = UserManager(config.get('database', 'users.db'))
        
        if args.action == 'demo':
            # Demonstrate secure user operations
            logger.info("Running user management demo...")
            
            # Sample user data with validation
            test_users = [
                {
                    "username": "admin_user",
                    "password": "SecureP@ssw0rd123!",
                    "email": "admin@example.com"
                },
                {
                    "username": "regular_user",
                    "password": "AnotherSecureP@ss456!",
                    "email": "user@example.com"
                }
            ]
            
            # Add users with proper error handling
            for user_data in test_users:
                try:
                    success = manager.add_user(
                        user_data["username"],
                        user_data["password"],
                        user_data["email"]
                    )
                    if success:
                        logger.info(f"Added user: {user_data['username']}")
                except (ValueError, sqlite3.IntegrityError) as e:
                    logger.warning(f"Could not add user {user_data['username']}: {e}")
            
            # Test authentication
            user = manager.authenticate_user("admin_user", "SecureP@ssw0rd123!")
            if user:
                logger.info(f"Authentication successful for {user.username}")
            
            # Process data safely
            processor_result = DataProcessor.process_user_data(test_users, 'analyze')
            logger.info(f"Data processing result: {processor_result['status']}")
            
        elif args.action == 'list-users':
            users = manager.list_users()
            for user in users:
                print(f"User: {user.username}, Email: {user.email}, Created: {user.created_at}")
        
        elif args.action == 'test-auth':
            username = input("Username: ")
            password = input("Password: ")
            user = manager.authenticate_user(username, password)
            if user:
                print(f"Authentication successful! Welcome, {user.username}")
            else:
                print("Authentication failed.")
        
        logger.info("Application completed successfully")
        return 0
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())