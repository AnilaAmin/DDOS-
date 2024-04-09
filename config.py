import os

class Config:
    SECRET_KEY = os.urandom(32)
    JWT_SECRET_KEY = os.urandom(32) 

class Config:
    SECRET_KEY = os.urandom(32)
    JWT_SECRET_KEY = os.urandom(32)



SECURITY_PASSWORD_SALT = 'your-password-salt'
SECURITY_PASSWORD_HASH = 'bcrypt'
SECURITY_TRACKABLE = False
SECURITY_REGISTERABLE = True
SECURITY_CHANGEABLE = True
SECURITY_RECOVERABLE = True

# Configure roles
SECURITY_ROLES_DEFINITIONS = {
    'User': 10,
    'Admin': 20
}
 