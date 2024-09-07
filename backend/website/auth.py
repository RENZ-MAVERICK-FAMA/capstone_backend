from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from . import db
from .models import db,User, Balance,Unit,Transaction,Teller,Delinquency,Kiosk,Admin,SuperAdmin
import os
from flask import session,send_file
import re
import cloudinary
import cloudinary.uploader
from io import BytesIO
from PIL import Image
import qrcode
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_mail import Message, Mail
from itsdangerous import Serializer,BadSignature, SignatureExpired
import re
from re import match
from flask_jwt_extended import get_jwt_identity, unset_jwt_cookies
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError
from flask import jsonify, request
from flask import send_from_directory

from datetime import datetime, date, timedelta
import json
from calendar import monthcalendar, THURSDAY
from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for, current_app,has_request_context
from flask_login import login_required, current_user
from .models import User, Balance, Transaction, Unit
from . import db
from datetime import datetime, date, timedelta
import json
from calendar import monthcalendar, THURSDAY

import calendar
from sqlalchemy import extract
from datetime import datetime, date
from calendar import monthcalendar
from sqlalchemy.exc import SQLAlchemyError
import os
from flask_wtf import csrf
from flask_wtf.csrf import generate_csrf
import qrcode
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import get_jwt_identity, unset_jwt_cookies
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError
import calendar
from sqlalchemy import extract
from datetime import datetime, date
from calendar import monthcalendar
import logging
from logging.handlers import RotatingFileHandler
from werkzeug.local import LocalProxy
import signal
import sys
from werkzeug.wrappers import Request
auth = Blueprint('auth', __name__)
logger = logging.getLogger() 
logger.setLevel(logging.INFO)
 # Use __name__ for logger name
STATUS_CODE_DESCRIPTIONS = {
    100: "Continue",
    101: "Switching Protocols",
    200: "Success",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    300: "Multiple Choices",
    301: "Moved Permanently",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized/Unauthenticated",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    422: "Unprocessable Entity",
    500: "Internal Server Error",
    501: "Not Implemented",
    503: "Service Unavailable",
}

class CustomFormatter(logging.Formatter):
    def format(self, record):
        if isinstance(record.args, tuple):
            request = record.args[0]
            if isinstance(request, Request):
                record.url = request.url
                record.remote = request.remote_addr
            else:
                record.url = "None"
                record.remote = "None"

        # Extract status code from log message
        log_message = record.getMessage()
        parts = log_message.split()
        if len(parts) > 1:
            status_code_str = parts[-2]  # Second-to-last part should be the status code
            try:
                status_code = int(status_code_str)
                status_description = STATUS_CODE_DESCRIPTIONS.get(status_code, 'Unknown')
                record.status_info = f"{status_code} - \"{status_description}\""
            except ValueError:
                record.status_info = "Unknown"
        else:
            record.status_info = "Unknown"

        return super().format(record)



logFormatter = CustomFormatter(fmt="%(message)s - %(url)s - %(remote)s - %(levelname)s   - %(status_info)s", datefmt="%Y-%m-%d %H:%M:%S")

# Console handler
consoleHandler = logging.StreamHandler(sys.stdout)
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)

# File handler (RotatingFileHandler for log rotation)
fileHandler = RotatingFileHandler("logs.log")
fileHandler.setFormatter(logFormatter)
logger.addHandler(fileHandler)

# Graceful shutdown handler
def shutdown_handler(signum, frame):
    logger.info("Shutting down...")
    fileHandler.close()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)
cloudinary.config( 
  cloud_name = "dgkj964hl", 
  api_key = "365493184756366", 
  api_secret = "SzShIiVUv4Su4T1JY8Vx3jRXxD0" 
)

mail = Mail

@auth.route('/download-logs')
def download_logs():
    try:
        # Send logs.log file as attachment
        return send_file("logs.log", as_attachment=True)
    except Exception as e:
        return str(e), 500

def get_updated_balance(unit_id):
    # Query the Balance model for the specified unit_id and get the latest balance
    balance = Balance.query.filter_by(unit_id=unit_id).order_by(Balance.id.desc()).first()
    if balance:
        return balance.balance
    else:
        return None
    
@auth.route('/delinquencies/today', methods=['GET'])
def get_delinquencies_for_today():
    today = date.today().isoformat()
    delinquencies = Delinquency.query.filter_by(date_of_payment=today).all()
    delinquencies_data = [{'id': delinquency.id, 'date_of_payment': delinquency.date_of_payment, 'unit_id': delinquency.unit_id} for delinquency in delinquencies]
    return jsonify({'delinquencies': delinquencies_data})


@auth.route('/logged_in_count', methods=['GET'])
def logged_in_count():
    count = sum(1 for key in session.keys() if key.startswith('logged_in_'))
    return jsonify({'count': count}), 200

@auth.route('/logout', methods=['POST'])
def logout():
    # Get the user_info from the session
    user_info = session.get('user_info')

    return jsonify({'message': 'Logged out successfully'}), 200
   


@auth.route('/transactions', methods=['GET'])
def get_all_transactions():
    transactions = Transaction.query.all()
    transaction_list = []
    for transaction in transactions:
        transaction_list.append({
            'id': transaction.id,
            'amount': transaction.amount,
            'date': transaction.date,
            'branch': transaction.branch,
            'date_of_payment': transaction.date_of_payment,
            'type': transaction.type.value  
        })
    return jsonify({'transactions': transaction_list})



@auth.route('/loginkiosk', methods=['POST'])
def loginkiosk():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Missing JSON data'}), 400

    username = data.get('username')
    password = data.get('password')

    kiosk = Kiosk.query.filter_by(username=username).first()
    if not kiosk or not check_password_hash(kiosk.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Generate access token
    account_type = 'kiosk'
    expires_in = timedelta(days=36500)
    access_token = create_access_token(identity=kiosk.id, expires_delta=expires_in)
    return jsonify({'access_token': access_token, 'accountType': account_type}), 200


@auth.route('/addkiosk', methods=['POST'])
def addkiosk():
    if request.method == 'POST':
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        # Validate form data
        if not username or not password1 or not password2:
            return jsonify({'message': 'Incomplete form data'}), 400

        kiosk = Kiosk.query.filter_by(username=username).first()
        if kiosk:
            return jsonify({'message': 'Username already exists'}), 400
        elif password1 != password2:
            return jsonify({'message': 'Passwords do not match'}), 400
        elif len(password1) < 2:
            return jsonify({'message': 'Password must be at least 7 characters'}), 400

        try:
            # Create new user
            new_user = Kiosk(username=username, password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'Account created successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': str(e)}), 500
    else:
        return jsonify({'message': 'Method not allowed'}), 405

    
@auth.route('/recent_topup_transactions')
def get_recent_topup_transactions():
    transactions = Transaction.query.filter_by(type="TOPUP").order_by(Transaction.id.desc()).limit(10).all()


    transactions_data = []
    for transaction in transactions:
        unit_id = transaction.unit_id
        unit_info = None
        if unit_id:
            unit = Unit.query.get(unit_id)
            if unit:
                unit_info = unit.unit_info
        transaction_data = {
            'id':transaction.id,
            'unitid': unit_info,
            'amount': transaction.amount,
            'date': transaction.date_of_payment,
            'reference': transaction.reference_key
        }
        transactions_data.append(transaction_data)

    return jsonify({'transactions': transactions_data}), 200


from sqlalchemy import or_



@auth.route('/loginall', methods=['POST'])
def loginall():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Missing JSON data'}), 400

    username = data.get('username')
    password = data.get('password')

    # Check if username exists in any of the tables
    user_query = User.query.filter_by(email=username)
    unit_query = Unit.query.filter_by(unit_info=username)
    teller_query = Teller.query.filter_by(username=username)
    admin_query = Admin.query.filter_by(username=username)
    super_query = SuperAdmin.query.filter_by(username=username)
    kiosk_query = Kiosk.query.filter_by(username=username)

    user = user_query.first()
    unit = unit_query.first()
    teller= teller_query.first()
    admin = admin_query.first()
    super = super_query.first()
    kiosk = kiosk_query.first()

    if not (user or unit or teller or admin or super or kiosk):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Check password and determine account type
    if user and check_password_hash(user.password, password):
        account_type = 'operator'
        user_id = user.id
        expires_in = timedelta(hours=1) 
        user_info = {
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'account_type':account_type,
        'ip_address': request.remote_addr,
        
        
    }
    elif unit and check_password_hash(unit.password, password):
        account_type = 'unit'
        user_id = unit.id
        expires_in = timedelta(minutes = 30) 
        user_info = {
        
        'unit_info': unit.unit_info,
        'account_type':account_type,
        'ip_address': request.remote_addr
    }
    elif teller and check_password_hash(teller.password, password):
        account_type = 'teller'
        user_id = teller.id
        expires_in = timedelta(hours=8) 
        user_info = {
      
        'username': teller.username,
        'first_name': teller.first_name,
        'last_name': teller.last_name,
        'account_type':account_type,
        'ip_address': request.remote_addr
    }
    elif admin and check_password_hash(admin.password, password):
        account_type = 'admin'
        user_id = admin.id
        expires_in = timedelta(days=36500)
        user_info = {
        'id': admin.id,
        'username': admin.username,
        'first_name': admin.first_name,
        'last_name': admin.last_name,
        'account_type':account_type,
        'ip_address': request.remote_addr
    }
    elif super and check_password_hash(super.password, password):
        account_type = 'SuperAdmin'
        user_id = super.id
        expires_in = timedelta(days=36500)
        user_info = {
        'id': super.id,
        'username': super.username,
        'account_type':account_type,
        'ip_address': request.remote_addr
    }
    elif kiosk and check_password_hash(kiosk.password, password):
        account_type = 'kiosk'
        user_id = kiosk.id
        expires_in = timedelta(days=36500)
        user_info = {
        'id': kiosk.id,
        'username': kiosk.username,
        'account_type':account_type,
        'ip_address': request.remote_addr
    }
    else:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    logger.info(f'Login for user: {username} from IP: {request.remote_addr} success' )
  
    access_token = create_access_token(identity=user_id, expires_delta=expires_in)
  
    return jsonify({'access_token': access_token, 'accountType': account_type, 'user_info': user_info}), 200

    


@auth.route('/addSuperAdmin', methods=['POST'])
def addSuperAdmin():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        address = request.form.get('address')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        admin = SuperAdmin.query.filter_by(username=username).first()
        if admin:
                flash('username already exists.', category='error')
        elif len(first_name) < 2:
                flash('First name must be greater than 1 character.', category='error')
        elif len(last_name) < 2:
                flash('Last name must be greater than 1 character.', category='error')
        elif len(address) < 2:
                flash('Address must be greater than 1 character.', category='error')
        elif password1 != password2:
                flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
                flash('Password must be at least 7 characters.', category='error')
        else:
               
                address = ''.join(char.lower() for char in address if char.isalnum())
                
                new_user = SuperAdmin(username=username, first_name=first_name, last_name=last_name,
                                address=address, password=generate_password_hash(password1, method='pbkdf2:sha256'),
                               )

                db.session.add(new_user)
                db.session.commit()

        return jsonify({'message': 'Account created successfully'}), 200
    
@auth.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    users_list = []
    for users in users:
        users_list.append({
            'id':users.id,
            'username': users.email,
            'first_name': users.first_name,
            'last_name': users.last_name,
            'address1': users.address,
            'password': users.password
          
        })
    return jsonify({'users': users_list})

@auth.route('/units', methods=['GET'])
def get_all_units():
    units = Unit.query.all()
    units_list = []
    for unit in units:  
       units_list.append({
            'id': unit.id,
            'unit_info': unit.unit_info,
            'unit_type': unit.unit_type,
            'color': unit.color,
            'password1':unit.password
            
          
        })
    return jsonify({'units': units_list})


@auth.route('/tellers', methods=['GET'])
def get_all_tellers():
    teller = Teller.query.all()
    teller_list = []
    for teller in teller:
        teller_list.append({
            'id':teller.id,
            'username': teller.username,
            'first_name': teller.first_name,
            'last_name': teller.last_name,
            'address1': teller.address,
            'password1': teller.password
          
        })
    return jsonify({'teller': teller_list})

@auth.route('/admins', methods=['GET'])
def get_all_admins():
    admins = Admin.query.all()
    admins_list = []
    for admins in admins:
        admins_list.append({
            'id':admins.id,
            'username': admins.username,
            'first_name': admins.first_name,
            'last_name': admins.last_name,
            'address1': admins.address,
            'password1': admins.password
          
        })
    return jsonify({'admins': admins_list})


@auth.route('/updateTeller/<int:id>', methods=['PUT'])
def update_teller(id):
    data = request.get_json()

    if not data:
        return jsonify({'message': 'No data provided in the request'}), 400

    try:
        teller = Teller.query.get(id)  

        if not teller:
            return jsonify({'message': f'Teller with ID {id} not found'}), 404

       
        if 'username' in data:
            teller.username = data['username']
        if 'firstName' in data:
            teller.first_name = data['firstName']
        if 'lastName' in data:
            teller.last_name = data['lastName']
        if 'address' in data:
            teller.address = data['address']
        if 'password' in data:
            new_password = data['password']
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            teller.password = hashed_password   

        db.session.commit() 

        return jsonify({'message': 'Teller updated successfully'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500
    
@auth.route('/updateAdmin/<int:id>', methods=['PUT'])
def update_admin(id):
    data = request.get_json()

    if not data:
        return jsonify({'message': 'No data provided in the request'}), 400

    try:
        admin = Admin.query.get(id)  

        if not admin:
            return jsonify({'message': f'admin with ID {id} not found'}), 404

        if 'username' in data:
            admin.username = data['username']
        if 'firstName' in data:
            admin.first_name = data['firstName']
        if 'lastName' in data:
            admin.last_name = data['lastName']
        if 'address' in data:
            admin.address = data['address']
        if 'password' in data:
            new_password = data['password']
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            admin.password = hashed_password   

        db.session.commit() 

        return jsonify({'message': 'admin updated successfully'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500
    
@auth.route('/updateOperator/<int:id>', methods=['PUT'])
def update_operator(id):
    data = request.get_json()

    if not data:
        return jsonify({'message': 'No data provided in the request'}), 400

    try:
        admin = User.query.get(id)  

        if not admin:
            return jsonify({'message': f'admin with ID {id} not found'}), 404

   
        if 'username' in data:
            admin.username = data['username']
        if 'firstName' in data:
            admin.first_name = data['firstName']
        if 'lastName' in data:
            admin.last_name = data['lastName']
        if 'address' in data:
            admin.address = data['address']
        if 'password' in data:
            new_password = data['password']
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            admin.password = hashed_password   

        db.session.commit()  

        return jsonify({'message': 'admin updated successfully'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500