from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from . import db
from .models import db,User, Balance,Unit,Transaction,Teller,Delinquency
import os
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
operator = Blueprint('operator', __name__)


cloudinary.config( 
  cloud_name = "dgkj964hl", 
  api_key = "365493184756366", 
  api_secret = "SzShIiVUv4Su4T1JY8Vx3jRXxD0" 
)
#user
@operator.route('/user_units', methods=['GET'])
@jwt_required()
def get_user_units():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()

    # Query the database for units belonging to the current user
    units = Unit.query.filter_by(user_id=current_user_id).all()

    # Create a list of unit data to return
    units_data = []
    for unit in units:
        unit_data = {
            'id': unit.id,
            'unit_info': unit.unit_info,
            'unit_type': unit.unit_type,
            'qrcode': unit.qrcode,
            'color': unit.color,
            'picture': unit.picture
        }
        units_data.append(unit_data)

    return jsonify({'units': units_data}), 200

@operator.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    frontend_url = request.headers.get('X-Frontend-URL', 'Unknown')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    current_app.logger.info(f'Frontend URL: {frontend_url}')
    current_app.logger.info(f'Client IP: {client_ip}')
    user_data = {
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'permit': user.permit,
        'address': user.address,
        'license': user.license,
        'frontend_url': frontend_url,
        'client_ip': client_ip
    }
    return jsonify(user_data), 200 

@operator.route('/check_email/<email>', methods=['GET'])
def check_email(email):
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})
    
@operator.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Missing JSON data'}), 400

    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Generate access token
    account_type = 'operator'
    expires_in = timedelta(days=36500)
    access_token = create_access_token(identity=user.id, expires_delta=expires_in)
    return jsonify({'access_token': access_token, 'accountType': account_type}), 200

@operator.route('/signup', methods=['POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        address = request.form.get('address')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        license = request.form.get('license')
        permit = request.files['permit'] if 'permit' in request.files else None

        # Validate email format
        address = ''.join(char.lower() for char in address if char.isalnum())
        user = User.query.filter_by(email=email).first()
        if user:
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
                if permit:
                    permit_filename = secure_filename(email + '.png')
                    permit_path = os.path.join(current_app.root_path, 'static', 'permit', permit_filename)
                    os.makedirs(os.path.dirname(permit_path), exist_ok=True)
                    permit.save(permit_path)
                else:
                    permit_filename = 'default_permit.png'  # Set a default permit filename if no permit is provided
                cloudinary_response = cloudinary.uploader.upload(permit_path, folder="permits")
                cloudinary_url = cloudinary_response['secure_url']
                # Create new user
                new_user = User(email=email, first_name=first_name, last_name=last_name,
                                address=address, password=generate_password_hash(password1, method='pbkdf2:sha256'),
                                license=license, permit=cloudinary_url)

                db.session.add(new_user)
                db.session.commit()

    return jsonify({'message': 'Account created successfully'}), 200
@operator.route('/updateuser', methods=['PUT'])
def update_user():
    # Check if user is logged in
    access_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not access_token:
        return jsonify({'message': 'Unauthorized access'}), 401
    
    # Validate the access token (you may need to implement this)
   

    # Get user data from request
    user_data = request.form
    email = user_data.get('email')
    first_name = user_data.get('first_name')
    last_name = user_data.get('last_name')
    address = user_data.get('address')
    license = user_data.get('license')
    password = user_data.get('password')
    permit = request.files.get('permit')

    # Update user information in the database
    # Assuming you have a User model with these attributes
    user = User.query.filter_by(email=email).first()
    if user:
        user.first_name = first_name
        user.last_name = last_name
        user.address = address
        user.license = license
        if password:
            user.set_password(password)  # Assuming set_password hashes the password
        if permit:
            # Handle permit file upload
            if user.permit:
                # Remove existing permit file
                existing_permit_path = os.path.join(current_app.root_path, 'static', 'permit', user.permit)
                if os.path.exists(existing_permit_path):
                    os.remove(existing_permit_path)

            # Save new permit file
            permit_filename = secure_filename(user.email + '_permit.png')  # Unique filename
            permit_path = os.path.join(current_app.root_path, 'static', 'permit', permit_filename)
            permit.save(permit_path)
            user.permit = permit_filename

        db.session.commit()
        return jsonify({'message': 'User updated successfully'}), 200
    else:
        return jsonify({'message': 'User not found'}), 404
    

@operator.route('/operator/analytics', methods=['GET'])
@jwt_required()
def get_operator_analytics():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not authenticated'}), 401

    motorela_count = Unit.query.filter_by(user_id=user_id, unit_type='motorela').count()
    multicab_count = Unit.query.filter_by(user_id=user_id, unit_type='multicab').count()

    return jsonify({
        'motorelaCount': motorela_count,
        'multicabCount': multicab_count
    })
@operator.route('/operator/paid_units_today', methods=['GET'])
@jwt_required()
def get_paid_units_today():
    user_id = get_jwt_identity()

    # Get the date for today
    today_date = datetime.now().date()

    # Count the number of motorela and multicab units owned by the user that have been paid for today
    motorela_paid_count = Transaction.query \
        .join(Unit, Unit.id == Transaction.unit_id) \
        .filter(Unit.user_id == user_id, Unit.unit_type == 'motorela', Transaction.date_of_payment == today_date,Transaction.type == 'TOLL_PAYMENT') \
        .count()

    multicab_paid_count = Transaction.query \
        .join(Unit, Unit.id == Transaction.unit_id) \
        .filter(Unit.user_id == user_id, Unit.unit_type == 'multicab', Transaction.date_of_payment == today_date,Transaction.type == 'TOLL_PAYMENT') \
        .count()

    return jsonify({
        'motorelaPaidCount': motorela_paid_count,
        'multicabPaidCount': multicab_paid_count
    })


@operator.route('/operator/delinquent_units_today', methods=['GET'])
@jwt_required()
def get_delinquent_units_today():
    user_id = get_jwt_identity()

    # Get the date for today
    today_date = datetime.now().date()

    # Count the number of motorela and multicab units owned by the user that have been paid for today
    motorela_del_count = Delinquency.query \
        .join(Unit, Unit.id == Delinquency.unit_id) \
        .filter(Unit.user_id == user_id, Unit.unit_type == 'motorela',Delinquency.date_of_payment == today_date,Delinquency.status == 'UNPAID') \
        .count()

    multicab_del_count = Delinquency.query \
        .join(Unit, Unit.id == Delinquency.unit_id) \
        .filter(Unit.user_id == user_id, Unit.unit_type == 'multicab', Delinquency.date_of_payment == today_date,Delinquency.status == 'UNPAID') \
        .count()

    return jsonify({
        'motoreladelCount': motorela_del_count,
        'multicabdelCount': multicab_del_count
    })
