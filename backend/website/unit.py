from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from . import db
from .models import db,User, Balance,Unit,Transaction,Teller,Delinquency
import os
import re
from sqlalchemy import and_,or_
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
from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for, current_app
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
unit = Blueprint('unit', __name__)
cloudinary.config( 
  cloud_name = "dgkj964hl", 
  api_key = "365493184756366", 
  api_secret = "SzShIiVUv4Su4T1JY8Vx3jRXxD0" 
)
#unit
@unit.route('/unit', methods=['GET'])
def get_unit_from_qr_code():
    qr_code = request.args.get('qr_code')
    unit = Unit.query.filter_by(qrcode=qr_code).first()
    if unit:
        return jsonify({'unit': {'id': unit.id, 'unit_info': unit.unit_info}})
    else:
        return jsonify({'message': 'Unit not found'}), 404

@unit.route('/unit/<int:unit_id>/balances', methods=['GET'])
@jwt_required()
def get_unit_balances(unit_id):
    unit = Unit.query.get(unit_id)
    if not unit:
        return jsonify({'message': 'Unit not found'}), 404

    balances = Balance.query.filter_by(unit_id=unit_id).all()

    balances_data = []
    for balance in balances:
        balance_data = {
            'id': balance.id,
            'balance': balance.balance
        }
        balances_data.append(balance_data)

    return jsonify({'balances': balances_data}), 200
@unit.route('/units', methods=['GET'])
@jwt_required()
def get_all_units():
    units = Unit.query.all()

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


@unit.route('/unitpaid', methods=['GET'])
@jwt_required()
def get_all_unitpaid():
    # Get today's date
    today = date.today()

    # Query units with 'toll_payment' transactions for today
    units_with_payment = Unit.query.join(Transaction).filter(
        and_(
            Unit.id == Transaction.unit_id,
            or_(
            Transaction.type == 'TOLL_PAYMENT',
            Transaction.type == 'DELINQUENCY_PAYMENT'
        ),
            Transaction.date == today
        )
    ).all()

    # Initialize a dictionary to track units with toll_payment today
    units_dict = {}
    for unit in units_with_payment:
        units_dict[unit.id] = {
            'id': unit.id,
            'unit_info': unit.unit_info,
            'unit_type': unit.unit_type,
            'qrcode': unit.qrcode,
            'has_toll_payment_today': True,
            'has_delinquency_unpaid': False  # Initialize delinquency flag
        }

    # Query delinquency records with status 'unpaid' and date_of_payment matching today
    delinquency_unpaid_today = Delinquency.query.filter(
        and_(
            Delinquency.status == 'UNPAID',
            Delinquency.date_of_payment == today
        )
    ).all()

    # Track units with delinquency records for today
    for delinquency in delinquency_unpaid_today:
        unit_id = delinquency.unit_id
        # Check if the unit already exists in units_dict
        if unit_id in units_dict:
            units_dict[unit_id]['has_delinquency_unpaid'] = True
        else:
            # Add unit to units_dict if not already present
            unit = Unit.query.get(unit_id)
            units_dict[unit_id] = {
                'id': unit.id,
                'unit_info': unit.unit_info,
                'unit_type': unit.unit_type,
                'qrcode': unit.qrcode,
                'has_toll_payment_today': False,
                'has_delinquency_unpaid': True
            }

    # Query all units from the Unit table
    all_units = Unit.query.all()

    # Ensure all units are included in the response
    for unit in all_units:
        if unit.id not in units_dict:
            units_dict[unit.id] = {
                'id': unit.id,
                'unit_info': unit.unit_info,
                'unit_type': unit.unit_type,
                'qrcode': unit.qrcode,
                'has_toll_payment_today': False,
                'has_delinquency_unpaid': False
            }

    # Convert units_dict values to a list
    units_data = list(units_dict.values())

    # Return the JSON response with the list of units data
    return jsonify({'units': units_data}), 200


@unit.route('/paid', methods=['GET'])
@jwt_required()
def getpaid(unit_id):
    # Query transactions of type 'TOLL_PAYMENT' and 'DELINQUENCY_PAYMENT' for the given unit ID
    transactions = Transaction.query.filter(
        and_(
            Transaction.unit_id == unit_id,
            or_(
                Transaction.type == 'TOLL_PAYMENT',
                Transaction.type == 'DELINQUENCY_PAYMENT'
            )
        )
    ).all()

    # Prepare a list to store transaction data
    transactions_data = []
    
    # Process each transaction and extract relevant information
    for transaction in transactions:
        transaction_data = {
            'id': transaction.id,
            'type': transaction.type,
            'date': transaction.date,  # Transaction date
            'date_of_payment': transaction.date_of_payment,  # Date of payment
            'amount': transaction.amount,  # Add any other required transaction attributes
        }
        transactions_data.append(transaction_data)

    # Return the JSON response with the list of transactions data
    return jsonify({'transactions': transactions_data}), 200

@unit.route('/loginunit', methods=['POST'])
def loginunit():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Missing JSON data'}), 400

    unit = data.get('unit')
    password = data.get('password')

    unit = Unit.query.filter_by(unit_info=unit).first()
    if not unit or not check_password_hash(unit.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Generate access token
    account_type = 'unit'
    expires_in = timedelta(days=36500)
    access_token = create_access_token(identity=unit.id, expires_delta=expires_in)
    return jsonify({'access_token': access_token, 'accountType': account_type}), 200

@unit.route('/unitdetails', methods=['GET'])
@jwt_required()
def get_unit():
    unit_id = get_jwt_identity()
    unit = Unit.query.get(unit_id)
    if not unit:
        return jsonify({'message': 'unit not found'}), 404

    return jsonify({
        'id': unit.id,
        'unit_info': unit.unit_info,
        'unit_type':unit.unit_type,
        'qrcode':unit.qrcode,
        'picture':unit.picture
       
    }), 200 

@unit.route('/api/check-unit/motorela', methods=['GET'])
def check_unit_motorela():
    unit_type = 'motorela'
    unit_info = request.args.get('unit_info')

    # Assuming Unit is your SQLAlchemy model for the Unit table
    unit_exists = Unit.query.filter_by(unit_type=unit_type, unit_info=unit_info).first() is not None

    return jsonify({'exists': unit_exists})


@unit.route('/api/check-unit/multicab', methods=['GET'])
def check_unit_multicab():
    unit_type = 'multicab'
    unit_info = request.args.get('unit_info')

    # Assuming Unit is your SQLAlchemy model for the Unit table
    unit_exists = Unit.query.filter_by(unit_type=unit_type, unit_info=unit_info).first() is not None

    return jsonify({'exists': unit_exists})

@unit.route('/addunit', methods=['POST'])
@jwt_required()
def addunit():
    unit_info = request.form.get('unitinfo')
    unit_type = request.form.get('unittype')
    color = request.form.get('color')
    relapic = request.files['picture'] if 'picture' in request.files else None
    password1 = request.form.get('password1')
    password2 = request.form.get('password2')
    user_id = get_jwt_identity()

    if not re.match("^[a-zA-Z]+$", color):
        return jsonify({'error': 'Color can only contain alphanumeric characters'}), 400
    if not re.match("^[a-zA-Z0-9]([ -]?[a-zA-Z0-9])*$", unit_info):
        return jsonify({'error': 'Unit Information can only contain alphanumeric characters'}), 400
    # Check if passwords match and meet length requirement
    if password1 != password2:
        flash('Passwords don\'t match.', category='error')
        return jsonify({'message': 'Passwords don\'t match'}), 400
    
    # Convert unit_info to uppercase and filter out non-alphanumeric characters
    unit_info = ''.join(char.upper() for char in unit_info if char.isalnum())
    color = ''.join(char.lower() for char in color if char.isalnum())
    unit_type = ''.join(char.lower() for char in unit_type if char.isalnum())
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(unit_info)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Save QR code image
    qr_code_dir = os.path.join(current_app.root_path, 'static', 'qrcodes')
    os.makedirs(qr_code_dir, exist_ok=True)
    qr_code_filename = f'{unit_info}_qrcode.png'
    qr_code_path = os.path.join(qr_code_dir, qr_code_filename)
    img.save(qr_code_path)

    pic_dir = os.path.join(current_app.root_path, 'static', 'pictures')
    os.makedirs(pic_dir, exist_ok=True)
    pic_filename = f'{unit_info}_pic.png'
    pic_path = os.path.join(pic_dir, pic_filename)
    relapic.save(pic_path)

    # Upload QR code image to Cloudinary
    cloudinary_response = cloudinary.uploader.upload(qr_code_path, folder="qrcodes")
    cloudinary_url = cloudinary_response['secure_url']

    picture_response = cloudinary.uploader.upload(pic_path, folder="picture")
    picture_url = picture_response['secure_url']
    

    # Add new unit to the database with Cloudinary URLs
    new_unit = Unit(unit_info=unit_info, unit_type=unit_type, qrcode=cloudinary_url, color=color, user_id=user_id, password=generate_password_hash(password1, method='pbkdf2:sha256'), picture=picture_url)
    db.session.add(new_unit)
    db.session.commit()

    # Add new balance for the unit
    new_balance = Balance(balance=0, unit=new_unit)
    db.session.add(new_balance)
    db.session.commit()

    return jsonify({'message': 'Unit added successfully'}), 200






    
@unit.route('/check_unit/<unit_info>', methods=['GET'])
def check_unit(unit_info):
    unit = Unit.query.filter_by(unit_info=unit_info).first()
    if unit:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})  
    
@unit.route('/unit/<int:unit_id>/delinquencies', methods=['GET'])
@jwt_required()
def get_unit_delinquencies(unit_id):
    unit = Unit.query.get(unit_id)
    if not unit:
        return jsonify({'message': 'Unit not found'}), 404

    delinquencies = Delinquency.query.filter_by(unit_id=unit_id).all()

    delinquencies_data = []
    for delinquency in delinquencies:
        delinquency_data = {
           
            'date_of_payment': delinquency.date_of_payment,
            'status': delinquency.status.value
            
        }
        delinquencies_data.append(delinquency_data)
       
    return jsonify({'delinquencies': delinquencies_data}), 200



@unit.route('/unit/<int:unit_id>/transactions', methods=['GET'])
@jwt_required()
def get_unit_transactions(unit_id):
    unit = Unit.query.get(unit_id)
    if not unit:
        return jsonify({'message': 'Unit not found'}), 404

    # Filter transactions by unit_id and type (top-up or payment)
    transactions = Transaction.query.filter_by(unit_id=unit_id).all()

    transactions_data = []
    for transaction in transactions:
        teller = Teller.query.get(transaction.teller_id)
        teller_name = f"{teller.first_name} {teller.last_name}" if teller else "Kiosk"
        transaction_data = {
            'id': transaction.id,
            'amount': transaction.amount,
            'branch': transaction.branch,
            'reference_key':transaction.reference_key,
            'teller': teller_name,
            
            'date_of_payment': transaction.date_of_payment,
            'date':transaction.date,
            'type': transaction.type.value
        }
        transactions_data.append(transaction_data)

    return jsonify({'transactions': transactions_data}), 200

