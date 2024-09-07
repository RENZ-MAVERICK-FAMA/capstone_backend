from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from . import db
from .models import db,User, Balance,Unit,Transaction,Teller,Delinquency,InsertedCoins
import os
from sqlalchemy import join
import re
import uuid
import cloudinary
from sqlalchemy import and_
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
from flask import jsonify, request,has_request_context
from flask import send_from_directory
from sqlalchemy import or_
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
from datetime import timedelta  
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

teller= Blueprint('teller', __name__)
logger = logging.getLogger()  # Use __name__ for logger name
logger.setLevel(logging.INFO)

#teller
@teller.route('/addTeller', methods=['POST'])
def addTeller():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        address = request.form.get('address')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        teller = Teller.query.filter_by(username=username).first()
        if teller:
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
                # Create new user
                new_user = Teller(username=username, first_name=first_name, last_name=last_name,
                                address=address, password=generate_password_hash(password1, method='pbkdf2:sha256'),
                               )

                db.session.add(new_user)
                db.session.commit()

        return jsonify({'message': 'Account created successfully'}), 200

@teller.route('/Teller', methods=['GET'])
@jwt_required()
def get_Teller():
    Teller_id = get_jwt_identity()
    teller = Teller.query.get(Teller_id)
    if not teller:
        return jsonify({'message': 'User not found'}), 404

    return jsonify({
        'id': teller.id,
        'username': teller.username,
        'first_name': teller.first_name,
        'last_name': teller.last_name
    }), 200 

@teller.route('/topup', methods=['POST'])
@jwt_required()
def topup():
    frontend_url = request.headers.get('X-Frontend-URL', 'Unknown')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    request_method = request.method
  
    logger.info(f'Manual Top up successful! HTTP Request: {request_method} ')
    data = request.json
    amt = data.get('amount')
    unit_id = data.get('selectedUnit')
    branch = data.get('selectedBranch')
    teller_id = data.get('teller')
    teller = Teller.query.get(teller_id)
    unit_type = data.get('unit_type')
    current_app.logger.info(f'Frontend URL: {frontend_url}')
    current_app.logger.info(f'Client IP: {client_ip}')
    unit = Unit.query.get(unit_id)

    if not unit:
        return jsonify({'message': 'Unit not found!'}), 400

    balance_entry = Balance.query.filter_by(unit_id=unit_id).first()

    if not balance_entry:
        balance_entry = Balance(unit_id=unit_id, balance=0)

    balance_entry.balance += int(amt)
    reference_number = datetime.now().strftime('%Y%m%d%H%M%S') + '-' + str(uuid.uuid4().hex)[:6]
    transaction = Transaction(amount=int(amt), unit=unit, branch=branch, unit_type=unit_type, balance=balance_entry, type='TOPUP', teller=teller,reference_key=reference_number)

   
    
    db.session.add(balance_entry)
    db.session.add(transaction)
    db.session.commit()


    return jsonify({'message': 'Top up successful!'}), 200



@teller.route('/kiosktopup', methods=['POST'])
@jwt_required()
def kiosk_topup():
    frontend_url = request.headers.get('X-Frontend-URL', 'Unknown')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    request_method = request.method
    
    logger.info(f'Top up successful! HTTP Request: {request_method} ')
    data = request.json
    amt = data.get('amount')
    unit_id = data.get('selectedUnit')
    branch = data.get('selectedBranch')
    teller_id = data.get('teller')
    teller = Teller.query.get(teller_id)
    unit_type = data.get('unit_type')
    current_app.logger.info(f'Frontend URL: {frontend_url}')
    current_app.logger.info(f'Client IP: {client_ip}')
    unit = Unit.query.get(unit_id)

    if not unit:
        return jsonify({'message': 'Unit not found!'}), 400

    balance_entry = Balance.query.filter_by(unit_id=unit_id).first()

    if not balance_entry:
        balance_entry = Balance(unit_id=unit_id, balance=0)

    balance_entry.balance += int(amt)
    reference_number = datetime.now().strftime('%Y%m%d%H%M%S') + '-' + str(uuid.uuid4().hex)[:6]
    transaction = Transaction(amount=int(amt), unit=unit, branch=branch, unit_type=unit_type, balance=balance_entry, type='TOPUP', teller=teller,reference_key=reference_number)

    # Delete the InsertedCoins record
    inserted_coins = InsertedCoins.query.first()
    if inserted_coins:
        db.session.delete(inserted_coins)
    
    db.session.add(balance_entry)
    db.session.add(transaction)
    db.session.commit()


    return jsonify({'message': 'Top up successful!'}), 200

@teller.route('/paymentdel', methods=['POST'])
def paymentdel():
    frontend_url = request.headers.get('X-Frontend-URL', 'Unknown')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    request_method = request.method
  
    logger.info(f'Top up successful! HTTP Request: {request_method} ')
    data = request.json
    unit_id = data.get('unit_id')
    unit_type = data.get('unit_type')
    date = data.get('date')
    amt = data.get('amount')
    branch = data.get('selectedBranch')
    teller_id = data.get('teller')
    current_app.logger.info(f'Frontend URL: {frontend_url}')
    current_app.logger.info(f'Client IP: {client_ip}')
    unit = Unit.query.get(unit_id)
    teller = Teller.query.get(teller_id)

    if not unit:
        return jsonify({'message': 'Unit not found'}), 404

    payment_date_str = date
    if not payment_date_str:
        return jsonify({'error': 'Payment date is required'}), 400

    try:
        payment_date = datetime.strptime(payment_date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

    today = datetime.now().date()
    if payment_date > today:
        return jsonify({'error': 'Cannot process payment for future dates'}), 400

    balance_entry = Balance.query.filter_by(unit_id=unit_id).first()

    if not balance_entry:
        return jsonify({'error': 'No balance entry found'}), 404

    if balance_entry.balance < amt:
        existing_delinquency = Delinquency.query.filter_by(unit_id=unit_id, date_of_payment=payment_date).first()
        if existing_delinquency:
            return jsonify({'message': 'Already Have a Record '}), 200
        else:
            # Create a new delinquency entry
            delinquency = Delinquency(unit_id=unit_id, date_of_payment=payment_date,unit_type=unit_type,status='unpaid')
            db.session.add(delinquency)
            db.session.commit()
            return jsonify({'message': 'Insufficient Balance, Added as a Delinquency'}), 200
    else:
        # Check if a transaction for this date has already been processed
        existing_transaction = Transaction.query.filter_by(unit_id=unit_id, date=payment_date).filter(
            or_(
                Transaction.type == 'TOLL_PAYMENT',
                Transaction.type == 'DELINQUENCY_PAYMENT'
            )
        ).first()
        if existing_transaction:
            return jsonify({'error': f'Payment already made and cannot be changed'}), 400

        delinquency_to_update = Delinquency.query.filter_by(unit_id=unit_id, date_of_payment=payment_date, status='unpaid').first()
        if delinquency_to_update:
            delinquency_to_update.status = 'paid'
            delinquency_to_update.type = 'delpayment'
            db.session.commit()
            transaction_type = 'DELINQUENCY_PAYMENT'  
            message = 'Payment Successful with Delinquency'
        else:
            transaction_type = 'TOLL_PAYMENT' 
            message = 'Payment Successful'

        balance_entry.balance -= amt
        reference_number = datetime.now().strftime('%Y%m%d%H%M%S') + '-' + str(uuid.uuid4().hex)[:6]

        transaction = Transaction(amount=amt, unit_id=unit_id, unit_type=unit_type, balance_id=balance_entry.id, type=transaction_type, date=payment_date, branch=branch, teller=teller,reference_key =reference_number)
        db.session.add(transaction)
        db.session.commit()

        return jsonify({'message': message}), 200

@teller.route('/deduct', methods=['POST'])
def deduct():
    frontend_url = request.headers.get('X-Frontend-URL', 'Unknown')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    request_method = request.method

    logger.info(f'Top up successful! HTTP Request: {request_method} ')
    data = request.json
    unit_id = data.get('unit_id')
    unit_type = data.get('unit_type')
    date = data.get('date')
    amt = data.get('amount')
    branch = data.get('selectedBranch')
    teller_id = data.get('teller')
    current_app.logger.info(f'Frontend URL: {frontend_url}')
    current_app.logger.info(f'Client IP: {client_ip}')
    unit = Unit.query.get(unit_id)
    teller = Teller.query.get(teller_id)

    if not unit:
        return jsonify({'message': 'Unit not found'}), 404

    payment_date_str = date
    if not payment_date_str:
        return jsonify({'error': 'Payment date is required'}), 400

    try:
        payment_date = datetime.strptime(payment_date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

    today = datetime.now().date()
    if payment_date > today:
        return jsonify({'error': 'Cannot process payment for future dates'}), 400

    balance_entry = Balance.query.filter_by(unit_id=unit_id).first()

    if not balance_entry:
        return jsonify({'error': 'No balance entry found'}), 404

    if balance_entry.balance < amt:
        existing_delinquency = Delinquency.query.filter_by(unit_id=unit_id, date_of_payment=payment_date).first()
        if existing_delinquency:
            return jsonify({'message': 'Already Have a Record '}), 200
        else:
            # Create a new delinquency entry
            delinquency = Delinquency(unit_id=unit_id, date_of_payment=payment_date,unit_type=unit_type,status='unpaid')
            db.session.add(delinquency)
            db.session.commit()
            return jsonify({'message': 'Insufficient Balance, Added as a Delinquency'}), 200
    else:
        # Check if a transaction for this date has already been processed
        existing_transaction = Transaction.query.filter_by(unit_id=unit_id, date=payment_date).filter(
            or_(
                Transaction.type == 'TOLL_PAYMENT',
                Transaction.type == 'DELINQUENCY_PAYMENT'
            )
        ).first()
        if existing_transaction:
            return jsonify({'error': f'Payment already made and cannot be changed'}), 400

        delinquency_to_update = Delinquency.query.filter_by(unit_id=unit_id, date_of_payment=payment_date, status='unpaid').first()
        if delinquency_to_update:
            delinquency_to_update.status = 'paid'
            delinquency_to_update.type = 'delpayment'
            db.session.commit()
            transaction_type = 'DELINQUENCY_PAYMENT'  
            message = 'Payment Successful with Delinquency'
        else:
            transaction_type = 'TOLL_PAYMENT' 
            message = 'Payment Successful'

        balance_entry.balance -= amt
        reference_number = datetime.now().strftime('%Y%m%d%H%M%S') + '-' + str(uuid.uuid4().hex)[:6]

        transaction = Transaction(amount=amt, unit_id=unit_id, unit_type=unit_type, balance_id=balance_entry.id, type=transaction_type, date=payment_date, branch=branch, teller=teller,reference_key =reference_number)
        db.session.add(transaction)
        db.session.commit()

        return jsonify({'message': message}), 200


@teller.route('/manualpay', methods=['POST'])
def manual_pay():
    frontend_url = request.headers.get('X-Frontend-URL', 'Unknown')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    request_method = request.method
    
    logger.info(f'Top up successful! HTTP Request: {request_method} ')
    data = request.json
    unit_id = data.get('unit_id')
    unit_type = data.get('unit_type')
    date = data.get('date')
    amt = data.get('amount')
    branch = data.get('selectedBranch')
    teller_id = data.get('teller')
    current_app.logger.info(f'Frontend URL: {frontend_url}')
    current_app.logger.info(f'Client IP: {client_ip}')
    unit = Unit.query.get(unit_id)
    teller = Teller.query.get(teller_id)

    if not unit:
        return jsonify({'message': 'Unit not found'}), 404

    payment_date_str = date
    if not payment_date_str:
        return jsonify({'error': 'Payment date is required'}), 400

    try:
        payment_date = datetime.strptime(payment_date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

    today = datetime.now().date()
    if payment_date > today:
        return jsonify({'error': 'Cannot process payment for future dates'}), 400

    balance_entry = Balance.query.filter_by(unit_id=unit_id).first()
    if unit_type == 'motorela':
       topup = 6
    elif unit_type == 'multicab':
        topup = 11

    balance_entry.balance += topup   
   
    if not balance_entry:
        return jsonify({'error': 'No balance entry found'}), 404

    if balance_entry.balance < amt:
        existing_delinquency = Delinquency.query.filter_by(unit_id=unit_id, date_of_payment=payment_date).first()
        if existing_delinquency:
            return jsonify({'message': 'Already Have a Record of Delinquency'}), 200
        else:
            # Create a new delinquency entry
            return jsonify({'message': 'Insufficient Balance, Added as a Delinquency'}), 200
    else:    
        delinquency_to_update = Delinquency.query.filter_by(unit_id=unit_id, date_of_payment=payment_date, status='unpaid').first()
        if delinquency_to_update:
            delinquency_to_update.status = 'paid'
            delinquency_to_update.type = 'delpayment'
            db.session.commit()
            transaction_type = 'DELINQUENCY_PAYMENT'  
            message = 'Payment Successful with Delinquency'
        else:
            transaction_type = 'TOLL_PAYMENT' 
            message = 'Payment Successful'

        existing_transaction = Transaction.query.filter_by(unit_id=unit_id, date=payment_date).filter(
            or_(
                Transaction.type == 'TOLL_PAYMENT',
                Transaction.type == 'DELINQUENCY_PAYMENT'
            )
        ).first()
        if existing_transaction:
            return jsonify({'error': f'Payment already made and cannot be changed'}), 400

        delinquency_to_update = Delinquency.query.filter_by(unit_id=unit_id, date_of_payment=payment_date, status='unpaid').first()
        if delinquency_to_update:
            delinquency_to_update.status = 'paid'
            delinquency_to_update.type = 'delpayment'
            db.session.commit()
            transaction_type = 'DELINQUENCY_PAYMENT'  
            message = 'Payment Successful with Delinquency'
        else:
            transaction_type = 'TOLL_PAYMENT' 
            message = 'Payment Successful'

        balance_entry.balance -= amt
        reference_number = datetime.now().strftime('%Y%m%d%H%M%S') + '-' + str(uuid.uuid4().hex)[:6]

        transaction = Transaction(amount=amt, unit_id=unit_id, unit_type=unit_type, balance_id=balance_entry.id, type=transaction_type, date=payment_date, branch=branch, teller=teller,reference_key =reference_number)
        db.session.add(transaction)
        db.session.commit()

        return jsonify({'message': message}), 200



    
@teller.route('/check_unit/<username>', methods=['GET'])
def check_operator(username):
    teller = Teller.query.filter_by(username=username).first()
    if teller:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})       

@teller.route('/loginTeller', methods=['POST'])
def loginTeller():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Missing JSON data'}), 400

    username = data.get('username')
    password = data.get('password')

    teller = Teller.query.filter_by(username=username).first()
    if not teller or not check_password_hash(teller.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Generate access token
    account_type = 'teller'
    expires_in = timedelta(days=36500)
    access_token = create_access_token(identity=teller.id, expires_delta=expires_in)
   
    return jsonify({'access_token': access_token, 'accountType': account_type,}), 200


@teller.route('/delinquencies/motorela', methods=['GET'])
def get_motorela_delinquencies():
    # Query motorela delinquencies from the database
    delinquencies = Delinquency.query.filter_by(unit_type='motorela').all()

    # Prepare the response data
    delinquency_list = []
    for delinquency in delinquencies:
        delinquency_list.append({
            'id': delinquency.id,
            'unit_id': delinquency.unit_id,
            'date_of_payment': delinquency.date_of_payment.strftime('%Y-%m-%d')  # Format date as string
            # Add more fields as needed
        })

    # Return the delinquency data as JSON
    return jsonify({'delinquencies': delinquency_list}), 200


@teller.route('/delinquencies/multicab', methods=['GET'])
def get_multicab_delinquencies():
    # Query motorela delinquencies from the database
    delinquencies = Delinquency.query.filter_by(unit_type='multicab').all()

    # Prepare the response data
    delinquency_list = []
    for delinquency in delinquencies:
        delinquency_list.append({
            'id': delinquency.id,
            'unit_id': delinquency.unit_id,
            'date_of_payment': delinquency.date_of_payment.strftime('%Y-%m-%d')  # Format date as string
            # Add more fields as needed
        })

    # Return the delinquency data as JSON
    return jsonify({'delinquencies': delinquency_list}), 200




@teller.route('/inserted_coins', methods=['GET'])
def get_inserted_coins():
    inserted_coins = InsertedCoins.query.order_by(InsertedCoins.id.desc()).first()
    if inserted_coins:
        return jsonify({'inserted_coins': inserted_coins.inserted_coins})
    return jsonify({'inserted_coins': 0})

from sqlalchemy import desc

@teller.route('/payment-details', methods=['GET'])
def get_unit_details():
    unit_info = request.args.get('unit_info')

    unit = Unit.query.filter_by(unit_info=unit_info).first()

    if not unit:
        return jsonify({'error': 'Unit not found'}), 404

    # Fetch delinquencies
    delinquencies = (
    Delinquency.query
    .filter_by(unit_id=unit.id)  # Filter delinquencies by unit_id
    .order_by(desc(Delinquency.date_of_payment))  # Order delinquencies by date_of_payment descending
    .limit(7)  # Limit to the latest 7 delinquencies
    .all()  # Execute the query and fetch all results
)

    # Fetch transactions
    transaction_types = ['TOLL_PAYMENT', 'DELINQUENCY_PAYMENT']

    transactions = (
    Transaction.query
    .filter(
        Transaction.unit_id == unit.id,  # Filter transactions by unit_id
        Transaction.type.in_(transaction_types)  # Filter transactions by specified types
    )
    .order_by(desc(Transaction.date_of_payment))  # Order transactions by date_of_payment descending
    .limit(7)  # Limit to the latest 7 transactions
    .all()  # Execute the query and fetch all results
)

    # Fetch balance
    balance = Balance.query.filter_by(unit_id=unit.id).first()

    unit_details = {
        'unit_info': unit.unit_info,
        'unit_type': unit.unit_type,
        'picture':unit.picture,
        'delinquencies': [{
            'id': delinquency.id,
            'date_of_payment': delinquency.date_of_payment,
            'status':delinquency.status.value
        } for delinquency in delinquencies],
        'transactions': [{
            'id': transaction.id,
            'amount': transaction.amount,
            'date_of_payment': transaction.date_of_payment,
            'type': transaction.type.value
        } for transaction in transactions],
        'balance': balance.balance if balance else 0
    }
    print(unit_details)
    return jsonify(unit_details)
