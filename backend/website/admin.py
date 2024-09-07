from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from . import db
from .models import db,User, Balance,Unit,Transaction,Teller,Delinquency,Admin
import os
from sqlalchemy import extract
import re
from calendar import monthrange
from sqlalchemy import func,or_
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
admin = Blueprint('admin', __name__)

          
cloudinary.config( 
  cloud_name = "dgkj964hl", 
  api_key = "365493184756366", 
  api_secret = "SzShIiVUv4Su4T1JY8Vx3jRXxD0" 
)

@admin.route('/loginAdmin', methods=['POST'])
def loginAdmin():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Missing JSON data'}), 400

    username = data.get('username')
    password = data.get('password')

    admin = Admin.query.filter_by(username=username).first()
    if not admin or not check_password_hash(admin.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Generate access token
    account_type = 'admin'
    access_token = create_access_token(identity=admin.id)
    return jsonify({'access_token': access_token, 'accountType': account_type}), 200



@admin.route('/admin/delinquencies/motorela/daily', methods=['GET'])
def get_motorela_delinquencies_daily():
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    delinquency_list = []

    start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date() if start_date_str else datetime.now().date()
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if end_date_str else datetime.now().date()

    delinquencies = Delinquency.query.filter(Delinquency.unit_type == 'motorela', Delinquency.date_of_payment.between(start_date, end_date)).all()

    for delinquency in delinquencies:
        delinquency_list.append({
            'id': delinquency.id,
            'unit_id': delinquency.unit.unit_info,
            'date_of_payment': delinquency.date_of_payment.strftime('%Y-%m-%d'),
            'status': delinquency.status.value
            # Add more fields as needed
        })

    return jsonify({'delinquencies': delinquency_list}), 200





@admin.route('/admin/delinquencies/multicab/daily', methods=['GET'])
def get_multicab_delinquencies_daily():
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    delinquency_list = []

    start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date() if start_date_str else datetime.now().date()
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if end_date_str else datetime.now().date()

    delinquencies = Delinquency.query.filter(Delinquency.unit_type == 'multicab', Delinquency.date_of_payment.between(start_date, end_date)).all()

    for delinquency in delinquencies:
        delinquency_list.append({
            'id': delinquency.id,
            'unit_id': delinquency.unit.unit_info,
            'date_of_payment': delinquency.date_of_payment.strftime('%Y-%m-%d'),
            'status': delinquency.status.value
            # Add more fields as needed
        })
  
    return jsonify({'delinquencies': delinquency_list}), 200

@admin.route('/admin/transactions/payment/motorela/daily', methods=['GET'])
def get_motorela_payment_transactions():
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date() if start_date_str else datetime.now().date()
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() + timedelta(days=1) if end_date_str else datetime.now().date()

    payment_transactions = Transaction.query.filter(
    Transaction.unit_type == 'motorela',
    Transaction.date_of_payment.between(start_date, end_date),
    or_(
        Transaction.type == 'TOLL_PAYMENT',
        Transaction.type == 'DELINQUENCY_PAYMENT'
    )
    ).all()


    transactions_list = []  
    for transaction in payment_transactions:
        transactions_list.append({
            'id': transaction.unit.unit_info,
            'date': transaction.date.strftime('%Y-%m-%d'),
            'amount': transaction.amount,
            'type': transaction.type.value
        })
  
    return jsonify({'transactions': transactions_list}), 200

@admin.route('/admin/transactions/payment/multicab/daily', methods=['GET'])
def get_multicab_payment_transactions():
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date() if start_date_str else datetime.now().date()
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() + timedelta(days=1) if end_date_str else datetime.now().date()

    payment_transactions = Transaction.query.filter(
    Transaction.unit_type == 'multicab',
    Transaction.date_of_payment.between(start_date, end_date),
    or_(
        Transaction.type == 'TOLL_PAYMENT',
        Transaction.type == 'DELINQUENCY_PAYMENT'
    )
    ).all()


    transactions_list = []  
    for transaction in payment_transactions:
        transactions_list.append({
            'id': transaction.unit.unit_info,
            'date': transaction.date.strftime('%Y-%m-%d'),
            'amount': transaction.amount,
            'type': transaction.type.value
        })
     
    return jsonify({'transactions': transactions_list}), 200


@admin.route('/addAdmin', methods=['POST'])
def addAdmin():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        address = request.form.get('address')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        admin = Admin.query.filter_by(username=username).first()
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
                # Create new user
                new_user = Admin(username=username, first_name=first_name, last_name=last_name,
                                address=address, password=generate_password_hash(password1, method='pbkdf2:sha256'),
                               )

                db.session.add(new_user)
                db.session.commit()

        return jsonify({'message': 'Account created successfully'}), 200
    
@admin.route('/admin/delinquencies/motorela/monthly', methods=['GET'])
def get_motorela_delinquencies_monthly():
    month = request.args.get('month')
    year = request.args.get('year')

    if not month or not year:
        return jsonify({'error': 'Month and year parameters are required.'}), 400

    try:
        month = int(month)
        year = int(year)
    except ValueError:
        return jsonify({'error': 'Invalid month or year format.'}), 400

    # Get the number of days in the selected month
    num_days_in_month = monthrange(year, month)[1]

    # Create a list of all dates in the selected month
    all_dates = [date(year, month, day) for day in range(1, num_days_in_month + 1)]

    # Query motorela delinquencies for the specified month and year from the database
    delinquencies = Delinquency.query.filter(
        extract('month', Delinquency.date_of_payment) == month,
        extract('year', Delinquency.date_of_payment) == year,
        Delinquency.unit_type == 'motorela'
    ).all()

    # Prepare the response data for daily and overall reports
    daily_report = {date.strftime('%Y-%m-%d'): {'total': 0, 'delinquencies': []} for date in all_dates}
    overall_report = {'total': 0}  # Initialize overall total

    for delinquency in delinquencies:
        date_str = delinquency.date_of_payment.strftime('%Y-%m-%d')

        # Daily report
        daily_report[date_str]['total'] += 1
        daily_report[date_str]['delinquencies'].append({
            'id': delinquency.id,
            'unit': delinquency.unit.unit_info,
            'date': date_str,
        })

        # Overall report
        overall_report['total'] += 1

    # Convert daily report to list for easier frontend handling
    daily_report_list = [{'date': date, 'total': report['total'], 'delinquencies': report['delinquencies']} 
                          for date, report in daily_report.items()]

    # Return the delinquency data as JSON
    return jsonify({'daily_report': daily_report_list, 'overall_report': overall_report}), 200

@admin.route('/admin/delinquencies/multicab/monthly', methods=['GET'])
def get_multicab_delinquencies_monthly():
    month = request.args.get('month')
    year = request.args.get('year')

    if not month or not year:
        return jsonify({'error': 'Month and year parameters are required.'}), 400

    try:
        month = int(month)
        year = int(year)
    except ValueError:
        return jsonify({'error': 'Invalid month or year format.'}), 400

    # Get the number of days in the selected month
    num_days_in_month = monthrange(year, month)[1]

    # Create a list of all dates in the selected month
    all_dates = [date(year, month, day) for day in range(1, num_days_in_month + 1)]

    # Query motorela delinquencies for the specified month and year from the database
    delinquencies = Delinquency.query.filter(
        extract('month', Delinquency.date_of_payment) == month,
        extract('year', Delinquency.date_of_payment) == year,
        Delinquency.unit_type == 'multicab'
    ).all()

    # Prepare the response data for daily and overall reports
    daily_report = {date.strftime('%Y-%m-%d'): {'total': 0, 'delinquencies': []} for date in all_dates}
    overall_report = {'total': 0}  # Initialize overall total

    for delinquency in delinquencies:
        date_str = delinquency.date_of_payment.strftime('%Y-%m-%d')

        # Daily report
        daily_report[date_str]['total'] += 1
        daily_report[date_str]['delinquencies'].append({
            'id': delinquency.id,
            'unit': delinquency.unit.unit_info,
            'date': date_str,
        })

        # Overall report
        overall_report['total'] += 1

    # Convert daily report to list for easier frontend handling
    daily_report_list = [{'date': date, 'total': report['total'], 'delinquencies': report['delinquencies']} 
                          for date, report in daily_report.items()]

    # Return the delinquency data as JSON
    return jsonify({'daily_report': daily_report_list, 'overall_report': overall_report}), 200


@admin.route('/admin/transactions/payment/motorela/monthly', methods=['GET'])
def get_motorela_payment_transactions_monthly():
    month = request.args.get('month')
    year = request.args.get('year')

    if not month or not year:
        return jsonify({'error': 'Month and year parameters are required.'}), 400

    try:
        month = int(month)
        year = int(year)
    except ValueError:
        return jsonify({'error': 'Invalid month or year format.'}), 400

    # Get the number of days in the selected month
    num_days_in_month = monthrange(year, month)[1]

    # Create a list of all dates in the selected month
    all_dates = [date(year, month, day) for day in range(1, num_days_in_month + 1)]

    # Query motorela payment transactions for the specified month and year from the database
    payment_transactions = Transaction.query.filter(
        extract('month', Transaction.date) == month,
        extract('year', Transaction.date) == year,
        or_(Transaction.type == 'TOLL_PAYMENT', Transaction.type == 'DELINQUENCY_PAYMENT'),
        Transaction.unit_type == 'motorela'
    ).all()

    # Prepare the response data for daily and overall reports
    daily_report = {date.strftime('%Y-%m-%d'): {'total': 0, 'transactions': []} for date in all_dates}
    overall_report = {'total': len(payment_transactions)}  # Initialize overall total

    for transaction in payment_transactions:
        date_str = transaction.date.strftime('%Y-%m-%d')

        # Daily report
        daily_report[date_str]['total'] += 1
        daily_report[date_str]['transactions'].append({
            'id': transaction.id,
            'unit': transaction.unit.unit_info,
            'date': date_str,
            'amount': transaction.amount,
            'type': transaction.type.value
        })

    # Convert daily report to list for easier frontend handling
    daily_report_list = [{'date': date, 'total': report['total'], 'transactions': report['transactions']} 
                          for date, report in daily_report.items()]

    # Return the transaction data as JSON
    return jsonify({'daily_report': daily_report_list, 'overall_report': overall_report}), 200



@admin.route('/admin/transactions/payment/multicab/monthly', methods=['GET'])
def get_multicab_payment_transactions_monthly():
    month = request.args.get('month')
    year = request.args.get('year')

    if not month or not year:
        return jsonify({'error': 'Month and year parameters are required.'}), 400

    try:
        month = int(month)
        year = int(year)
    except ValueError:
        return jsonify({'error': 'Invalid month or year format.'}), 400

    # Get the number of days in the selected month
    num_days_in_month = monthrange(year, month)[1]

    # Create a list of all dates in the selected month
    all_dates = [date(year, month, day) for day in range(1, num_days_in_month + 1)]

    # Query motorela payment transactions for the specified month and year from the database
    payment_transactions = Transaction.query.filter(
        extract('month', Transaction.date) == month,
        extract('year', Transaction.date) == year,
        or_(Transaction.type == 'TOLL_PAYMENT', Transaction.type == 'DELINQUENCY_PAYMENT'),
        Transaction.unit_type == 'multicab'
    ).all()

    # Prepare the response data for daily and overall reports
    daily_report = {date.strftime('%Y-%m-%d'): {'total': 0, 'transactions': []} for date in all_dates}
    overall_report = {'total': len(payment_transactions)}  # Initialize overall total

    for transaction in payment_transactions:
        date_str = transaction.date.strftime('%Y-%m-%d')

        # Daily report
        daily_report[date_str]['total'] += 1
        daily_report[date_str]['transactions'].append({
            'id': transaction.id,
            'unit': transaction.unit.unit_info,
            'date': date_str,
            'amount': transaction.amount,
            'type': transaction.type.value
        })

    # Convert daily report to list for easier frontend handling
    daily_report_list = [{'date': date, 'total': report['total'], 'transactions': report['transactions']} 
                          for date, report in daily_report.items()]
    
    # Return the transaction data as JSON
    return jsonify({'daily_report': daily_report_list, 'overall_report': overall_report}), 200


@admin.route('/money/daily', methods=['GET'])
@jwt_required()
def get_topup_transactions():
    transactions = Transaction.query.filter_by(type='TOPUP').all()
    topup_transactions = [{'id': transaction.id, 'amount': transaction.amount, 'unit_id': transaction.unit_id, 'branch': transaction.branch, 'unit_type': transaction.unit_type, 'balance_id': transaction.balance_id, 'teller_id': transaction.teller_id, 'type': transaction.type, 'timestamp': transaction.timestamp} for transaction in transactions]
    return jsonify({'topup_transactions': topup_transactions})

@admin.route('/money/monthly', methods=['GET'])
@jwt_required()
def get_topup_transactions_month():
    # Get the current month and year
    current_month = datetime.datetime.now().month
    current_year = datetime.datetime.now().year

    # Filter transactions for the current month and year
    transactions = Transaction.query.filter(func.month(Transaction.timestamp) == current_month, func.year(Transaction.timestamp) == current_year, Transaction.type == 'TOPUP').all()

    topup_transactions = [{'id': transaction.id, 'amount': transaction.amount, 'unit_id': transaction.unit_id, 'branch': transaction.branch, 'unit_type': transaction.unit_type, 'balance_id': transaction.balance_id, 'teller_id': transaction.teller_id, 'type': transaction.type, 'timestamp': transaction.timestamp} for transaction in transactions]

    return jsonify({'topup_transactions': topup_transactions})

@admin.route('/admin/analytics', methods=['GET'])
@jwt_required()
def get_operator_analytics():
    current_user_id = get_jwt_identity()

    motorela_count = Unit.query.filter_by( unit_type='motorela').count()
    multicab_count = Unit.query.filter_by( unit_type='multicab').count()

    return jsonify({
        'motorelaCount': motorela_count,
        'multicabCount': multicab_count
    })

@admin.route('/admin/analytics/overall', methods=['GET'])
def get_overall_data():
    year = request.args.get('year')
    if not year:
        return jsonify({'error': 'Year parameter is required'}), 400

    # Parse the year string to an integer
    try:
        year_int = int(year)
    except ValueError:
        return jsonify({'error': 'Invalid year format'}), 400

    # Get all toll payment transactions for the selected year
    toll_payments = Transaction.query.filter(Transaction.type == 'toll_payment') \
                                     .filter(func.year(Transaction.date) == year_int) \
                                     .all()

    # Get all delinquencies (both paid and unpaid) for the selected year
    delinquencies = Delinquency.query.filter(func.year(Delinquency.date_of_payment) == year_int) \
                                     .all()

    # Initialize dictionaries to store the total payments and delinquencies for each unit type
    total_payments_by_type = {'multicab': 0, 'motorela': 0}
    total_delinquencies_by_type = {'multicab': 0, 'motorela': 0}

    # Calculate the total toll payments and delinquencies for each unit type
    for transaction in toll_payments:
        if transaction.unit.unit_type == 'multicab':
            total_payments_by_type['multicab'] += transaction.amount
        elif transaction.unit.unit_type == 'motorela':
            total_payments_by_type['motorela'] += transaction.amount

    for delinquency in delinquencies:
        if delinquency.unit.unit_type == 'multicab':
            total_delinquencies_by_type['multicab'] += 11
        elif delinquency.unit.unit_type == 'motorela':
            total_delinquencies_by_type['motorela'] += 6

    # Calculate the total payments and delinquencies for all unit types
    total_payments = sum(total_payments_by_type.values())
    total_delinquencies = sum(total_delinquencies_by_type.values())

    # Return the data as JSON
    return jsonify({
        'total_payments': total_payments,
        'total_delinquencies': total_delinquencies,
        'total_payments_by_type': total_payments_by_type,
        'total_delinquencies_by_type': total_delinquencies_by_type
    }), 200

