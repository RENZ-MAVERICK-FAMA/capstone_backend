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

views = Blueprint('views', __name__)
import calendar
 

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    
        return render_template("home.html", user=current_user)




@views.route('/topup1', methods=['GET', 'POST'])
@login_required
def topup():


    if request.method == 'POST':
        amt = request.form.get('amt')
        unit_id = request.form.get('unit')
        branch = request.form.get('branch')
        teller = request.form.get('teller')

        try:
            # Get the selected unit object
            unit = Unit.query.get(unit_id)

            if not unit:
                return jsonify({'message': 'Unit not found!'}), 400

            # Get or create the balance entry
            balance_entry = Balance.query.filter_by(unit_id=unit_id).first()

            if not balance_entry:
                balance_entry = Balance(unit_id=unit_id, balance=0)

            # Update the balance amount
            balance_entry.balance += int(amt)

            # Create a new transaction
            transaction = Transaction(amount=int(amt), unit=unit, teller=teller, branch=branch, balance=balance_entry, type='TOPUP')

            # Add the balance entry and transaction to the session and commit the changes
            db.session.add(balance_entry)
            db.session.add(transaction)
            db.session.commit()

            flash('Balance added!', category='success')

            # If AJAX request, return JSON response
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'message': 'Top up successful!'}), 200

            # If regular form submission, redirect with flash message
            return redirect(url_for('views.topup'))

        except SQLAlchemyError as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', category='error')
            print(e)

            # If AJAX request, return JSON response
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'message': 'An error occurred. Please try again.'}), 500

            # If regular form submission, redirect with flash message
            return redirect(url_for('views.topup'))

    # Fetch all units for the current user
    units = Unit.query.filter_by(user_id=current_user.id).all()

    # Generate CSRF token
    csrf_token = generate_csrf()

    # If AJAX request, return JSON response
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'message': 'Invalid request'}), 400

    # Render the template with the CSRF token and flash messages
    return render_template("topup.html", user=current_user, units=units, csrf_token=csrf_token)




@views.route('/get_balance/<int:unit_id>')
def get_balance(unit_id):
    unit = Unit.query.get(unit_id)
    if unit:
        return jsonify({'balance': unit.balance})
    else:
        return jsonify({'error': 'Unit not found'}), 404
    


@views.route('/deducta', methods=['GET', 'POST'])
@login_required
def deduct1():
        if request.method == 'POST':
        
            user = User.query.get(current_user.id)
            unit_type = user.unit_type
        

            if unit_type == 'Motorela':
                amt1 = 6
            elif unit_type == 'Multicab':
                amt1 = 10
                
                amt1 = unit_type
            # Get the payment date from the form
            payment_date_str = request.form.get('payment_date')
            payment_date = datetime.strptime(payment_date_str, '%Y-%m-%d').date()

            # Ensure the payment date is not in the future
            today = date.today()
            if payment_date > today:
                flash('Cannot process payment for future dates', category='error')
                return redirect(url_for('views.deduct'))  # Redirect back to the form

            # Get the user's balance entry from the Balance table
            balance_entry = Balance.query.filter_by(user_id=user.id).first()

            # If no balance entry exists, return an error
            if not balance_entry:
                flash('No balance entry found', category='error')
                return redirect(url_for('views.deduct'))  # Redirect back to the form

        

            if balance_entry.balance < amt1:
                flash('Insufficient balance', category='error')
                return redirect(url_for('views.deduct'))  # Redirect back to the form

            # Check if a deduction has already been made for the selected date
            existing_transaction = Transaction.query.filter_by(user_id=user.id, date=payment_date).first()
            if existing_transaction:
                flash('Deduction already made for {}'.format(payment_date), category='error')
                return redirect(url_for('views.deduct'))  # Redirect back to the form

            # Deduct the amount from the balance
            balance_entry.balance -= amt1

            # Create a new transaction
            transaction = Transaction(amount=amt1, user_id=user.id, balance_id=balance_entry.id, type='PAYMENT', date=payment_date, date_of_payment=today)

            # Commit the transaction and balance changes to the database
            db.session.add(transaction)
            db.session.commit()

            flash('Balance deducted!', category='success')
            return redirect(url_for('views.deduct'))  
        
        return render_template("deduct.html", user=current_user)  




@views.route('/payment_calendar', defaults={'year': None, 'month': None})
@views.route('/payment_calendar/<int:year>/<int:month>')
@login_required
def payment_calendar(year=None, month=None):
        if year is None or month is None:
            current_date = datetime.today()
            year = current_date.year
            month = current_date.month

        # Handle year boundaries
        if month < 1:
            month = 12
            year -= 1
        elif month > 12:
            month = 1
            year += 1

        # Calculate the previous and next months
        previous_month = month - 1 if month > 1 else 12
        previous_year = year if month > 1 else year - 1
        next_month = month + 1 if month < 12 else 1
        next_year = year if month < 12 else year + 1

        # Get the calendar data for the specified year and month
        calendar_data = [[{'day': day, 'is_paid': False, 'is_future': False} for day in week] for week in monthcalendar(year, month)]

        # Query transaction dates for the current month
        transaction_dates = {transaction.date.day for transaction in Transaction.query.filter(
            extract('year', Transaction.date) == year,
            extract('month', Transaction.date) == month,
            Transaction.user_id == current_user.id
        ).all()}

        for week in calendar_data:
            for day in week:
                if day['day'] != 0:
                    day_date = date(year, month, day['day'])
                    is_paid = day['day'] in transaction_dates
                    is_future = day_date > date.today()
                    day['is_paid'] = is_paid
                    day['is_future'] = is_future

        # Define the calendar variable
        calendar = {
            'year': year,
            'month': month
        }
    
        first_day_of_month = datetime(year, month, 1)
        calendar['month_name'] = first_day_of_month.strftime('%B')

        return render_template('payment_calendar.html', calendar_data=calendar_data, user=current_user, current_date=datetime(year, month, 1), calendar=calendar, previous_month=previous_month, next_month=next_month, previous_year=previous_year, next_year=next_year)


@views.route('/deduct_no_redirect', methods=['GET', 'POST'])
@login_required
def deduct_no_redirect():
        if request.method == 'POST':
            user = User.query.get(current_user.id)
            unit_type = user.unit_type

            if unit_type == 'Motorela':
                amt1 = 6
            elif unit_type == 'Multicab':
                amt1 = 10
            else:
                amt1 = 0

            payment_date_str = request.form.get('payment_date')
            payment_date = datetime.strptime(payment_date_str, '%Y-%m-%d').date()

            today = date.today()
            if payment_date > today:
                flash('Cannot process payment for future dates', category='error')
                return redirect(url_for('views.payment_calendar', year=today.year, month=today.month))

            balance_entry = Balance.query.filter_by(user_id=user.id).first()

            if not balance_entry:
                flash('No balance entry found', category='error')
                return redirect(url_for('views.payment_calendar', year=today.year, month=today.month))

            if balance_entry.balance < amt1:
                flash('Insufficient balance', category='error')
                return redirect(url_for('views.payment_calendar', year=today.year, month=today.month))

            existing_transaction = Transaction.query.filter_by(user_id=user.id, date=payment_date).first()
            if existing_transaction:
                flash('Deduction already made for {}'.format(payment_date), category='error')
                return redirect(url_for('views.payment_calendar', year=today.year, month=today.month))

            balance_entry.balance -= amt1

            transaction = Transaction(amount=amt1, user_id=user.id, balance_id=balance_entry.id, type='PAYMENT', date=payment_date, date_of_payment=today)

            db.session.add(transaction)
            db.session.commit()

            flash('Balance deducted!', category='success')
            return redirect(url_for('views.payment_calendar', year=payment_date.year, month=payment_date.month))

        # Redirect to payment calendar in case of GET request
        return redirect(url_for('views.payment_calendar'))



@views.route('/addunitsa', methods=['GET','POST'])
@login_required
def addunit():
    if request.method == 'POST':
        unit_info = request.form.get('unitinfo')
        unit_type = request.form.get('unittype')
        color = request.form.get('color')
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(unit_info)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        qr_code_dir = os.path.join(current_app.root_path, 'static', 'qrcodes')
        os.makedirs(qr_code_dir, exist_ok=True)
        qr_code_filename = f'{unit_info}_qrcode.png'
        qr_code_path = os.path.join(qr_code_dir, qr_code_filename)
        img.save(qr_code_path)
        
       
        new_unit = Unit(unit_info=unit_info, unit_type=unit_type, qrcode=qr_code_filename, color=color, user_id=current_user.id)
        db.session.add(new_unit)
        db.session.commit()
        
        new_balance = Balance(balance=0, unit=new_unit)
        db.session.add(new_balance)
        db.session.commit()
        
        flash('Unit added!', category='success')
    return render_template("addunit.html", user=current_user)   

@views.route('/unita', methods=['GET'])
@login_required
def units():
    units = Unit.query.filter_by(user_id=current_user.id).all()
    transactions = {}
    for unit in units:
        transactions[unit.id] = Transaction.query.filter_by(unit_id=unit.id).all()
    return render_template('units.html', user=current_user, units=units, transactions=transactions)

