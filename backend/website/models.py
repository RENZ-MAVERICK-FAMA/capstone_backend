from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from enum import Enum
from sqlalchemy.orm import relationship
from datetime import datetime



class TransactionType(Enum):
    TOPUP = 'top-up'
    TOLL_PAYMENT = 'toll payment'
    DELINQUENCY_PAYMENT = 'delinquency payment'

class DElStatus(Enum):
    PAID ='paid'
    UNPAID ='unpaid'

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer)
    date_of_payment = db.Column(db.DateTime(timezone=True), default=func.now())
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    unit_type = db.Column(db.String(150))
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'))
    balance_id = db.Column(db.Integer, db.ForeignKey('balance.id'))
    teller_id = db.Column(db.Integer, db.ForeignKey('teller.id'))
    branch = db.Column(db.String(150))
    reference_key = db.Column(db.String(150))
    type = db.Column(db.Enum(TransactionType))
    teller = db.relationship('Teller', backref='transactions')
    unit = db.relationship('Unit', backref='transactions')
    balance = db.relationship('Balance', backref='transactions')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    address = db.Column(db.String(150))
    license = db.Column(db.String(150))
    permit = db.Column(db.String(150))
    units = db.relationship('Unit', backref='user', lazy=True)

class Teller(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    address = db.Column(db.String(150))
 
    
class Kiosk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique = True)
    password = db.Column(db.String(150))
   
class Unit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unit_info = db.Column(db.String(150), unique = True)
    color = db.Column(db.String(150))
    unit_type = db.Column(db.String(150))
    password = db.Column(db.String(150))
    qrcode = db.Column(db.String(999))
    picture = db.Column(db.String(999))
    balances = db.relationship('Balance', back_populates='unit')  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Balance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Integer, nullable=False)
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'), nullable=False)
    unit = db.relationship('Unit', back_populates='balances') 
    
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    address = db.Column(db.String(150))

    
class Delinquency(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    date_of_payment = db.Column(db.Date, nullable=False)
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'))
    status = db.Column(db.Enum(DElStatus))
    unit_type = db.Column(db.String(150))
    unit = db.relationship('Unit', backref='delinquency')



# Define your database models here
class Amount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float)
    teller_id = db.Column(db.Integer, db.ForeignKey('teller.id'))
    teller = db.relationship('Teller', backref='amounts')


class InsertedCoins(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inserted_coins = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, inserted_coins):
        self.inserted_coins = inserted_coins
class SuperAdmin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    address = db.Column(db.String(150))


