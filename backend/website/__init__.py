from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
import pymysql
pymysql.install_as_MySQLdb()

db = SQLAlchemy()
DB_NAME = "database.db"



def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'QRMCPASS'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/qrmcpass'

    db.init_app(app)

    from .views import views
    from .auth import auth
    from .teller import teller
    from .operator import operator
    from .unit import unit
    from .admin import admin

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(teller, url_prefix='/')
    app.register_blueprint(operator, url_prefix='/')
    app.register_blueprint(unit, url_prefix='/')
    app.register_blueprint(admin, url_prefix='/')
    from .models import User

    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app

def create_database(app):
    with app.app_context():
        if not path.exists('website/' + DB_NAME):
            db.create_all()
            print('Created Database!')

app = create_app()

# Initialize the database
create_database(app)


