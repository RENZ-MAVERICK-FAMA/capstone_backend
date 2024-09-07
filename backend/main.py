from flask_mail import Mail
from website import create_app
from flask_cors import CORS
from flask import Flask, request, has_request_context
from flask_jwt_extended import JWTManager
import logging
from logging.handlers import RotatingFileHandler

app = create_app()
logger = logging.getLogger(__name__)  # Use __name__ for logger name

class newFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            record.url = request.url
            record.remote = request.remote_addr
        else:
            record.url = None
            record.remote = None

        return super().format(record)

logFormatter = newFormatter("%(asctime)s - %(url)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)  # Use logFormatter, not newFormatter
logger.addHandler(consoleHandler)

filehandler = RotatingFileHandler("logs.log" ,backupCount=500 ,maxBytes=20883)
filehandler.setFormatter(logFormatter)  # Use logFormatter, not newFormatter
logger.addHandler(filehandler)

CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})
jwt = JWTManager(app)
mail = Mail(app)

if __name__ == '__main__':  
    app.run(debug=True, host='0.0.0.0', port=9000)
