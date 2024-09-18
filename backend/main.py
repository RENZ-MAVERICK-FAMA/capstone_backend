from flask_mail import Mail
from website import create_app
from flask_cors import CORS
from flask import request, has_request_context
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

# Console handler
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)

# File handler
fileHandler = RotatingFileHandler("logs.log", maxBytes=1024 * 1024 * 5, backupCount=5)  # 5 MB per file, keep 5 backups
fileHandler.setFormatter(logFormatter)
logger.addHandler(fileHandler)

CORS(app, resources={r"/*": {"origins": "https://main--qrmc-pass.netlify.app"}})
jwt = JWTManager(app)
mail = Mail(app)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=9000)
