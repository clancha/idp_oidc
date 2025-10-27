from flask import Flask
from .config import Config
from .blueprints import bp
from .model import init_demo_data

def create_app():
    app = Flask(__name__, template_folder="templates")
    app.config.from_object(Config())
    app.register_blueprint(bp)

    with app.app_context():
        init_demo_data()
    return app
