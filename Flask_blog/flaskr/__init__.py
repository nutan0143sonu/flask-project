import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY']="thisismysecretkeyinformation"
    app.config['SQLALCHEMY_DATABASE_URI']="postgresql://postgres:Mobiloitte1@localhost:5432/flaskblog"

    db.init_app(app)
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from . import auth
    app.register_blueprint(auth.auth)

    from . import main
    app.register_blueprint(main.main)

    from .models import User

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    return app

if __name__ == "__main__":
    app.run()
    