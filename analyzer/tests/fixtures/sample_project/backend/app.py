import os
import sys
from flask import Flask
from services.user_service import get_user

app = Flask(__name__)

@app.route("/users/<int:user_id>")
def user_detail(user_id):
    return get_user(user_id)
