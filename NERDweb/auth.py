from functools import wraps
import jwt
from flask import request, abort
from flask import current_app
from userdb import get_user_by_id
import os
import common.config


config = common.config.read_config(os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "/etc/nerd/nerdweb.yml")))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"]
        if not token:
            return {
                "message": "Authentication Token is missing!",
                "data": None,
                "error": "Unauthorized"
            }, 401
        try:
            data=jwt.decode(token, config.get("secret_key"), algorithms=["HS256"])
            
            if data["user"]["login_type"] == "devel":
                return data
            current_user=get_user_by_id(data["user"]["id"])
            if current_user is None:
                return {
                "message": "Invalid Authentication token!",
                "data": None,
                "error": "Unauthorized"
            }, 401
            if not "registered" in current_user["groups"]:
                return {
                "message": "Email address not verified",
                "data": None,
            }, 403
        except Exception as e:
            return {
                "message": "Something went wrong",
                "data": str(e),
                "error": "AuthToken wrong"
            }, 401

        return f(current_user, *args, **kwargs)

    return decorated

