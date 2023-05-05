import json

import google.auth.transport.requests
import requests
import jwt
from flask import redirect, request, session
from flask_session import Session
from flask.wrappers import Response
from flask_cors import cross_origin
from flask_restful import Resource
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, unset_jwt_cookies
from google.oauth2 import id_token
from pip._vendor import cachecontrol

from config.config import FRONTEND_URL, GOOGLE_CLIENT_ID, SECRET_KEY, flow
from init_app import db
from src.const import *
from src.models.states_md import States
from src.models.users_md import Users
from src.services.ratings_sv import *
from src.services.users_sv import *
from src.utils import *

class Login(Resource):
    @cross_origin(supports_credentials=True)
    def post(self):
        form = request.get_json()
        if not form:
            return {'msg': 'Wrong us'}, 401
        if not is_valid_username(form[USERNAME], 64):
            return {'msg': 'Wrong us'}, 401

        user = Users.query.filter_by(username=form[USERNAME]).first()
        if user:
            if user.password == form[PASSWORD]:
                access_token = jwt.encode(
                        {
                            'username': user.username
                        }, SECRET_KEY, algorithm="HS256"
                    )
                # user.login_state = access_token
                # db.session.commit()
                # response = {'access_token':access_token}
                link = f"{FRONTEND_URL}/account"
                if user.user_role == ADMIN:
                    link = f"{FRONTEND_URL}/dashboard"
                
                response = Response(
                    response=json.dumps(
                        {'url': link, 'user': access_token}),
                    status=200,
                    mimetype='application/json'
                )

                return response, OK_STATUS
        
        return {"msg": "Wrong email or password"}, 401
    
class LoginAPI(Resource):
    @cross_origin(supports_credentials=True)
    def get(self):
        
        authorization_url, state = flow.authorization_url()
        # response = redirect(authorization_url)
        print("login")
        # session[STATE] = state
        # db.session.add(States(state))
        # db.session.commit()

        # print("STATE FROM LOGIN(): ", state)  # gud


        response = Response(
            response=json.dumps(
                {'auth_url': authorization_url, 'state': state}),
            status=200,
            mimetype='application/json'
        )
        # response.set_cookie(STATE, state)
        # response.headers.add('Access-Control-Allow-Origin', '*')
        return response

class Register(Resource):
    @cross_origin(supports_credentials= True)
    def post(self):
        user_info = request.get_json()
        status = add_user(user_info)
        
        if status == OK_STATUS:
            return redirect(f"{FRONTEND_URL}/login")
        elif status == BAD_REQUEST:
            return "BAD_REQUEST"
        # response = 
        # return response



class Callback(Resource):
    @cross_origin(supports_credentials=True)
    def get(self):
        # print("STATE AT BEGINNING OF CALLBACK(): ", request.cookies.get(STATE)) # wrong

        flow.fetch_token(authorization_response=request.url)
        
        # if not session[STATE] == request.args[STATE]:
        #     return BAD_REQUEST
        
        state=request.args[STATE]
        
        if not state:
            # remove_current_state()
            # print("DB_STATE: ", db_state.state)
            return {"message": "States don't match. You may delete your cookies and retry."}, 500

        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(
            session=cached_session)

        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=3
        )
        print("callback")
        current_email = id_info.get(EMAIL)
        print(current_email)
        user = Users.query.filter_by(email=current_email).first()
        if user is None:
            user = Users(email=current_email, profile_pic=id_info.get(PICTURE))
            db.session.add(user)
            db.session.commit()
        access_token = jwt.encode(
                        {
                            'username': user.username
                        }, SECRET_KEY, algorithm="HS256"
                    )
        # user.login_state = access_token
        link = f"{FRONTEND_URL}/account"
        if user.user_role == ADMIN:
            link = f"{FRONTEND_URL}/dashboard"
        response = Response(
                    response=json.dumps(
                        {'url': link, 'user': access_token}),
                    status=200,
                    mimetype='application/json'
                )
        # response.set_cookie(STATE, access_token)
        # response = redirect(f"{FRONTEND_URL}/account")
        
        return response


class Logout(Resource):
    def get(self):
        # remove_current_state()
        # response = redirect("/")
        # response.delete_cookie(STATE)
        # return response

        response=json.dumps({"message": "Logged out"})
        unset_jwt_cookies(response)
        return Response(
            response,
            status=202,
            mimetype='application/json'
        )
