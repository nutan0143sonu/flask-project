import jwt
import datetime
import uuid
import json
import requests
from flask import jsonify
from flask import Flask,request
from flask_pymongo import PyMongo
from flask_restful import Resource, Api
from bson import json_util
from bson.json_util import dumps,loads
# from flask_jwt_extended import JWTManager
# from flask_bcrypt import Bcrypt



app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY']="thisisthesecretkeytocreatetherestfulapi"
app.config["MONGO_URI"] = "mongodb://localhost:27017/rest"
mongo = PyMongo(app)

#----------------------------Encode Jwt Key------------------------------------------
def encode_auth_token(id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=15),
            'iat': datetime.datetime.utcnow(),
            'sub': id
        }
        return jwt.encode(
            payload,
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
    except Exception as e:
        return e

#------------------------Decode Jwt Key--------------------------
def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, app.config['SECRET_KEY'])
        return payload['sub'],200
    except jwt.ExpiredSignatureError:
        return {"message":'Signature expired. Please log in again.'},400
    except jwt.InvalidTokenError:
        return {"message":'Invalid token. Please log in again.'},400

#---------------------------Call Decode method with authentication--------
def authtoken():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return {"message":"Authentication required!"},400
    auth_token = auth_header.split(" ")[1]
    if auth_token:
        resp = decode_auth_token(auth_token)
        return resp
    return {"Message":"tokoen is not correct"},400
        


# mongo.db.User.drop()
class SignUpApi(Resource):
    def post(self):
        params = json.loads(request.data)
        params['_id'] = str(uuid.uuid4())
        user = mongo.db.User.find_one({"email":params['email']})
        if user :
            return {"message":"User already exist"},400
        user_data = mongo.db.User.insert_one(params)
        return { "status": 'success',"uuid":params['_id']}, 201
    
    def get(self):
        token = authtoken()
        print("token",token)
        if 400 in token:
           return token,400
        else:
            print(token[0])
            data = mongo.db.User.find_one({"_id":token[0]})
            return {"data":loads(dumps(data))}, 200
api.add_resource(SignUpApi, '/signup')


class LoginApi(Resource):
    def post(self):
        params = json.loads(request.data)
        try:
            user = mongo.db.User.find_one({"email":params['email']})
            print("hello",user['_id'])
            if not user and user['password']!=params['password']:
                return {"message":"Please Enter correct credetial!"},400
            auth_token = encode_auth_token(user['_id'])
            print("auth token",auth_token)
            if auth_token:
                return {"message":"Successful Login!","JWT Token":auth_token.decode()},200
        except Exception as e:
            print("Exception",e)
            return {"message":"Something Went Wrong!"},400
api.add_resource(LoginApi, '/login')


class UpdateUser(Resource):   
    def put(self, id):
        params = json.loads(request.data)
        data = mongo.db.User.update_one(
        { "_id": id },
        { "$set":params } )
        return {"message":"Successfully Updated","data":loads(dumps(mongo.db.User.find_one({"_id": id})))}, 200

    def get(self,id):
        try:
            user = mongo.db.User.find_one({"_id":id})
            return {"data":loads(dumps(user))}, 200
        except:
            return {"message":"Something Went Wrong"},400
    def delete(self,id):
        user = mongo.db.User.delete_one({"_id": id})
        return {"message" : "User deleted successfully"}, 200

api.add_resource(UpdateUser, '/update/<id>')

if __name__ == '__main__':
    app.run(debug=True)
