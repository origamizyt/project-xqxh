# database.py

import pymongo
import mysql.connector as mysql
from models import User

MYSQL_HOST = 'localhost'
MYSQL_USER = 'campusnav_guest'
MYSQL_PASSWORD = 'iqa0ysIYZg'
MYSQL_DATABASE = 'campusnav'
MONGO_URL = "mongodb+srv://face_recognition_guest:4bwBHaGaUSm7FdLY@cloudmongo-fbkmu.azure.mongodb.net/campusnav?retryWrites=true&w=majority"
mongo_client = None
mysql_client = None

def get_mongo_client():
    global mongo_client
    if mongo_client is None:
        mongo_client = pymongo.MongoClient(MONGO_URL)
    return mongo_client

def get_mysql_client():
    global mysql_client
    if mysql_client is None:
        mysql_client = mysql.connect(host=MYSQL_HOST, user=MYSQL_USER, passwd=MYSQL_PASSWORD, database=MYSQL_DATABASE)
    return mysql_client

def store_user_face(user_id, base64_data):
    client = get_mongo_client()
    db = client.get_database('campusnav')
    db.faces.update_one({'user_id': user_id },
                        {'$set': {'face_data': base64_data}}, True)

def get_user_face(user_id):
    client = get_mongo_client()
    db = client.get_database('campusnav')
    result = db.faces.find_one({'user_id': user_id})
    if result:
        return result['face_data']
    return None

def get_user_datas():
    client = get_mongo_client()
    db = client.get_database('campusnav')
    result = db.faces.find()
    result = map(lambda doc: (doc['user_id'], doc['face_data']), result)
    return list(result)

def remove_user_data(user_id):
    client = get_mongo_client()
    db = client.get_database('campusnav')
    db.faces.remove({ 'user_id': user_id })

def close_current_mongo_client():
    global mongo_client
    if mongo_client != None:
        mongo_client.close()
        mongo_client = None

def close_current_mysql_client():
    global mysql_client
    if mysql_client != None:
        mysql_client.close()
        mysql_client = None

def register_user(user):
    client = get_mysql_client()
    cursor = client.cursor()
    cursor.execute('INSERT INTO users (username) VALUES (%s)', (user.username,))
    client.commit()
    return cursor.lastrowid

def user_exists(user_id):
    client = get_mysql_client()
    cursor = client.cursor()
    cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
    return cursor.fetchone() is not None

def get_user(user_id):
    client = get_mysql_client()
    cursor = client.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
    result = cursor.fetchone()
    if result is None: return None
    return User(result['username'])

def remove_user(user_id):
    client = get_mysql_client()
    cursor = client.cursor()
    cursor.execute('DELETE FROM users WHERE user_id = %s', (user_id,))
    client.commit()
