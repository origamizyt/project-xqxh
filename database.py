# database.py

import pymongo
import mysql.connector as mysql
from models import User, config

MYSQL_HOST = config.mysql.host
MYSQL_USER = config.mysql.user
MYSQL_PASSWORD = config.mysql.password
MYSQL_DATABASE = config.mysql.database
MONGO_URL = config.mongo.url
MONGO_DATABASE = config.mongo.database
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
        mysql_client = mysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            passwd=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            auth_plugin='mysql_native_password')
    return mysql_client

def store_user_face(user_id, base64_data):
    client = get_mongo_client()
    db = client.get_database(MONGO_DATABASE)
    db.faces.update_one({'user_id': user_id },
                        {'$set': {'face_data': base64_data}}, True)

def get_user_face(user_id):
    client = get_mongo_client()
    db = client.get_database(MONGO_DATABASE)
    result = db.faces.find_one({'user_id': user_id})
    if result:
        return result['face_data']
    return None

def get_user_datas():
    client = get_mongo_client()
    db = client.get_database(MONGO_DATABASE)
    result = db.faces.find()
    result = map(lambda doc: (doc['user_id'], doc['face_data']), result)
    return list(result)

def remove_user_data(user_id):
    client = get_mongo_client()
    db = client.get_database(MONGO_DATABASE)
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
    return User(**result)

def remove_user(user_id):
    client = get_mysql_client()
    cursor = client.cursor()
    cursor.execute('DELETE FROM users WHERE user_id = %s', (user_id,))
    client.commit()

def certify_dog(dog_name, password):
    client= get_mysql_client()
    cursor = client.cursor(dictionary=True)
    cursor.execute('SELECT * FROM dogs WHERE dog_name = %s', (dog_name,))
    result = cursor.fetchone()
    if result is None: return False
    return result['password'] == password