# database.py

import pymongo

MONGO_URL = "mongodb+srv://face_recognition_guest:4bwBHaGaUSm7FdLY@cloudmongo-fbkmu.azure.mongodb.net/campusnav?retryWrites=true&w=majority"

def get_mongo_client():
    return pymongo.MongoClient(MONGO_URL)

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