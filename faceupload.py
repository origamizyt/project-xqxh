# faceupload.py

import cv2.cv2 as cv2, base64, face_recognition, json, sys
from io import BytesIO
import numpy as np
import database as db
from models import User, config

ERR_ERROR = 0
ERR_NO_FACE = 1
DISTANCE_THRESHOLD = config.face.distanceThreshold

class UploadResult:
    def __init__(self, success, data):
        self.success = success
        self.data = data
    def toJson(self):
        return json.dumps({"success": self.success, "data": self.data})

class FaceData:
    def __init__(self, user_id, data):
        self.user_id = user_id
        self.data = data

def upload(data):
    try:
        return upload_internal(data)
    except Exception:
        return UploadResult(False, ERR_ERROR)

def upload_internal(data):
    image = decode_base64_image(data.data)
    face = find_single_face(image)
    if face is None:
        return UploadResult(False, ERR_NO_FACE)
    trait = face_recognition.face_encodings(image)[0]
    save_model(data.user_id, trait)
    return UploadResult(True, None)

def save_model(user_id, model):
    b = BytesIO()
    np.save(b, model)
    db.store_user_face(user_id, encode_base64(b.getvalue()).decode('iso-8859-1'))

def load_model(user_id):
    face_data = decode_base64(db.get_user_face(user_id).encode('iso-8859-1'))
    b = BytesIO(face_data)
    return np.load(b)

def load_models():
    ids = []
    models = []
    for user_id, model in db.get_user_datas():
        ids.append(user_id)
        b = BytesIO(decode_base64(model.encode('iso-8859-1')))
        models.append(np.load(b))
    return ids, models

def face_match(new_face, models, threshold=DISTANCE_THRESHOLD):
    result = face_recognition.face_distance(models, new_face)
    index = np.argmin(result)
    if result[index] > threshold:
        return -1, None
    return index, result[index]

def decode_base64(data):
    return base64.b64decode(data)

def encode_base64(data):
    return base64.b64encode(data)

def decode_base64_image(data):
    data = base64.b64decode(data)
    array = np.fromstring(data, np.uint8)
    return cv2.imdecode(array, cv2.IMREAD_COLOR)

def encode_base64_image(data):
    array = cv2.imencode('.png', data)[1]
    return base64.b64encode(array)

def find_single_face(image):
    faces = face_recognition.face_locations(image)
    if len(faces) > 0:
        return faces[0]
    return None

def find_faces(image):
    return face_recognition.face_locations(image)

if __name__ == '__main__':
    op = input("Store/Detect/Remove/Query (s/d/r/q): ").strip().lower()
    if op == 's':
        username = input("Username: ")
        uid = db.register_user(User(username))
        print("Your user id is:", uid)
        cam = cv2.VideoCapture(0)
        while True:
            ret, frame = cam.read()
            small = cv2.resize(frame, (0, 0), fx=0.25, fy=0.25)
            face = find_single_face(small)
            if face is not None:
                t, r, b, l = face
                frame = cv2.rectangle(frame, (l*4, t*4), (r*4, b*4), (255, 0, 0), 2)
            cv2.imshow('face', frame)
            if cv2.waitKey(1) == 27: break
        cv2.destroyAllWindows()
        cam.release()
        bframe = encode_base64_image(frame)
        fd = FaceData(uid, bframe)
        print(upload_internal(fd).toJson())
    elif op == 'd':
        ids, models = load_models()
        usernames = [None] * len(ids)
        cam = cv2.VideoCapture(0)
        while True:
            ret, frame = cam.read()
            small = cv2.resize(frame, (0, 0), fx=0.25, fy=0.25)
            for face in find_faces(small):
                t, r, b, l = face
                new_face = face_recognition.face_encodings(small, [face])[0]
                index, distance = face_match(new_face, models)
                if index >= 0:
                    frame = cv2.rectangle(frame, (l*4, t*4), (r*4, b*4), (0, 255, 0), 2)
                    uid = ids[index]
                    username = usernames[index]
                    if username == None:
                        username = usernames[index] = db.get_user(uid).username
                    frame = cv2.putText(frame, f'User Id: {uid}', (l*4, (t*4-50 if t*4>50 else t*4+50)), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 255, 0), 1)
                    frame = cv2.putText(frame, f'User Name: {username}', (l*4, (t*4-30 if t*4>30 else t*4+30)), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 255, 0), 1)
                    frame = cv2.putText(frame, f'Similarity: {1-distance:.5%}', (l*4, (t*4-10 if t*4>10 else t*4+10)), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 255, 0), 1)
                else:
                    frame = cv2.rectangle(frame, (l*4, t*4), (r*4, b*4), (0, 0, 255), 2)
            cv2.imshow('tolerance=' + str(DISTANCE_THRESHOLD), frame)
            if cv2.waitKey(1) == 27: break
        cv2.destroyAllWindows()
        cam.release()
    elif op == 'r':
        uid = int(input("User Id: "))
        if db.user_exists(uid):
            db.remove_user_data(uid)
            db.remove_user(uid)
            print("User successfully removed.")
        else:
            print("User does not exist.")
    elif op == 'q':
        uid = int(input("User Id: "))
        if db.user_exists(uid):
            user = db.get_user(uid)
            print("User Name:", user.username)
        else:
            print("User does not exist.")
    db.close_current_mongo_client()
    db.close_current_mysql_client()