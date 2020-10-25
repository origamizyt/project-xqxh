# faceupload.py

import cv2.cv2 as cv2, base64, face_recognition, json, sys, pickle
from io import BytesIO
import numpy as np
import database as db
from models import User, config, FaceData, UploadResult

ERR_ERROR = 0
ERR_NO_FACE = 1
DISTANCE_THRESHOLD = config.face.distanceThreshold


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
    return UploadResult(True, data.user_id)

def save_model(user_id, model):
    binary = pickle.dumps(model)
    b64data = encode_base64(binary)
    db.store_user_face(user_id, b64data.decode('iso-8859-1'))

def load_model(user_id):
    b64data = db.get_user_face(user_id).encode('iso-8859-1')
    binary = decode_base64(b64data)
    return pickle.loads(binary)

def load_models():
    ids = []
    models = []
    for user_id, model in db.get_user_datas():
        ids.append(user_id)
        b64data = model.encode('iso-8859-1')
        binary = decode_base64(b64data)
        models.append(pickle.loads(binary))
    return ids, models

def face_match(new_face, models, threshold=DISTANCE_THRESHOLD):
    if len(models) == 0:
        return -1, None
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
    array = np.frombuffer(data, np.uint8)
    return cv2.imdecode(array, cv2.IMREAD_COLOR)

def encode_base64_image(data):
    array = cv2.imencode('.png', data)[1]
    return base64.b64encode(array)

def encode_jpg(array):
    return cv2.imencode('.png', array)[1].tobytes()

def decode_jpg(data):
    return cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)

def find_single_face(image):
    faces = face_recognition.face_locations(image)
    if len(faces) > 0:
        return faces[0]
    return None

def find_faces(image):
    return face_recognition.face_locations(image)

def face_encodings(image, locations=None):
    return face_recognition.face_encodings(image, locations)[0]

if __name__ == '__main__':
    op = input("Store/Detect/Remove/Query (s/d/r/q): ").strip().lower()
    if op == 's':
        username = input("Username: ")
        password = input("Password: ")
        uid = db.register_user(User(username=username, password=password))
        print("Your user id is:", uid)
        cam = cv2.VideoCapture(0)
        while True:
            ret, frame = cam.read()
            small = cv2.resize(frame, (0, 0), fx=0.33, fy=0.33)
            face = find_single_face(small)
            if face is not None:
                t, r, b, l = face
                frame = cv2.rectangle(frame, (l*3, t*3), (r*3, b*3), (255, 0, 0), 2)
            else:
                frame = cv2.putText(frame, 'Please move your face closer.', (10, 20), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 0, 255), 1)
            cv2.imshow(f'Face registering for user {username}', frame)
            if cv2.waitKey(1) == 27 and face is not None: break
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
            small = cv2.resize(frame, (0, 0), fx=0.33, fy=0.33)
            for face in find_faces(small):
                t, r, b, l = face
                new_face = face_recognition.face_encodings(small, [face])[0]
                index, distance = face_match(new_face, models)
                if index >= 0:
                    frame = cv2.rectangle(frame, (l*3, t*3), (r*3, b*3), (0, 255, 0), 2)
                    uid = ids[index]
                    username = usernames[index]
                    if username == None:
                        username = usernames[index] = db.get_user(uid).username
                    frame = cv2.putText(frame, f'User Id: {uid}', (l*3, (t*3-50 if t*3>50 else t*3+50)), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 255, 0), 1)
                    frame = cv2.putText(frame, f'User Name: {username}', (l*3, (t*3-30 if t*3>30 else t*3+30)), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 255, 0), 1)
                    frame = cv2.putText(frame, f'Similarity: {1-distance:.5%}', (l*3, (t*3-10 if t*3>10 else t*3+10)), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 255, 0), 1)
                else:
                    frame = cv2.rectangle(frame, (l*3, t*3), (r*3, b*3), (0, 0, 255), 2)
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