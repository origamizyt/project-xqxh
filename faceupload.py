# faceupload.py

import cv2, base64, face_recognition, json
from io import BytesIO
import numpy as np
from database import *

ERR_ERROR = 0
ERR_NO_FACE = 1
DISTANCE_THRESHOLD = 0.4
SCALE = 0.25

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
    store_user_face(user_id, encode_base64(b.getvalue()).decode('iso-8859-1'))

def load_model(user_id):
    face_data = decode_base64(get_user_face(user_id).encode('iso-8859-1'))
    b = BytesIO(face_data)
    return np.load(b)

def load_models():
    ids = []
    models = []
    for user_id, model in get_user_datas():
        ids.append(user_id)
        b = BytesIO(decode_base64(model.encode('iso-8859-1')))
        models.append(np.load(b))
    return ids, models

def face_match(new_face, models):
    result = face_recognition.compare_faces(models, new_face, DISTANCE_THRESHOLD)
    if any(result):
        return result.index(True)
    else: return -1

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
    op = input("Store or Detect (s/d): ").strip().lower()
    if op == 's':
        uid = int(input("User Id: "))
        cam = cv2.VideoCapture(0)
        while True:
            ret, frame = cam.read()
            #small_frame = cv2.resize(frame, (0, 0), fx=SCALE, fy=SCALE)
            face = find_single_face(frame)
            if face is not None:
                t, r, b, l = face
                #t/=SCALE; r/=SCALE; b/=SCALE; l/=SCALE
                frame = cv2.rectangle(frame, (l, t), (r, b), (255, 0, 0), 2)
            cv2.imshow('face', frame)
            if cv2.waitKey(1) == 27: break
        cv2.destroyAllWindows()
        cam.release()
        bframe = encode_base64_image(frame)
        fd = FaceData(uid, bframe)
        print(upload_internal(fd).toJson())
    elif op == 'd':
        ids, models = load_models()
        cam = cv2.VideoCapture(0)
        while True:
            ret, frame = cam.read()
            #small_frame = cv2.resize(frame, (0, 0), fx=SCALE, fy=SCALE)
            for face in find_faces(frame):
                t, r, b, l = face
                #t/=SCALE; r/=SCALE; b/=SCALE; l/=SCALE
                new_face = face_recognition.face_encodings(frame)[0]
                index = face_match(new_face, models)
                if index != -1:
                    frame = cv2.rectangle(frame, (l, t), (r, b), (0, 255, 0), 2)
                    uid = ids[index]
                    frame = cv2.putText(frame, f'User Id: {uid}', (l, (t-10 if t>10 else t+10)), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 255, 0), 2)
                else:
                    frame = cv2.rectangle(frame, (l, t), (r, b), (0, 0, 255), 2)
            cv2.imshow('tolerance=' + str(DISTANCE_THRESHOLD), frame)
            if cv2.waitKey(1) == 27: break
        cv2.destroyAllWindows()
        cam.release()
