import cv2
from models import config
from twisted.python import log

class DebugFeature:
    def __init__(self, func):
        self.func = func
    def __call__(self, *args, **kwargs):
        if config.server.debug:
            return self.func(*args, **kwargs)
        return None
    def __repr__(self):
        return f'DebugFeature({self.func.__name__})'
    def __str__(self):
        return str(self.func)

@DebugFeature
def prepare_detect_image(addr):
    cv2.namedWindow(f'face-detect-{addr}')

@DebugFeature
def prepare_recognize_image(addr):
    cv2.namedWindow(f'face-recognize-{addr}')

@DebugFeature
def show_face_detect_image(addr, frame, data):
    frame = cv2.resize(frame, (0, 0), fx=2, fy=2)
    if data['success']:
        for t, r, b, l in data['positions']:
            frame = cv2.rectangle(frame, (l*2, t*2), (r*2, b*2), (255, 0, 0), 2)
    else:
        cv2.putText(frame, 'No face detected.', (10, 20), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 0, 255), 1)
    cv2.imshow(f'face-detect-{addr}', frame)
    cv2.waitKey(1)

@DebugFeature
def show_face_recognize_image(addr, frame, data):
    frame = cv2.resize(frame, (0, 0), fx=2, fy=2)
    if data['success']:
        for face in data['faces']:
            t, r, b, l = face['position']
            if face['found']:
                username = face['user']['username']
                uid = face['user_id']
                distance = face['distance']
                frame = cv2.rectangle(frame, (l*2, t*2), (r*2, b*2), (0, 255, 0), 2)
                frame = cv2.putText(frame, f'User Id: {uid}', (l*2, (t*2-50 if t*2>50 else t*2+50)), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 255, 0), 1)
                frame = cv2.putText(frame, f'User Name: {username}', (l*2, (t*2-30 if t*2>30 else t*2+30)), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 255, 0), 1)
                frame = cv2.putText(frame, f'Similarity: {1-distance:.2%}', (l*2, (t*2-10 if t*2>10 else t*2+10)), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (0, 255, 0), 1)
            else:
                frame = cv2.rectangle(frame, (l*2, t*2), (r*2, b*2), (0, 0, 255), 2)
    cv2.imshow(f'face-recognize-{addr}', frame)
    cv2.waitKey(1)

@DebugFeature
def close_detect_image(addr):
    cv2.destroyWindow(f'face-detect-{addr}')

@DebugFeature
def close_recognize_image(addr):
    cv2.destroyWindow(f'face-recognize-{addr}')

@DebugFeature
def debug_log(msg):
    log.msg(msg)