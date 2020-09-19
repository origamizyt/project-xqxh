from wsgiref.simple_server import make_server
from urllib.parse import parse_qs
from models import config
import json, time, faceupload

def get_server_info():
    return {
        'serverName': config.server.name,
        'serverTime': int(time.time() * 1000)
    }

def read_content(environ):
    length = int(environ.get('CONTENT_LENGTH', 0))
    return environ['wsgi.input'].read(length)

def root(environ, start_response):
    start_response("200 OK", [('Content-type', 'application/json')])
    return [json.dumps(get_server_info()).encode()]

def face_detect(environ, start_response):
    content = read_content(environ)
    data = parse_qs(content)
    feedback = ''
    if 'face' in data:
        image_data = faceupload.decode_base64_image(data['face'][0])
        faces = faceupload.find_faces(image_data)
        start_response('200 OK', [('Content-type': 'application/json')])
        feedback = json.dumps(faces)
    else:
        start_response('400 Bad Request', [])
        feedback = "Parameter 'face' not found."
    return [feedback.encode()]


def face_upload(environ, start_response):
    content = read_content(environ).decode()
    data = parse_qs(content)
    start_response("200 OK", [('Content-type', 'application/json')])
    return [json.dumps(data).encode()]

data = {'success': True, 'error': None}
pages = {
    '/': root,
    '/faceupload': face_upload
    }

def application(environ, start_response):
    path = environ['PATH_INFO'].lower()
    if path in pages:
        return pages[path](environ, start_response)
    start_response('404 NOT FOUND', [])
    return [b'']

def main():
    httpd = make_server('localhost', 5000, application)
    print("Serving WSGI on localhost:5000...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Server aborted.")

if __name__ == "__main__": main()
