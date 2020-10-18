from models import config, ServerMethods
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource
from bottle import request, response
import json, time, faceupload, bottle, sys

app = bottle.Bottle()
methods = ServerMethods()

def client_addr():
    return request.environ.get('HTTP_X_FORWARDED_FOR') or request.environ.get('REMOTE_ADDR')

def authenticate():
    addr = client_addr()
    data = request.headers.get('X-Authorization')
    if data is None: return False
    data = methods.base64decode(data)
    return methods.authenticate(addr, data)

def get_server_info():
    return {
        'serverName': config.server.name,
        'serverTime': int(time.time() * 1000)
    }

@app.route('/')
def root():
    if not authenticate():
        methods.clearPermission(client_addr())
        response.status = 401
        return ''
    else:
        response.content_type = 'application/json'
        return json.dumps(get_server_info())

@app.route('/auth', method='POST')
def auth():
    response.content_type = 'application/json'
    if authenticate():
        response.set_header('X-Authorization', 'passed')
        return json.dumps({
            'success': True
        })
    else:
        if not request.forms.type:
            response.status = 400
            return json.dumps({
                'success': False,
                'error': "Parameter 'type' is not specified."
            })
        elif request.forms.type == 'dog':
            username = request.forms.username
            password = request.forms.password
            if methods.dogCertificate(username, password):
                response.set_header('X-Authorization', 'passed')
                return json.dumps({
                    'success': True,
                    'hmac': methods.base64encode(methods.getHMacKey()),
                    'idhex': methods.newSession(client_addr())
                })
            else:
                response.set_header('X-Authorization', 'failed')
                return json.dumps({
                    'success': False,
                    'error': 'Incorrect user name or password.'
                })
        elif request.form.type == 'user':
            response.set_header('X-Authorization', 'failed')
            return json.dumps({
                'success': False,
                'error': 'Not implemented.'
            })
        else:
            response.status = 400
            return json.dumps({
                'success': False,
                'error': f"Incorrect value for parameter 'type': {request.form.type!r}."
            })

@app.route('/facedetect')
def face_detect():
    image_data = faceupload.decode_base64_image(bottle.request.body.read())
    faces = faceupload.find_faces(image_data)
    feedback = json.dumps(faces)
    response.set_header('Content-type', 'application/json')
    return [feedback.encode()]

@app.route('/faceupload')
def face_upload():
    data = dict(bottle.request.forms)
    response.set_header('Content-type', 'application/json')
    return [json.dumps(data).encode()]

@app.route('/endsession')
def quit_session():
    addr = client_addr()
    methods.endSession(addr)
    response.set_header('Content-type', 'application/json')
    return json.dumps({
        'success': True
    })

@app.route('/exitserver')
def quit_server():
    sys.exit()

methods.launch()