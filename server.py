from models import config, ServerMethods, Result, TcpFactory
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web.wsgi import WSGIResource
from bottle import request, response
import json, time, faceupload, bottle, sys

app = bottle.Bottle()
methods = ServerMethods.getInstance()

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
        'serverTime': int(time.time() * 1000),
        'loggedUser': methods.getSession(client_addr()).getUserName()
    }

def response401():
    methods.clearPermission(client_addr())
    response.status = 401
    return ''

@app.route('/')
def root():
    if not authenticate(): return response401()
    else:
        response.content_type = 'application/json'
        return json.dumps(get_server_info())

@app.route('/auth', method='POST')
def auth():
    response.content_type = 'application/json'
    if not request.forms.type:
        response.status = 400
        return Result(False,
            error="Parameter 'type' is not specified."
        ).toJson()
    elif request.forms.type == 'dog':
        username = request.forms.username
        password = request.forms.password
        if methods.isUserNameOccupied(username):
            response.set_header('X-Authorization', 'failed')
            return Result(False,
                error='User name is occupied by another session.'
            ).toJson()
        elif methods.dogCertificate(client_addr(), username, password):
            response.set_header('X-Authorization', 'passed')
            return Result(True,
                hmac=methods.base64encode(methods.getHMacKey()),
                idhex=methods.getSession(client_addr()).getSessionHex()
            ).toJson()
        else:
            response.set_header('X-Authorization', 'failed')
            return Result(False,
                error='Incorrect user name or password.'
            ).toJson()
    elif request.form.type == 'user':
        response.set_header('X-Authorization', 'failed')
        return Result(False,
            error='Not implemented.'
        ).toJson()
    else:
        response.status = 400
        return Result(False,
            error=f"Incorrect value for parameter 'type': {request.form.type!r}."
        ).toJson()

@app.route('/atss', method='POST')
def allocate_tcp_server_slot():
    if not authenticate(): return response401()
    response.content_type = 'application/json'
    if not request.forms.type:
        response.status = 400
        return Result(False,
            error="Parameter 'type' is not specified."
        ).toJson()
    elif request.forms.type == 'large':
        spare = methods.prepareLargeDataTransfer(client_addr())
        if spare:
            return Result(True).toJson()
        else:
            return Result(False,
                error='Server slot is occupied by another session.'
            ).toJson()
    elif request.forms.type == 'sensitive':
        spare = methods.prepareSensitiveDataTransfer(client_addr())
        if not spare:
            return Result(False, error='Server slot is occupied by another session.').toJson()
        remote_key = methods.base64decode(request.forms.ecckey)
        public_key = methods.ecdhKeyExchange(client_addr(), remote_key)
        if public_key is None:
            return Result(False,
                error='Server slot is occupied by another session.'
            )
        else:
            return Result(True,
                ecckey=methods.base64encode(public_key)
            ).toJson()
    else:
        response.status = 400
        return Result(False,
            error="Invalid value for parameter 'type'."
        ).toJson()

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
    response.set_header('Content-type', 'application/json')
    if methods.endSession(addr):
        return Result(True).toJson()
    else:
        return Result(False, error='Cannot terminate session while server slot is being occupied.').toJson()

factory = TcpFactory()
reactor.listenTCP(5050, factory)
updateHMac = LoopingCall(methods.updateHMacKey)
# updateHMac.start(600)