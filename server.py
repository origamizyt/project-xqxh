from models import config, ServerMethods, Result, TcpFactory, SlotType, Serializer
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web.wsgi import WSGIResource
from twisted.web.server import Site
from twisted.python import log
from bottle import request, response
import json, time, faceupload, bottle, sys

app = bottle.Bottle()
methods = ServerMethods

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
        response.content_type = Serializer.httpContentType
        return json.dumps(get_server_info())

@app.route('/auth', method='POST')
def authenticate_client():
    response.content_type = Serializer.httpContentType
    if methods.isSessionLocked(client_addr()):
        return Result(False, error='Cannot perform authentication on a locked session.').serialize()
    if not request.forms.type:
        response.status = 400
        return Result(False,
            error="Parameter 'type' is not specified."
        ).serialize()
    elif request.forms.type == 'dog':
        username = request.forms.username
        password = request.forms.password
        remote_key = bytes.fromhex(request.forms.ecckey)
        if methods.isUserNameOccupied(username):
            response.set_header('X-Authorization', 'failed')
            return Result(False,
                error='User name is occupied by another session.'
            ).serialize()
        elif methods.dogCertificate(client_addr(), username, password):
            response.set_header('X-Authorization', 'passed')
            ecdh = methods.ecdhKeyExchange(client_addr(), remote_key)
            return Result(True,
                ecckey=ecdh.hex(),
                idhex=methods.getSession(client_addr()).getSessionHex()
            ).serialize()
        else:
            response.set_header('X-Authorization', 'failed')
            return Result(False,
                error='Incorrect user name or password.'
            ).serialize()
    elif request.form.type == 'user':
        response.set_header('X-Authorization', 'failed')
        return Result(False,
            error='Not implemented.'
        ).serialize()
    else:
        response.status = 400
        return Result(False,
            error=f"Incorrect value for parameter 'type': {request.form.type!r}."
        ).serialize()

@app.route('/prepare', method='POST')
def allocate_server_slot():
    if not authenticate(): return response401()
    response.content_type = Serializer.httpContentType
    if not request.forms.type:
        response.status = 400
        return Result(False,
            error="Parameter 'type' is not specified."
        ).serialize()
    elif request.forms.type == 'large':
        spare = methods.prepareLargeDataTransfer(client_addr())
        if spare:
            return Result(True).serialize()
        else:
            return Result(False,
                error='Server slot is occupied by another session.'
            ).serialize()
    elif request.forms.type == 'sensitive':
        secret = methods.prepareSensitiveDataTransfer(client_addr())
        if secret is None:
            return Result(False, error='Server slot is occupied by another session.').serialize()
        else:
            return Result(True,
                secret=methods.base64encode(secret)
            ).serialize()
    else:
        response.status = 400
        return Result(False,
            error="Invalid value for parameter 'type'."
        ).serialize()

@app.route('/release', methods='POST')
def release_server_slot():
    if not authenticate(): return response401()
    slot = methods.getTcpSlot(client_addr())
    if slot.isOccupied():
        return Result(False, 
            error='Server slot is being occupied.'
        ).serialize()
    elif slot.getSlotType() == SlotType.TSS_UNAUTHORIZED:
        return Result(False, 
            error='Server slot not allocated yet.'
        ).serialize()
    elif slot.getSlotType() == SlotType.TSS_SENSITIVE_DATA:
        if not request.forms.secret:
            return Result(False,
                error='A secret must be specified.'
            ).serialize()
        secret = request.forms.secret
        secret = methods.base64decode(secret)
        if methods.verifySignSecret(client_addr(), secret):
            methods.releaseServerSlot(client_addr())
            return Result(True).serialize()
        else:
            return Result(False,
                error='Secret mismatch.'
            ).serialize()
    elif slot.getSlotType() == SlotType.TSS_LARGE_DATA:
        methods.releaseServerSlot(client_addr())
        return Result(True).serialize()
    else:
        return Result(False, error='Server error.').serialize()

@app.route('/end')
def quit_session():
    addr = client_addr()
    if not authenticate(): return response401()
    response.content_type = Serializer.httpContentType
    if methods.isSessionLocked(addr):
        return Result(False, error='Cannot terminate a locked session.')
    if methods.endSession(addr):
        return Result(True).serialize()
    else:
        return Result(False, error='Cannot terminate session while server slot is being occupied.').serialize()

@app.route('/lock', method='POST')
def lock_session():
    if not authenticate(): return response401()
    response.content_type = Serializer.httpContentType
    if methods.isSessionLocked(client_addr()):
        return Result(False, error='Session is already locked.').serialize()
    secret = methods.lockSession(client_addr())
    return Result(True, secret=methods.base64encode(secret)).serialize()

@app.route('/unlock', method='POST')
def unlock_session():
    if not authenticate(): return response401()
    response.content_type = Serializer.httpContentType
    if not methods.isSessionLocked(client_addr()):
        return Result(False, error='Session is not locked yet.').serialize()
    secret = request.forms.secret
    if secret is None:
        return Result(False, error='A secret must be provided.').serialize()
    secret = methods.base64decode(secret)
    if methods.verifyLockSecret(client_addr(), secret):
        methods.unlockSession(client_addr())
        return Result(True).serialize()
    else:
        return Result(False, error='Secret mismatch.').serialize()

def get_site():
    res = WSGIResource(reactor, reactor.getThreadPool(), app)
    site = Site(res)
    return site