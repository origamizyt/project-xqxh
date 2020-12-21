from models import config, ServerMethods, Result, TcpFactory, SlotType, Serializer, DogPermission, HumanPermission
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web.wsgi import WSGIResource
from twisted.web.server import Site
from twisted.python import log
from bottle import request, response
from debug_utils import DebugMiddleware
from errors import ErrorCode
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
        return Serializer.serialize(get_server_info())

@app.route('/start', method='GET')
def start_session():
    response.content_type = Serializer.httpContentType
    session = methods.getSession(client_addr())
    return Result(True, idhex=session.getSessionHex())

@app.route('/auth', method='POST')
def authenticate_client():
    response.content_type = Serializer.httpContentType
    if methods.isSessionLocked(client_addr()):
        return Result(False, error=ErrorCode.ERR_LOCKED_SESSION).serialize()
    if not request.forms.type:
        response.status = 400
        return Result(False, error=ErrorCode.ERR_MISSING_PARAMETER).serialize()
    elif request.forms.type == 'dog':
        username = request.forms.username
        password_base64 = request.forms.password
        password = methods.base64decode(password_base64)
        remote_key = bytes.fromhex(request.forms.ecckey)
        if methods.isUserNameOccupied(username):
            response.set_header('X-Authorization', 'failed')
            return Result(False,
                error=ErrorCode.ERR_OCCUPIED_USERNAME
            ).serialize()
        elif methods.dogCertificate(client_addr(), username, password):
            response.set_header('X-Authorization', 'passed')
            ecdh = methods.ecdhKeyExchange(client_addr(), remote_key)
            methods.grantPermission(client_addr(), DogPermission())
            return Result(True,
                ecckey=ecdh.hex(),
                idhex=methods.getSession(client_addr()).getSessionHex()
            ).serialize()
        else:
            response.set_header('X-Authorization', 'failed')
            return Result(False,
                error=ErrorCode.ERR_INCORRECT_USER
            ).serialize()
    elif request.forms.type == 'user':
        username = request.forms.username
        password_base64 = request.forms.password
        password = methods.base64decode(password_base64)
        remote_key = bytes.fromhex(request.forms.ecckey)
        if methods.isUserNameOccupied(username):
            response.set_header('X-Authorization', 'failed')
            return Result(False,
                error=ErrorCode.ERR_OCCUPIED_USERNAME
            ).serialize()
        elif methods.userCertificate(client_addr(), username, password):
            response.set_header('X-Authorization', 'passed')
            ecdh = methods.ecdhKeyExchange(client_addr(), remote_key)
            methods.grantPermission(client_addr(), HumanPermission(username))
            return Result(True,
                ecckey=ecdh.hex(),
                idhex=methods.getSession(client_addr()).getSessionHex()
            ).serialize()
        else:
            response.set_header('X-Authorization', 'failed')
            return Result(False,
                error=ErrorCode.ERR_INCORRECT_USER
            ).serialize()
    else:
        response.status = 400
        return Result(False,
            error=ErrorCode.ERR_INVALID_VALUE
        ).serialize()

@app.route('/user', method='POST')
def user_operation():
    response.content_type = Serializer.httpContentType
    if not request.forms.type:
        response.status = 400
        return Result(False,
            error=ErrorCode.ERR_MISSING_PARAMETER
        ).serialize()
    elif request.forms.type == 'register':
        username = request.forms.username
        password_base64 = request.forms.password
        password = methods.base64decode(password)
        if not methods.isValidUser(username, password):
            return Result(False,
                error=ErrorCode.ERR_USER_INVALID
            ).serialize()
        if methods.userExists(username):
            return Result(False, 
                error=ErrorCode.ERR_USER_EXISTS
            ).serialize()
        uid = methods.registerUser(username, password)
        return Result(True, userid=uid).serialize()
    elif request.forms.type == 'verify':
        if not authenticate(): return response401()
        username = request.forms.username
        password_hmac = request.forms.password
        password_hmac = methods.base64decode(password_hmac)
        if not methods.hasUserPermissionFor(client_addr(), username):
            return Result(False, error=ErrorCode.ERR_PERMISSION_INSUFFICIENT).serialize()
        return Result(True, result=methods.verifyUser(client_addr(), username, password_hmac)).serialize()
    elif request.forms.type == 'query':
        if not authenticate(): return response401()
        username = request.forms.username
        password_hmac = request.forms.password
        password_hmac = methods.base64decode(password_hmac)
        if not methods.hasUserPermissionFor(client_addr(), username):
            return Result(False, error=ErrorCode.ERR_PERMISSION_INSUFFICIENT).serialize()
        if not methods.verifyUser(client_addr(), username, password_hmac):
            return Result(False, error=ErrorCode.ERR_INCORRECT_USER).serialize()
        return Result(True, userid=methods.getUserId(username)).serialize()
    else:
        response.status = 400
        return Result(False,
            error=ErrorCode.ERR_INVALID_VALUE
        ).serialize()

@app.route('/prepare', method='POST')
def allocate_server_slot():
    if not authenticate(): return response401()
    response.content_type = Serializer.httpContentType
    if not request.forms.type:
        response.status = 400
        return Result(False,
            error=ErrorCode.ERR_MISSING_PARAMETER
        ).serialize()
    elif request.forms.type == 'large':
        spare = methods.prepareLargeDataTransfer(client_addr())
        if spare:
            return Result(True).serialize()
        else:
            return Result(False,
                error=ErrorCode.ERR_OCCUPIED_SLOT
            ).serialize()
    elif request.forms.type == 'sensitive':
        secret = methods.prepareSensitiveDataTransfer(client_addr())
        if secret is None:
            return Result(False, error=ErrorCode.ERR_OCCUPIED_SLOT).serialize()
        else:
            return Result(True,
                secret=methods.base64encode(secret)
            ).serialize()
    else:
        response.status = 400
        return Result(False,
            error=ErrorCode.ERR_INVALID_VALUE
        ).serialize()

@app.route('/release', methods='POST')
def release_server_slot():
    if not authenticate(): return response401()
    slot = methods.getTcpSlot(client_addr())
    if slot.isOccupied():
        return Result(False, 
            error=ErrorCode.ERR_OCCUPIED_SLOT
        ).serialize()
    elif slot.getSlotType() == SlotType.TSS_UNAUTHORIZED:
        return Result(False, 
            error=ErrorCode.ERR_UNALLOCATED_SLOT
        ).serialize()
    elif slot.getSlotType() == SlotType.TSS_SENSITIVE_DATA:
        if not request.forms.secret:
            return Result(False,
                error=ErrorCode.ERR_NO_SECRET_SPECIFIED
            ).serialize()
        secret = request.forms.secret
        secret = methods.base64decode(secret)
        if methods.verifySignSecret(client_addr(), secret):
            methods.releaseServerSlot(client_addr())
            return Result(True).serialize()
        else:
            return Result(False,
                error=ErrorCode.ERR_SECRET_MISMATCH
            ).serialize()
    elif slot.getSlotType() == SlotType.TSS_LARGE_DATA:
        methods.releaseServerSlot(client_addr())
        return Result(True).serialize()
    else:
        return Result(False, error=ErrorCode.ERR_SERVER_ERROR).serialize()

@app.route('/end')
def quit_session():
    addr = client_addr()
    if not authenticate(): return response401()
    response.content_type = Serializer.httpContentType
    if methods.isSessionLocked(addr):
        return Result(False, error=ErrorCode.ERR_LOCKED_SESSION)
    if methods.endSession(addr):
        return Result(True).serialize()
    else:
        return Result(False, error=ErrorCode.ERR_OCCUPIED_SLOT).serialize()

@app.route('/lock', method='POST')
def lock_session():
    if not authenticate(): return response401()
    response.content_type = Serializer.httpContentType
    if methods.isSessionLocked(client_addr()):
        return Result(False, error=ErrorCode.ERR_LOCKED_SESSION).serialize()
    secret = methods.lockSession(client_addr())
    return Result(True, secret=methods.base64encode(secret)).serialize()

@app.route('/unlock', method='POST')
def unlock_session():
    if not authenticate(): return response401()
    response.content_type = Serializer.httpContentType
    if not methods.isSessionLocked(client_addr()):
        return Result(False, error=ErrorCode.ERR_UNLOCKED_SESSION).serialize()
    secret = request.forms.secret
    if secret is None:
        return Result(False, error=ErrorCode.ERR_NO_SECRET_SPECIFIED).serialize()
    secret = methods.base64decode(secret)
    if methods.verifyLockSecret(client_addr(), secret):
        methods.unlockSession(client_addr())
        return Result(True).serialize()
    else:
        return Result(False, error=ErrorCode.ERR_SECRET_MISMATCH).serialize()

@app.route('/update', method='GET')
@DebugMiddleware
def update_config():
    config.reloadFile()
    response.content_type = Serializer.httpContentType
    return Result(True).serialize()

def get_site():
    res = WSGIResource(reactor, reactor.getThreadPool(), app)
    site = Site(res)
    return site