# models.py
# Defines the data models used in the interface.

import json, hmac, uuid, base64, security, struct, msgpack, lzma, bz2
from errors import ErrorCode
from enum import IntEnum
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from twisted.python import log
from autobahn.twisted.websocket import WebSocketServerProtocol, WebSocketServerFactory

class Serializer:
    httpContentType = 'application/json'
    # serialization
    @staticmethod
    def serialize(data):
        return json.dumps(data)
    @staticmethod
    def deserialize(data):
        return json.loads(data)
    @staticmethod
    def serializeBinary(data):
        return msgpack.packb(data)
    @staticmethod
    def deserializeBinary(data):
        return msgpack.unpackb(data)
    # compression
    # uses bz2 for small compression and lzma for large compression
    @staticmethod
    def compress(data):
        return lzma.compress(data) if config.server.dataCompression else data
    @staticmethod
    def decompress(data):
        return lzma.decompress(data) if config.server.dataCompression else data
    @staticmethod
    def compressLarge(data):
        return bz2.compress(data) if config.server.largeDataCompression else data
    @staticmethod
    def decompressLarge(data):
        return bz2.decompress(data) if config.server.largeDataCompression else data

class Config:
    def __init__(self, data={}):
        self.data = data
        self.file = None
    def __getattr__(self, name):
        item = self.data[name]
        if isinstance(item, (dict, list, tuple)):
            return Config(item)
        else:
            return item
    def __getitem__(self, index):
        item = self.data[index]
        if isinstance(item, (dict, list, tuple)):
            return Config(item)
        else:
            return item
    def __iter__(self):
        return iter(self.data)
    def loadFile(self, filename):
        self.file = filename
        with open(filename) as config_file:
            self.data = json.load(config_file)
    def reloadFile(self):
        self.loadFile(self.file)

config = Config()
config.loadFile('config.json')

class Result(dict):
    def __init__(self, success, **kwargs):
        super().__init__(success=success, **kwargs)
    def serialize(self):
        return Serializer.serialize(dict(self))
    def serializeBinary(self):
        return Serializer.serializeBinary(dict(self))
    def __str__(self):
        return self.serialize()

class User:
    def __init__(self, **kwargs):
        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
    def toDict(self):
        return {
            'username': self.username
        }

class UploadResult(Result):
    def __init__(self, success, data):
        super().__init__(success, data=data)

class FaceData:
    def __init__(self, user_id, data):
        self.user_id = user_id
        self.data = data

import database as db, faceupload as fu, debug_utils as utils

class PermissionType(IntEnum):
    BOOLEAN = 0
    INTEGER = 1
    NULLABLE_INTEGER = 2
    STRING = 3
    NULLABLE_STRING = 4

class PermissionItem:
    def __init__(self, ptype, pvalue):
        self.permissionType = ptype
        self.permissionValue = pvalue
    def getType(self):
        return self.permissionType
    def getValue(self):
        return self.permissionValue
    def __repr__(self):
        return f'PermissionItem(type={self.permissionType!r}, value={self.permissionValue!r})'
    def __str__(self):
        return str(self.permissionValue)

class Permission:
    def has(self, name):
        perm = getattr(self, name, None)
        return isinstance(perm, PermissionItem)
    def get(self, name):
        if not self.has(name):
            raise AttributeError(f'No permission named {name!r}')
        perm = getattr(self, name)
        return perm
    def getValue(self, name):
        perm = self.get(name)
        return perm.getValue()
    def getType(self, name):
        perm = self.get(name)
        return perm.getType()

class NoPermission(Permission):
    faceDetect = PermissionItem(PermissionType.BOOLEAN, False)
    faceRecognition = PermissionItem(PermissionType.BOOLEAN, False)
    faceUpload = PermissionItem(PermissionType.BOOLEAN, False)
    userData = PermissionItem(PermissionType.NULLABLE_STRING, None)
    accessMaps = PermissionItem(PermissionType.BOOLEAN, False)
    planRoute = PermissionItem(PermissionType.BOOLEAN, False)
    accessLocations = PermissionItem(PermissionType.BOOLEAN, False)

class DogPermission(Permission):
    faceDetect = PermissionItem(PermissionType.BOOLEAN, True)
    faceRecognition = PermissionItem(PermissionType.BOOLEAN, True)
    faceUpload = PermissionItem(PermissionType.BOOLEAN, False)
    userData = PermissionItem(PermissionType.NULLABLE_STRING, '*')
    accessMaps = PermissionItem(PermissionType.BOOLEAN, True)
    planRoute = PermissionItem(PermissionType.BOOLEAN, True)
    accessLocations = PermissionItem(PermissionType.BOOLEAN, True)

class HumanPermission(Permission):
    faceDetect = PermissionItem(PermissionType.BOOLEAN, True)
    faceRecognition = PermissionItem(PermissionType.BOOLEAN, False)
    faceUpload = PermissionItem(PermissionType.BOOLEAN, True)
    accessMaps = PermissionItem(PermissionType.BOOLEAN, False)
    planRoute = PermissionItem(PermissionType.BOOLEAN, False)
    accessLocations = PermissionItem(PermissionType.BOOLEAN, False)
    def __init__(self, user):
        self.userData = PermissionItem(PermissionType.NULLABLE_STRING, user)

class AddressMap(dict):
    def isUserNameOccupied(self, username):
        return any(username == x.getUserName() for x in self.values())
    def __setitem__(self, key, item):
        if not isinstance(key, str) or not isinstance(item, Session):
            raise TypeError('Key must be str and value must be Session.')
        super().__setitem__(key, item)
    def setdefault(self, key, default=None):
        if not isinstance(key, str) or not isinstance(default, Session):
            raise TypeError('Key must be str and default must be Session.')
        return super().setdefault(key, default)

class TcpUsingList(dict):
    def __setitem__(self, key, item):
        if not isinstance(key, str) or not isinstance(item, TcpServerSlot):
            raise TypeError('Key must be str and value must be TcpServerSlot.')
        super().__setitem__(key, item)
    def setdefault(self, key, default=None):
        if not isinstance(key, str) or not isinstance(default, TcpServerSlot):
            raise TypeError('Key must be str and default must be TcpServerSlot.')
        return super().setdefault(key, default)

class Session:
    def __init__(self):
        self.sessionId = uuid.uuid4()
        self.attributes = SessionAttributes(
            authorized=False,
            locked=False)
        self.permission = NoPermission()
        self.eccKeys = security.EccKeys(ServerMethods.getPrivateKey().secret)
    def getEccKeys(self):
        return self.eccKeys
    def ecdhKeyExchange(self, remote_key):
        self.eccKeys.setRemoteKey(remote_key)
        return self.eccKeys.getPublicKey()
    def getSessionHex(self):
        return self.sessionId.hex
    def getSessionBytes(self):
        return self.sessionId.bytes
    def grantPermission(self, permission):
        self.permission = permission
    def clearPermission(self):
        self.permission = NoPermission()
    def getUserName(self):
        return self.attributes.getAttribute('username')
    def setUserName(self, username):
        self.attributes.setAttribute('username', username)
        self.attributes.setAttribute('authorized', True)
    def isAuthorized(self):
        return self.attributes.getAttribute('authorized')
    def getAttribute(self, name, default=None):
        return self.attributes.getAttribute(name, default)
    def setAttribute(self, name, value):
        self.attributes.setAttribute(name, value)
    def getHMacKey(self):
        return self.eccKeys.getSharedSecret()
    def isKeyExchangePerformed(self):
        return self.eccKeys.keyExchanged()

class SessionAttributes:
    def __init__(self, **kwargs):
        self.data = kwargs
    def __delattr__(self, name):
        self.setAttribute(name, None)
    def getAttribute(self, name, default=None):
        return self.data.get(name, default)
    def setAttribute(self, name, value):
        self.data[name] = value
        if self.data[name] is None:
            del self.data[name]

class ServerMethods:
    def __init__(self):
        self.addressMap = AddressMap()
        self.usingTcp = TcpUsingList()
        self.privateKey = security.generate_private_key()
    def ecdhKeyExchange(self, addr, remote_key):
        if addr not in self.addressMap: return None
        ecdh = self.addressMap[addr].ecdhKeyExchange(remote_key)
        utils.debug_log(f'Performed ECDH key exchange with {addr}')
        utils.debug_log(f'Using shared secret {self.addressMap[addr].getHMacKey()} as HMAC key.')
        return ecdh
    def releaseServerSlot(self, addr):
        if addr in self.usingTcp:
            del self.usingTcp[addr]
    def prepareSensitiveDataTransfer(self, addr):
        slot = self.usingTcp.setdefault(addr, EncryptedTcpServerSlot(addr, SlotType.TSS_SENSITIVE_DATA))
        return None if slot.isOccupied() else slot.secret
    def prepareLargeDataTransfer(self, addr):
        slot = self.usingTcp.setdefault(addr, TcpServerSlot(addr, SlotType.TSS_LARGE_DATA))
        return not slot.isOccupied()
    def getTcpSlot(self, addr):
        return self.usingTcp.get(addr, TcpServerSlot(addr, SlotType.TSS_UNAUTHORIZED))
    def updatePrivateKey(self):
        self.privateKey = security.generate_private_key()
    def getPrivateKey(self):
        return self.privateKey
    def getSession(self, addr):
        return self.addressMap.setdefault(addr, Session())
    def endSession(self, addr):
        if addr in self.usingTcp:
            if self.usingTcp[addr].isOccupied():
                return False
            self.releaseServerSlot(addr)
        if addr in self.addressMap:
            del self.addressMap[addr]
        return True
    def authenticate(self, addr, data=None):
        if addr not in self.addressMap: return False
        session = self.addressMap[addr]
        if not session.isKeyExchangePerformed(): return False
        return security.certify_hmac_digest(session.getHMacKey(), session.getSessionBytes(), data)
    def grantPermission(self, addr, permission):
        if addr not in self.addressMap: return
        self.addressMap[addr].grantPermission(permission)
    def clearPermission(self, addr):
        if addr not in self.addressMap: return
        self.addressMap[addr].clearPermission()
    def dogCertificate(self, addr, dog_name, password):
        if db.certify_dog(dog_name, password):
            self.addressMap.setdefault(addr, Session()).setUserName(dog_name)
            return True
        else: return False
    def userCertificate(self, addr, username, password):
        if db.certify_user(username, password):
            self.addressMap.setdefault(addr, Session()).setUserName(username)
            return True
        else: return False
    def isUserNameOccupied(self, username):
        return self.addressMap.isUserNameOccupied(username)
    def isSessionLocked(self, addr):
        session = self.getSession(addr)
        if not session: return False
        return session.getAttribute('locked')
    def lockSession(self, addr):
        session = self.getSession(addr)
        session.setAttribute('locked', True)
        secret = security.generate_secret()
        session.setAttribute('lockSecret', secret)
        return secret
    def unlockSession(self, addr):
        session = self.getSession(addr)
        session.setAttribute('locked', False)
        session.setAttribute('lockSecret', None)
    def verifyLockSecret(self, addr, data=None):
        if addr not in self.addressMap: return False
        return security.certify_hmac_digest(self.addressMap[addr].getHMacKey(), self.addressMap[addr].getAttribute('lockSecret'), data)
    def verifySignSecret(self, addr, data=None):
        if addr not in self.usingTcp: return False
        slot = self.usingTcp[addr]
        return security.certify_hmac_digest(self.addressMap[addr].getHMacKey(), slot.getSecret(), data)
    def hasPermission(self, addr, name):
        if addr not in self.addressMap: return False
        return self.addressMap[addr].permission.has(name)
    def hasUserPermissionFor(self, addr, username):
        perm = self.getPermission(addr, 'userData')
        if perm.getValue() == '*': return True
        return perm.getValue() == username
    def getPermission(self, addr, name):
        if addr not in self.addressMap: return None
        return self.addressMap[addr].permission.get(name)
    def verifyUser(self, addr, username, password_hmac):
        if not self.userExists(username): return False
        return security.certify_hmac_digest(self.addressMap[addr].getHMacKey(), db.get_user_by_username(username).password.encode(), password_hmac)
    @staticmethod
    def getUserId(username):
        return db.get_user_id(username)
    @staticmethod
    def userExists(username):
        return db.user_exists(username)
    @staticmethod
    def registerUser(username, password):
        return db.register_user(User(username=username, password=password))
    @staticmethod
    def isValidUser(username, password):
        return bool(username.strip() and password.strip())
    @staticmethod
    def base64decode(data):
        return base64.b64decode(data.encode('iso-8859-1'))
    @staticmethod
    def base64encode(data):
        return base64.b64encode(data).decode('iso-8859-1')

ServerMethods = ServerMethods()

class SlotType(IntEnum):
    TSS_UNAUTHORIZED = 0
    TSS_SENSITIVE_DATA = 1
    TSS_LARGE_DATA = 2

class TcpServerSlot:
    def __init__(self, address, slotType):
        self.address = address
        self.slotType = slotType
        self.occupied = False
    def getSlotType(self):
        return self.slotType
    def setSlotType(self, newSlotType):
        self.slotType = newSlotType
    def occupy(self):
        self.occupied = True
    def isOccupied(self):
        return self.occupied
    def canUseTcp(self):
        return self.slotType != SlotType.TSS_UNAUTHORIZED
    def __repr__(self):
        return f'TcpServerSlot({self.address}, {self.slotType})'

class EncryptedTcpServerSlot(TcpServerSlot):
    def __init__(self, address, slotType):
        super().__init__(address, slotType)
        self.secret = security.generate_secret()
    def getSecret(self):
        return self.secret

class TcpProtocol(Protocol):
    def __init__(self, slot):
        self.slot = slot
        self.extraData = {}
    def connectionLost(self, reason):
        ServerMethods.releaseServerSlot(self.slot.address)

class StructHeaderTcpProtocol(TcpProtocol):
    def __init__(self, slot):
        super().__init__(slot)
        self.buffer = b''
        self.length = 0
    def dataReceived(self, data):
        if not self.length:
            header = data[:5]
            self.length, self.isHeader = struct.unpack('>I?', header)
            data = data[5:]
        self.buffer += data
        if len(self.buffer) >= self.length > 0:
            self.process(self.buffer[:self.length], self.isHeader)
            self.buffer = self.buffer[self.length:]
            self.length = 0
            if self.buffer:
                header = self.buffer[:5]
                self.buffer = self.buffer[5:]
                self.length, self.isHeader = struct.unpack('>I?', header)
    def process(self, data, isHeader):
        pass

class SensitiveDataTcpProtocol(StructHeaderTcpProtocol):
    def __init__(self, slot):
        super().__init__(slot)
        self.verified = False
        self.handler = None
        self.keys = ServerMethods.getSession(slot.address).getEccKeys()
        self.type = None
    def checkPermission(self, name):
        perm = ServerMethods.getPermission(self.slot.address, name)
        return perm.getValue()
    def process(self, line, isHeader):
        if isHeader:
            line = Serializer.decompress(line)
            line = self.keys.decrypt(line)
            if not self.verified:
                self.handshake(line)
            else:
                self.processHeader(line)
        elif self.handler:
            line = self.keys.decrypt(line)
            self.send(self.handler(line))
        else:
            self.send(Result(False, error=ErrorCode.ERR_NO_HANDLER).serializeBinary())
    def faceDetect(self, data):
        data = fu.decode_png(data)
        pos = fu.find_faces(data)
        if len(pos) > 0:
            result = Result(True, positions=pos)
        else:
            result = Result(False)
        utils.show_face_detect_image(self.slot.address, data, result)
        return result.serializeBinary()
    def faceRecognize(self, data):
        data = fu.decode_png(data)
        faces = []
        for face in fu.find_faces(data):
            new_face = fu.face_encodings(data, [face])
            ids, models = self.extraData.get('ids', []), self.extraData.get('models', [])
            index, distance = fu.face_match(new_face, models)
            if index >= 0:
                faces.append({'found': True, 'position': face, 'user_id': ids[index], 'user': db.get_user(ids[index]).toDict(), 'distance': distance})
            else:
                faces.append({'found': False, 'position': face})
        if len(faces) == 0:
            result = Result(False)
        else:
            result = Result(True, faces=faces)
        utils.show_face_recognize_image(self.slot.address, data, result)
        return result.serializeBinary()
    def faceUpload(self, data):
        user_id = self.extraData.get('user_id')
        if user_id is None:
            return Result(False, error=ErrorCode.ERR_MISSING_PARAMETER).serializeBinary()
        data = fu.decode_png(data)
        result = fu.upload(data, user_id)
        return result.serializeBinary()
    def send(self, data):
        data = self.keys.encrypt(data)
        data = Serializer.compress(data)
        length = len(data)
        header = struct.pack('>I', length)
        self.transport.write(header + data)
    def processHeader(self, data):
        data = msgpack.loads(data)
        signature = data.get('signature')
        if not signature:
            self.send(Result(False, error=ErrorCode.ERR_NO_SIGNATURE_SPECIFIED).serializeBinary())
            return
        if not self.keys.verifySignature(signature, self.slot.secret):
            self.send(Result(False, error=ErrorCode.ERR_SIGNATURE_MISMATCH).serializeBinary())
            return
        op = data.get('operation')
        if not op:
            self.send(Result(False, error=ErrorCode.ERR_MISSING_PARAMETER).serializeBinary())
            return
        if op == 'switch':
            to = data.get('type').lower()
            if to == self.type:
                self.send(Result(False, error=ErrorCode.ERR_SAME_DATATYPE).serializeBinary())
                return
            if to == 'detect':
                if not self.checkPermission('faceDetect'):
                    self.send(Result(False, error=ErrorCode.ERR_PERMISSION_INSUFFICIENT).serializeBinary())
                    return
                if self.type == 'recognize':
                    utils.close_recognize_image(self.slot.address)
                self.type = 'detect'
                self.handler = self.faceDetect
                utils.prepare_detect_image(self.slot.address)
            elif to == 'recognize':
                if not self.checkPermission('faceRecognize'):
                    self.send(Result(False, error=ErrorCode.ERR_PERMISSION_INSUFFICIENT).serializeBinary())
                    return
                if self.type == 'detect':
                    utils.close_detect_image(self.slot.address)
                self.type = 'recognize'
                self.handler = self.faceRecognize
                utils.prepare_recognize_image(self.slot.address)
            elif to == 'upload':
                if not self.checkPermission('faceUpload'):
                    self.send(Result(False, error=ErrorCode.ERR_PERMISSION_INSUFFICIENT).serializeBinary())
                    return
                if self.type == 'detect':
                    utils.close_detect_image(self.slot.address)
                elif self.type == 'recognize':
                    utils.close_recognize_image(self.slot.address)
                self.type = 'upload'
                self.handler = self.faceUpload
                self.extraData['user_id'] = data.get('userid')
            else:
                self.send(Result(False, error=ErrorCode.ERR_INVALID_VALUE).serializeBinary())
                return
            self.send(Result(True).serializeBinary())
            return
        else:
            self.send(Result(False, error=ErrorCode.ERR_INVALID_VALUE).serializeBinary())
    def handshake(self, data):
        data = msgpack.loads(data)
        signature = data.get('signature')
        if not signature:
            self.send(Result(False, error=ErrorCode.ERR_NO_SIGNATURE_SPECIFIED).serializeBinary())
            self.transport.loseConnection()
            return
        if not self.keys.verifySignature(signature, self.slot.secret):
            self.send(Result(False, error=ErrorCode.ERR_SIGNATURE_MISMATCH).serializeBinary())
            self.transport.loseConnection()
            return
        self.type = data.get('type').lower()
        if not self.type:
            self.send(Result(False, error=ErrorCode.ERR_MISSING_PARAMETER).serializeBinary())
            self.transport.loseConnection()
            return
        if self.type == 'detect':
            if not self.checkPermission('faceDetect'):
                self.send(Result(False, error=ErrorCode.ERR_PERMISSION_INSUFFICIENT).serializeBinary())
                self.transport.loseConnection()
                return
            self.handler = self.faceDetect
            utils.prepare_detect_image(self.slot.address)
        elif self.type == 'recognize':
            if not self.checkPermission('faceRecognition'):
                self.send(Result(False, error=ErrorCode.ERR_PERMISSION_INSUFFICIENT).serializeBinary())
                self.transport.loseConnection()
                return
            self.handler = self.faceRecognize
            self.extraData['ids'], self.extraData['models'] = fu.load_models()
            utils.prepare_recognize_image(self.slot.address)
        elif self.type == 'upload':
            if not self.checkPermission('faceUpload'):
                self.send(Result(False, error=ErrorCode.ERR_PERMISSION_INSUFFICIENT).serializeBinary())
                self.transport.loseConnection()
                return
            self.handler = self.faceUpload
            self.extraData['user_id'] = data.get('userid')
        else:
            self.send(Result(False, error=ErrorCode.ERR_INVALID_VALUE).serializeBinary())
            self.transport.loseConnection()
            return
        self.verified = True
        self.send(Result(True).serializeBinary())
        utils.debug_log(f'Socket handshake with {self.slot.address} complete.')
        utils.debug_log(f'Socket type: {self.type}, remote signature: {signature}')
    def connectionLost(self, reason):
        super().connectionLost(reason)
        if self.type == 'detect':
            utils.close_detect_image(self.slot.address)
        elif self.type == 'recognize':
            utils.close_recognize_image(self.slot.address)
        
class OccupiedTcpProtocol(Protocol):
    def __init__(self, slot):
        self.slot = slot
    def connectionMade(self):
        data = Result(False, error=ErrorCode.ERR_OCCUPIED_SLOT).serializeBinary()
        length = len(data)
        header = struct.pack('>I', length)
        self.transport.write(header + data)
        self.transport.loseConnection()

class LargeDataTcpProtocol(Protocol):
    def __init__(self):
        super().__init__()
        self.headerMatch = False
    def connectionMade(self):
        pass
    def dataReceived(self, data):
        pass

class TcpFactory(Factory):
    def buildProtocol(self, addr):
        methods = ServerMethods
        slot = methods.getTcpSlot(addr.host)
        if not slot.canUseTcp():
            return None
        elif slot.isOccupied():
            return OccupiedTcpProtocol(slot)
        else:
            slot.occupy()
            if slot.getSlotType() == SlotType.TSS_SENSITIVE_DATA:
                return SensitiveDataTcpProtocol(slot)
            elif slot.getSlotType() == SlotType.TSS_LARGE_DATA:
                return LargeDataTcpProtocol()

class SensitiveDataWebSocketProtocol(WebSocketServerProtocol):
    def __init__(self):
        super().__init__()
        self.needsClose = False
        self.closeMessage = None
        self.verified = False
    def onConnect(self, request):
        log.msg(f'Web socket connection from {request.peer}')
        self.slot = ServerMethods.getTcpSlot(request.peer.split(':')[1])
        if self.slot.isOccupied():
            self.needsClose = True
            self.closeMessage = Result(False, error=ErrorCode.ERR_OCCUPIED_SLOT).serializeBinary()
        if not self.slot.canUseTcp():
            self.needsClose = True
            self.closeMessage = Result(False, error=ErrorCode.ERR_UNALLOCATED_SLOT).serializeBinary()
        if not self.slot.getSlotType() == SlotType.TSS_SENSITIVE_DATA:
            self.needsClose = True
            self.closeMessage = Result(False, error=ErrorCode.ERR_INVALID_SLOT).serializeBinary()
    def onOpen(self):
        if self.needsClose:
            self.sendMessage(self.closeMessage, isBinary=True)
            self.sendClose()
            return
    def onMessage(self, data, isBinary):
        if not self.verified:
            self.handshake(data)
    def encryptAndSend(self, data):
        data = self.slot.eccKey.encrypt(data)
        self.send(data)
    def send(self, data):
        self.sendMessage(data, isBinary=True)
    def handshake(self, data):
        data = msgpack.loads(data)
        signature = data.get('signature')
        if not signature:
            self.send(Result(False, error=ErrorCode.ERR_NO_SIGNATURE_SPECIFIED).serializeBinary())
            self.transport.loseConnection()
            return
        if not self.slot.eccKey.verifySignature(signature, self.slot.secret):
            self.send(Result(False, error=ErrorCode.ERR_SIGNATURE_MISMATCH).serializeBinary())
            self.transport.loseConnection()
            return
        datatype = data.get('type')
        if not datatype:
            self.send(Result(False, error=ErrorCode.ERR_MISSING_PARAMETER).serializeBinary())
            self.transport.loseConnection()
            return
        if datatype == 'detect':
            self.handler = self.faceDetect
        elif datatype == 'recognize':
            self.handler = self.faceRecognize
            self.extraData['ids'], self.extraData['models'] = fu.load_models()
        else:
            self.send(Result(False, error='Invalid data type.').serializeBinary())
            self.transport.loseConnection()
            return
        self.verified = True
        self.send(Result(True).serializeBinary())
        log.msg(f'Socket handshake with {self.slot.address} complete.')
        log.msg(f'Socket type: {datatype}, remote signature: {signature}')
        

class WebSocketFactory(WebSocketServerFactory):
    protocol = SensitiveDataWebSocketProtocol
