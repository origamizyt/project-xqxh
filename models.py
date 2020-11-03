# models.py
# Defines the data models used in the interface.

import json, hmac, uuid, base64, security, struct, msgpack
from enum import IntEnum
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from twisted.python import log
from autobahn.twisted.websocket import WebSocketServerProtocol, WebSocketServerFactory

class Serializer:
    httpContentType = 'application/json'
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

class Config:
    def __init__(self, data):
        self.data = data
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
    @staticmethod
    def getConfig(filename):
        config_file = open(filename)
        data = json.load(config_file)
        config_file.close()
        return Config(data)

config = Config.getConfig("config.json")

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
        super().__init__(success=success, data=data)

class FaceData:
    def __init__(self, user_id, data):
        self.user_id = user_id
        self.data = data

import database as db, faceupload as fu, debug_utils as utils

class Permission: pass

class NoPermission(Permission):
    faceRecognition = False
    userData = None
    accessMaps = False
    planRoute = False
    accessLocations = False

class DogPermission(Permission):
    faceRecognition = True
    userData = '*'
    accessMaps = True
    planRoute = True
    accessLocations = True

class HumanPermission(Permission):
    faceRecognition = True
    accessMaps = False
    planRoute = False
    accessLocations = False
    def __init__(self, user):
        self.userData = user

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
        self.privateKey = security.generate_hmac_key()
    def getPrivateKey(self):
        return self.privateKey
    def getSession(self, addr):
        return self.addressMap.get(addr)
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
            header = data[:4]
            self.length = struct.unpack('>I', header)[0]
            data = data[4:]
        self.buffer += data
        if len(self.buffer) >= self.length > 0:
            self.process(self.buffer[:self.length])
            self.buffer = self.buffer[self.length:]
            self.length = 0
            if self.buffer:
                header = self.buffer[:4]
                self.buffer = self.buffer[4:]
                self.length = struct.unpack('>I', header)[0]
    def process(self, data):
        pass

class SensitiveDataTcpProtocol(StructHeaderTcpProtocol):
    def __init__(self, slot):
        super().__init__(slot)
        self.verified = False
        self.handler = None
        self.keys = ServerMethods.getSession(slot.address).getEccKeys()
        self.type = None
    def process(self, line):
        if not self.verified:
            self.handshake(line)
        elif self.handler:
            line = self.keys.decrypt(line)
            self.encryptAndSend(self.handler(line))
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
    def encryptAndSend(self, data):
        data = self.keys.encrypt(data)
        self.send(data)
    def send(self, data):
        length = len(data)
        header = struct.pack('>I', length)
        self.transport.write(header + data)
    def handshake(self, data):
        data = msgpack.loads(data)
        signature = data.get('signature')
        if not signature:
            self.send(Result(False, error='A signature must be provided.').serializeBinary())
            self.transport.loseConnection()
            return
        signature = base64.b64decode(signature)
        if not self.keys.verifySignature(signature, self.slot.secret):
            self.send(Result(False, error='Signature mismatch.').serializeBinary())
            self.transport.loseConnection()
            return
        self.type = data.get('type')
        if not self.type:
            self.send(Result(False, error='A data type must be provided.').serializeBinary())
            self.transport.loseConnection()
            return
        if self.type == 'detect':
            self.handler = self.faceDetect
            utils.prepare_detect_image(self.slot.address)
        elif self.type == 'recognize':
            self.handler = self.faceRecognize
            self.extraData['ids'], self.extraData['models'] = fu.load_models()
            utils.prepare_recognize_image(self.slot.address)
        else:
            self.send(Result(False, error='Invalid data type.').serializeBinary())
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
        data = Result(False, error='Server slot is occupied by another session.').serializeBytes()
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
            self.closeMessage = Result(False, error='Server slot is being occupied by another session.').serializeBinary()
        if not self.slot.canUseTcp():
            self.needsClose = True
            self.closeMessage = Result(False, error='Client not authorized to use web sockets.').serializeBinary()
        if not self.slot.getSlotType() == SlotType.TSS_SENSITIVE_DATA:
            self.needsClose = True
            self.closeMessage = Result(False, error='Incorrect server slot type.').serializeBinary()
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
            self.send(Result(False, error='A signature must be provided.').serializeBinary())
            self.transport.loseConnection()
            return
        signature = base64.b64decode(signature)
        if not self.slot.eccKey.verifySignature(signature, self.slot.secret):
            self.send(Result(False, error='Signature mismatch.').serializeBinary())
            self.transport.loseConnection()
            return
        datatype = data.get('type')
        if not datatype:
            self.send(Result(False, error='A data type must be provided.').serializeBinary())
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
