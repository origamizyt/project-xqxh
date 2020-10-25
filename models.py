# models.py
# Defines the data models used in the interface.

import json, hmac, uuid, base64, security, struct
from enum import IntEnum
from math import inf
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from twisted.protocols.basic import LineOnlyReceiver

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

class User:
    def __init__(self, **kwargs):
        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
    def toJsonObject(self):
        return {
            'username': self.username
        }

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

import database as db, faceupload as fu

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
        return any(username == x.username for x in self.values())
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
        self.authorized = False
        self.username = None
        self.permission = NoPermission()
    def getSessionHex(self):
        return self.sessionId.hex
    def getSessionBytes(self):
        return self.sessionId.bytes
    def grantPermission(self, permission):
        self.permission = permission
    def clearPermission(self):
        self.permission = NoPermission()
    def getUserName(self):
        return self.username
    def setUserName(self, username):
        self.username = username
        self.authorized = True
    

class ServerMethods:
    _instance = None
    def __init__(self):
        self.addressMap = AddressMap()
        self.usingTcp = TcpUsingList()
        self.hmacKey = security.generate_hmac_key()
    def ecdhKeyExchange(self, addr, remote_key):
        if addr not in self.usingTcp: return None
        if self.usingTcp[addr].isOccupied(): return None
        return self.usingTcp[addr].ecdhKeyExchange(remote_key)
    def releaseServerSlot(self, addr):
        if addr in self.usingTcp:
            del self.usingTcp[addr]
    def prepareSensitiveDataTransfer(self, addr):
        slot = self.usingTcp.setdefault(addr, EncryptedTcpServerSlot(addr, SlotType.TSS_SENSITIVE_DATA))
        return not slot.isOccupied()
    def prepareLargeDataTransfer(self, addr):
        slot = self.usingTcp.setdefault(addr, TcpServerSlot(addr, SlotType.TSS_LARGE_DATA))
        return not slot.isOccupied()
    def getTcpSlot(self, addr):
        return self.usingTcp.get(addr, TcpServerSlot(addr, SlotType.TSS_UNAUTHORIZED))
    def updateHMacKey(self):
        self.hmacKey = security.generate_hmac_key()
    def getHMacKey(self):
        return self.hmacKey
    def getSession(self, addr):
        return self.addressMap.get(addr)
    def endSession(self, addr):
        if addr in self.addressMap:
            del self.addressMap[addr]
    def authenticate(self, addr, data=None):
        if addr not in self.addressMap: return False
        return security.certify_hmac_digest(self.hmacKey, self.addressMap[addr].getSessionBytes(), data)
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
    @staticmethod
    def base64decode(data):
        return base64.b64decode(data.encode('iso-8859-1'))
    @staticmethod
    def base64encode(data):
        return base64.b64encode(data).decode('iso-8859-1')
    @staticmethod
    def getInstance():
        if ServerMethods._instance is None:
            ServerMethods._instance = ServerMethods()
        return ServerMethods._instance

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
        self.eccKey = security.EccKeys()
    def ecdhKeyExchange(self, remote_key):
        self.eccKey.setRemoteKey(remote_key)
        return self.eccKey.getPublicKey()

class TcpProtocol(Protocol):
    def __init__(self, slot):
        self.slot = slot
        self.extraData = {}
    def connectionLost(self, reason):
        ServerMethods.getInstance().releaseServerSlot(self.slot.address)

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
    def process(self, line):
        if not self.verified:
            line = line.decode('iso-8859-1')
            self.processHeader(line)
        elif self.handler:
            line = self.slot.eccKey.decrypt(line)
            self.encryptAndSend(self.handler(line))
    def faceDetect(self, data):
        data = fu.decode_jpg(data)
        result = fu.find_single_face(data)
        success = result is not None
        return Result(success, position=result).toJsonBytes()
    def faceRecognize(self, data):
        data = fu.decode_jpg(data)
        face = fu.find_single_face(data)
        if not face:
            return Result(False, found=False, position=None, user_id=None, user=None, distance=None).toJsonBytes()
        new_face = fu.face_encodings(data, [face])
        ids, models = self.extraData.get('ids', []), self.extraData.get('models', [])
        index, distance = fu.face_match(new_face, models)
        if index >= 0:
            return Result(True, found=True, position=face, user_id=ids[index], user=db.get_user(ids[index]).toJsonObject(), distance=distance).toJsonBytes()
        else:
            return Result(True, found=False, position=face, user_id=None, user=None, distance=None).toJsonBytes()
    def encryptAndSend(self, data):
        data = self.slot.eccKey.encrypt(data)
        length = len(data)
        header = struct.pack('>I', length)
        self.transport.write(header + data)
    def send(self, data):
        length = len(data)
        header = struct.pack('>I', length)
        self.transport.write(header + data)
    def processHeader(self, data):
        data = json.loads(data)
        signature = data.get('signature')
        if not signature:
            self.send(Result(False, error='A signature must be provided.').toJsonBytes())
            self.transport.loseConnection()
            return
        signature = ServerMethods.base64decode(signature)
        if not self.slot.eccKey.verifySharedSecretSignature(signature):
            self.send(Result(False, error='The provided signature does not match the shared secret.').toJsonBytes())
            self.transport.loseConnection()
            return
        datatype = data.get('type')
        if not datatype:
            self.send(Result(False, error='A data type must be provided.').toJsonBytes())
            self.transport.loseConnection()
            return
        if datatype == 'detect':
            self.handler = self.faceDetect
        elif datatype == 'recognize':
            self.handler = self.faceRecognize
            self.extraData['ids'], self.extraData['models'] = fu.load_models()
        else:
            self.send(Result(False, error='Invalid data type.').toJsonBytes())
            self.transport.loseConnection()
            return
        self.verified = True
        self.send(Result(True).toJsonBytes())
        
class OccupiedTcpProtocol(Protocol):
    def __init__(self, slot):
        self.slot = slot
    def connectionMade(self):
        data = Result(False, error='Server slot is occupied by another session.').toJsonBytes()
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
        methods = ServerMethods.getInstance()
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

class Result(dict):
    def __init__(self, success, **kwargs):
        super().__init__(success=success, **kwargs)
    def toJson(self):
        return json.dumps(self)
    def toJsonBytes(self):
        return self.toJson().encode('iso-8859-1')
    def __str__(self):
        return self.toJson()