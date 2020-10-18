# models.py
# Defines the data models used in the interface.

import json, hmac, os, uuid, base64

TSS_UNAUTHORIZED = 0
TSS_SENSITIVE_DATA = 1
TSS_LARGE_DATA = 2

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
    def __init__(self, username):
        self.username = username
    def toJsonObject(self):
        return {
            'username': self.username
        }

import database as db

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

class Session:
    def __init__(self):
        self.sessionId = uuid.uuid4()
        self.permission = NoPermission()
    def getSessionHex(self):
        return self.sessionId.hex
    def getSessionBytes(self):
        return self.sessionId.bytes
    def grantPermission(self, permission):
        self.permission = permission
    def clearPermission(self):
        self.permission = NoPermission()
    

class ServerMethods:
    def __init__(self):
        self.addressMap = {}
        self.usingTcp = {}
        self.hmacKey = None
    def prepareSensitiveDataTransfer(self, addr):
        self.usingTcp[addr] = TcpServerSlot(TSS_SENSITIVE_DATA)
    def prepareLargeDataTransfer(self, addr):
        self.usingTcp[addr] = TcpServerSlot(TSS_LARGE_DATA)
    def getTcpSlot(self, addr):
        return self.usingTcp.get(addr, TcpServerSlot(TSS_UNAUTHORIZED))
    def launch(self):
        self.hmacKey = os.urandom(16)
    def getHMacKey(self):
        return self.hmacKey
    def newSession(self, addr):
        session = Session()
        self.addressMap[addr] = session
        return session.getSessionHex()
    def endSession(self, addr):
        if addr in self.addressMap:
            del self.addressMap[addr]
    def authenticate(self, addr, data=None):
        if addr not in self.addressMap: return False
        return hmac.compare_digest(hmac.digest(self.hmacKey, self.addressMap[addr].getSessionBytes(), digest='sha256'), data)
    def grantPermission(self, addr, permission):
        if addr not in self.addressMap: return
        self.addressMap[addr].grantPermission(permission)
    def clearPermission(self, addr):
        if addr not in self.addressMap: return
        self.addressMap[addr].clearPermission()
    def dogCertificate(self, dog_name, password):
        return db.certify_dog(dog_name, password)
    def base64decode(self, data):
        return base64.b64decode(data.encode('iso-8859-1'))
    def base64encode(self, data):
        return base64.b64encode(data).decode('iso-8859-1')