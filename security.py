import os, coincurve as coin, ecies, hmac

def generate_hmac_key():
    return os.urandom(16)

def certify_hmac_digest(key, data, digest):
    return hmac.compare_digest(hmac.digest(key, data, digest='sha256'), digest)

class EccKeys:
    def __init__(self):
        self.privateKey = coin.PrivateKey()
        self.publicKey = self.privateKey.public_key
        self.remoteKey = None
    def setRemoteKey(self, remote_key):
        self.remoteKey = coin.PublicKey(remote_key)
    def encrypt(self, data):
        if not self.remoteKey:
            return None
        return ecies.encrypt(self.remoteKey.format(False), data)
    def decrypt(self, data):
        return ecies.decrypt(self.privateKey.secret, data)
    def getPublicKey(self):
        return self.publicKey.format(False)
    def getSharedSecret(self):
        return self.privateKey.ecdh(self.remoteKey.format(False))
    def verifySharedSecretSignature(self, signature):
        return coin.verify_signature(signature, self.getSharedSecret(), self.remoteKey.format(False))
    