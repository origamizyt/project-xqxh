import coincurve as coin, ecies, hmac, secrets

def generate_private_key():
    return coin.PrivateKey()

def generate_secret():
    return secrets.token_bytes()

def certify_hmac_digest(key, data, digest):
    return hmac.compare_digest(hmac.digest(key, data, digest='sha256'), digest)

class EccKeys:
    def __init__(self, private_key=None):
        self.privateKey = coin.PrivateKey(private_key) if private_key else coin.PrivateKey()
        self.publicKey = self.privateKey.public_key
        self.remoteKey = None
    def setRemoteKey(self, remote_key):
        self.remoteKey = coin.PublicKey(remote_key)
    def keyExchanged(self):
        return self.remoteKey is not None
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
    def verifySignature(self, signature, data):
        return coin.verify_signature(signature, data, self.remoteKey.format(False))
    