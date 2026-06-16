import rsa
from domain import User


def resolvePrivateKeyFileName(user: User):
    return "priv.pem"

def resolvePublicKeyFileName(user: User):
    return "pub.pem"

class RsaService:
    def generateKeyPair(self, size) -> tuple[rsa.PrivateKey, rsa.PublicKey]:
        assert size == 1024 or size == 2048 , 'key size not valid'
        public, private = rsa.newkeys(nbits=size)
        return private, public
    
    
    def exportPublicKeyToPem(self, key: rsa.PublicKey, user: User):
        keyBytes = key.save_pkcs1(format="PEM")
        publicFileName = resolvePublicKeyFileName(user)
        with open(publicFileName, "wb") as f:
            f.write(keyBytes)


    def exportPrivateKeyToPem(self, key: rsa.PrivateKey, user: User):
        keyBytes = key.save_pkcs1(format="PEM")
        privateFileName = resolvePrivateKeyFileName(user)
        with open(privateFileName, "wb") as f:
            f.write(keyBytes)

    def exportKeyPairToPem(self, pub: rsa.PublicKey,
                            priv:rsa.PrivateKey, user: User):
        self.exportPrivateKeyToPem(priv, user) 
        self.exportPublicKeyToPem(pub, user) 
    
    def importPublicRsaKey(self, filename: str) -> rsa.PublicKey:
        keyBytes = bytes()
        with open(filename, "rb") as f:
            keyBytes = f.read()
        return rsa.PublicKey.load_pkcs1(keyfile=keyBytes, format="PEM")

    def importPrivateRsaKey(self, filename: str) -> rsa.PrivateKey:
        keyBytes = bytes()
        with open(filename, "rb") as f:
            keyBytes = f.read()
        return rsa.PrivateKey.load_pkcs1(keyfile=keyBytes, format="PEM")