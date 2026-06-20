from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import serialization

class RsaService:
    def generateKeyPair(self, size) -> tuple[rsa.RSAPrivateKey,
                                              rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=size)
        public_key = private_key.public_key()
        return private_key,public_key
    
    def exportPublicKeyToPem(self, key: rsa.RSAPublicKey, filename: str):
        keyBytes = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filename + "_pub.pem", "wb") as f:
            f.write(keyBytes)

    def exportPrivateKeyToPem(self, key: rsa.RSAPrivateKey,
                               password: bytes, filename: str):
        keyBytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        with open(filename + "_priv.pem", "wb") as f:
            f.write(keyBytes)

    def exportKeyPairToPem(self, pub: rsa.RSAPublicKey,
                            priv:rsa.RSAPrivateKey, password: bytes, filename: str):
        self.exportPublicKeyToPem(pub, filename)
        self.exportPrivateKeyToPem(priv,password, filename)
    
    def importPublicRsaKey(self, filename: str) -> rsa.RSAPublicKey:
        with open(filename, "rb") as f:
            pemKey = f.read()
            return load_pem_public_key(pemKey)

    def importPrivateRsaKey(self, filename: str, password:bytes) -> rsa.RSAPrivateKey:
        try: 
            with open(filename, "rb") as f:
                pemKey = f.read()
                return load_pem_private_key(pemKey, password)
        except:
            return None

    def generateDigitanSignature(self, priv:rsa.RSAPrivateKey,
                                  message: bytes) -> bytes:
        return priv.sign(message, padding.PKCS1v15(), hashes.SHA1())
    
    def verifyDigitalSignature(self,message: bytes, signature: bytes,
                                pub: rsa.RSAPublicKey) -> bool:
        try:
            pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA1())
            return True
        except:
            return False

    def encryptMessage(self, message:bytes, pub: rsa.RSAPublicKey) -> bytes:
        return pub.encrypt(message, padding.PKCS1v15())


    def decryptMessage(self, message:bytes, priv: rsa.RSAPrivateKey) -> bytes:
        return priv.decrypt(message, padding.PKCS1v15())
