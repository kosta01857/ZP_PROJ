from hashlib import sha1
from cryptography.hazmat.primitives.asymmetric import rsa
from rsa_service import RsaService

class AuthService:
    def __init__(self):
        self.rsaSvc = RsaService()

    def sign(self, message, priv: rsa.RSAPrivateKey) -> bytes:
        return self.rsaSvc.generateDigitanSignature(priv,message)

    def verify(self, message:bytes, signature:bytes, pub: rsa.RSAPublicKey) -> bool:
        return self.rsaSvc.verifyDigitalSignature(message=message,signature=signature,pub=pub)
        