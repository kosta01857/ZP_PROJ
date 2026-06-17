from hashlib import sha1
import rsa
from rsa_service import RsaService

class AuthService:
    def __init__(self):
        self.rsaSvc = RsaService()

    def sign(self, message, priv: rsa.PrivateKey) -> bytes:
        return self.rsaSvc.generateDigitanSignature(priv,message)

    def verify(self, message:bytes, signature:bytes, pub: rsa.PublicKey) -> bool:
        return self.rsaSvc.verifyDigitalSignature(message=message,signature=signature,pub=pub)
        