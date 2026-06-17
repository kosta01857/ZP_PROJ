import cryptography
import rsa
from rsa_service import RsaService

class EncryptionService:
    def __init__(self):
        self.rsaSvc = RsaService()

    def encryptMessage(self, message, Ks):
        pass


    def decryptMessage(self, message, Ks):
        pass

    
    def encryptKs(self, Ks: int, pub: rsa.PublicKey) -> bytes:
        return self.rsaSvc.encryptMessage(Ks.to_bytes(16,"big"),pub)

    def decryptKs(self, encryptedKs: bytes , priv: rsa.PrivateKey) -> int:
        decryptedKsBytes = self.rsaSvc.decryptMessage(encryptedKs, priv)
        return int.from_bytes(decryptedKsBytes, "big")
