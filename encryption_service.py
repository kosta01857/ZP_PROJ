from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import secrets
from rsa_service import RsaService

class EncryptionService:
    def __init__(self):
        self.rsaSvc = RsaService()

    def encryptMessage(self, message: bytes, Ks: int, algorithm: str):
        if algorithm == "AES":
            algorithmChoice = algorithms.AES(Ks.to_bytes(16,"big"))
            iv = secrets.randbits(128).to_bytes(16,"big")
            blockSize = 128

        elif algorithm == "3DES":
            algorithmChoice = algorithms.TripleDES(Ks.to_bytes(16,"big"))
            iv = secrets.randbits(64).to_bytes(8,"big")
            blockSize = 64

        else:
            raise ValueError("Unsupported algorithm")
        
        padder = padding.PKCS7(blockSize).padder()
        padded = ( padder.update(message) + padder.finalize())
        cipher = Cipher(algorithmChoice, modes.CFB(iv))
        encryptor = cipher.encryptor()
        cipherText = (encryptor.update(padded) + encryptor.finalize())
        return iv + cipherText

    def decryptMessage(self, messageIv:bytes, Ks: int, algorithm: str):
        iv = bytes()
        message = bytes()
        if algorithm == "AES":
            algorithmChoice = algorithms.AES(Ks.to_bytes(16,"big"))
            block_size = 128
            iv = messageIv[0:16]
            message = messageIv[16:]

        elif algorithm == "3DES":
            algorithmChoice = algorithms.TripleDES(Ks.to_bytes(16,"big"))
            block_size = 64
            iv = messageIv[0:8]
            message = messageIv[8:]

        else:
            raise ValueError("Unsupported algorithm")

        cipher = Cipher(algorithmChoice,modes.CFB(iv))
        decryptor = cipher.decryptor()
        padded = (decryptor.update(message) + decryptor.finalize())
        unpadder = padding.PKCS7(block_size).unpadder()
        textBytes = unpadder.update(padded) + unpadder.finalize()

        return textBytes
        

    
    def encryptKs(self, Ks: int, pub: rsa.RSAPublicKey) -> bytes:
        return self.rsaSvc.encryptMessage(Ks.to_bytes(16,"big"),pub)

    def decryptKs(self, encryptedKs: bytes , priv: rsa.RSAPrivateKey) -> int:
        decryptedKsBytes = self.rsaSvc.decryptMessage(encryptedKs, priv)
        return int.from_bytes(decryptedKsBytes, "big")
