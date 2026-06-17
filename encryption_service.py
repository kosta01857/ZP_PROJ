from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import rsa
import secrets
from rsa_service import RsaService

class EncryptionService:
    def __init__(self):
        self.rsaSvc = RsaService()

    def encryptMessage(self, message: bytes, Ks: int, algorithm: str):
        if algorithm == "AES":
            algorithmChoice = algorithms.AES(Ks)
            iv = secrets.randbits(128).to_bytes(16,"big")
            blockSize = 128

        elif algorithm == "3DES":
            algorithmChoice = algorithms.TripleDES(Ks)
            iv = secrets.randbits(64).to_bytes(8,"big")
            blockSize = 64

        else:
            raise ValueError("Unsupported algorithm")
        
        padder = padding.PKCS7(blockSize).padder()
        padded = ( padder.update(message) + padder.finalize())
        cipher = Cipher(algorithmChoice, modes.CFB(iv))
        encryptor = cipher.encryptor()
        cipherText = (encryptor.update(padded) + encryptor.finalize())
        return iv, cipherText

    def decryptMessage(self, message:bytes, Ks: int, iv: bytes, algorithm: str):

        if algorithm == "AES":
            algorithmChoice = algorithms.AES(Ks)
            block_size = 128

        elif algorithm == "3DES":
            algorithmChoice = algorithms.TripleDES(Ks)
            block_size = 64

        else:
            raise ValueError("Unsupported algorithm")

        cipher = Cipher(algorithmChoice,modes.CFB(iv))
        decryptor = cipher.decryptor()
        padded = (decryptor.update(message) + decryptor.finalize())
        unpadder = padding.PKCS7(block_size).unpadder()
        textBytes = (unpadder.update(padded) + unpadder.finalize)

        return textBytes
        

    
    def encryptKs(self, Ks: int, pub: rsa.PublicKey) -> bytes:
        return self.rsaSvc.encryptMessage(Ks.to_bytes(16,"big"),pub)

    def decryptKs(self, encryptedKs: bytes , priv: rsa.PrivateKey) -> int:
        decryptedKsBytes = self.rsaSvc.decryptMessage(encryptedKs, priv)
        return int.from_bytes(decryptedKsBytes, "big")
