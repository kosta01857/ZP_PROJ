from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import secrets
from rsa_service import RsaService
#Ima svoj rsa servise, enkriptuje/dekriptuje poruke (iv+poruka), e/d KS pomocu rsa
class EncryptionService:
    def __init__(self):
        self.rsaSvc = RsaService()

    def encryptMessage(self, message: bytes, Ks: bytes, algorithm: str):
        if algorithm == "AES":
            algorithmChoice = algorithms.AES(Ks)
            iv = secrets.token_bytes(16) #nonce
            blockSize = 128

        elif algorithm == "3DES":
            algorithmChoice = algorithms.TripleDES(Ks)
            iv = secrets.token_bytes(8) #nonce
            blockSize = 64

        else:
            raise ValueError("Unsupported algorithm")

        padder = padding.PKCS7(blockSize).padder() #Dodaje padding na poruku
        padded = padder.update(message) + padder.finalize()
        cipher = Cipher(algorithmChoice, modes.CFB(iv))
        encryptor = cipher.encryptor()
        cipherText = encryptor.update(padded) + encryptor.finalize()
        return iv + cipherText #zalepi iv i cipher

    def decryptMessage(self, messageIv: bytes, Ks: bytes, algorithm: str):
        if algorithm == "AES":
            algorithmChoice = algorithms.AES(Ks)
            block_size = 128
            iv = messageIv[0:16]
            message = messageIv[16:]

        elif algorithm == "3DES":
            algorithmChoice = algorithms.TripleDES(Ks)
            block_size = 64
            iv = messageIv[0:8]
            message = messageIv[8:]

        else:
            raise ValueError("Unsupported algorithm")

        cipher = Cipher(algorithmChoice, modes.CFB(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(message) + decryptor.finalize()
        unpadder = padding.PKCS7(block_size).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    #Enkriptuje KS preko rsa
    def encryptKs(self, Ks: bytes, pub: rsa.RSAPublicKey) -> bytes:
        return self.rsaSvc.encryptMessage(Ks, pub)

    def decryptKs(self, encryptedKs: bytes, priv: rsa.RSAPrivateKey) -> bytes:
        Ks = self.rsaSvc.decryptMessage(encryptedKs, priv)
        if len(Ks) != 16:
            raise ValueError("Decryption failed: private key does not match the encrypted message")
        return Ks
