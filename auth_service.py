from hashlib import sha1
import rsa

class AuthService:
    def sign(self, message, key):
        #ovaj key treba da bude private key
        hashedMessage = sha1(message.encode("utf-8")).digest()
        signature = rsa.sign_hash(hashedMessage, key, "SHA-1")
        return signature

    def verify(self, message, signature, key):
        #ovaj treba da bude public
        
    
        

    
