from pgp_service import PgpService
from rsa_service import RsaService
from user import User
<<<<<<< HEAD
from cryptography.hazmat.primitives.asymmetric import rsa
=======
import rsa
>>>>>>> origin/main
class MainService:
    pgpSvc = PgpService()
    rsaSvc = RsaService()


    def send(self, message: str, dest: str, senderPriv: rsa.RSAPrivateKey,
              receiverPub: rsa.RSAPublicKey, algorithm: str):
        byteMessage = message.encode()
        encryptedMessage = self.pgpSvc.pgpEncrypt(byteMessage, receiverPub, senderPriv, algorithm)
        with open(dest , "w") as f:
            f.write("\n".join(encryptedMessage))


    def receive(self, source: str, senderPub: rsa.RSAPublicKey, receiverPriv: rsa.RSAPrivateKey) -> str:
        encryptedData = []
        with open(source, "r") as f:
            encryptedData = f.read().split('\n')
        message = self.pgpSvc.pgpDecrypt(encryptedData,senderPub,receiverPriv)
        return message
            


    def generateKeyPair(self, user: User, keySize: int) -> tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]:
        priv, pub = self.rsaSvc.generateKeyPair(keySize)
        return pub,priv