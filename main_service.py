from pgp_service import PgpService
from rsa_service import RsaService
from user import User
import rsa
class MainService:
    pgpSvc = PgpService()
    rsaSvc = RsaService()


    def send(self, message: str, dest: str, senderPriv: rsa.PublicKey,
              receiverPub: rsa.PrivateKey, algorithm: str):
        byteMessage = message.encode()
        encryptedMessage = self.pgpSvc.pgpEncrypt(byteMessage, receiverPub, senderPriv, algorithm)
        with open(dest , "w") as f:
            f.write("\n".join(encryptedMessage))


    def receive(self, source: str, senderPub: rsa.PublicKey, receiverPriv: rsa.PrivateKey) -> str:
        encryptedData = []
        with open(source, "r") as f:
            encryptedData = f.read().split('\n')
        message = self.pgpSvc.pgpDecrypt(encryptedData,senderPub,receiverPriv)
        return message
            


    def generateKeyPair(self, user: User, keySize: int) -> tuple[rsa.PublicKey, rsa.PrivateKey]:
        priv, pub = self.rsaSvc.generateKeyPair(keySize)
        return pub,priv