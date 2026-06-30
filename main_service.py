from pgp_service import PgpService
from rsa_service import RsaService
from user import User
from cryptography.hazmat.primitives.asymmetric import rsa
from send_options import SendOptions
class MainService:
    pgpSvc = PgpService()
    rsaSvc = RsaService()
    opt = SendOptions()


    def send(self, message: str, dest: str, senderPriv: rsa.RSAPrivateKey,
              receiverPub: rsa.RSAPublicKey, opt: SendOptions):
        byteMessage = message.encode()
        encryptedMessages = self.pgpSvc.pgpEncrypt(byteMessage, receiverPub, senderPriv, opt)
        with open(dest , "wb") as f:
            for chunk_len,chunk in encryptedMessages:
                f.write(chunk_len.to_bytes(4,"big") + chunk)


    def receive(self, source: str, senderPub: rsa.RSAPublicKey, receiverPriv: rsa.RSAPrivateKey) -> str:
        encryptedData = []
        with open(source, "rb") as f:
            while True:
                header = f.read(4)
                if len(header) < 4:
                    break
                chunk_len = int.from_bytes(header, "big")
                chunk = f.read(chunk_len)
                encryptedData.append(chunk)
        message = self.pgpSvc.pgpDecrypt(encryptedData,senderPub,receiverPriv)
        return message