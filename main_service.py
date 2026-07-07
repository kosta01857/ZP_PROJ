from pgp_service import PgpService
from rsa_service import RsaService
from user import User
from cryptography.hazmat.primitives.asymmetric import rsa
from send_options import SendOptions

KEY_ID_PLACEHOLDER = '\x00' * 16
class MainService:
    pgpSvc = PgpService()
    rsaSvc = RsaService()
    opt = SendOptions()


    def send(self, message: str, dest: str, senderPriv: rsa.RSAPrivateKey,
              receiverPub: rsa.RSAPublicKey, opt: SendOptions):
        byteMessage = message.encode()
        encryptedMessages = self.pgpSvc.pgpEncrypt(byteMessage, receiverPub, senderPriv, opt)
        with open(dest , "wb") as f:
            # upisi key ids u fajl
            publicKeyId = User._deriveKeyId(receiverPub).encode() if opt.encrypt else KEY_ID_PLACEHOLDER.encode()
            privateKeyId = User._deriveKeyId(senderPriv.public_key()).encode() if opt.sign else KEY_ID_PLACEHOLDER.encode()
            f.write(publicKeyId + privateKeyId)

            # upisi chunkove u fajl
            for chunk_len,chunk in encryptedMessages:
                f.write(chunk_len.to_bytes(4,"big") + chunk) # duzina chunka na 4 bajta pa chunk

    def resolveKeyIds(self, source: str, user) -> tuple[dict, dict]:
        receiverPublicKeyId = None
        senderPrivateKeyId  = None
        with open(source, "rb") as f:
            #procitaj key ids iz fajla
            keyIds = f.read(32)
            receiverPublicKeyId = keyIds[:16].decode()
            senderPrivateKeyId = keyIds[16:32].decode()
        # proveri dal su sve nule, to je placeholder
        recieverPrivKey = None
        senderPubKey = None
        if receiverPublicKeyId != KEY_ID_PLACEHOLDER:
            privateKeyRing = user.loadPrivateKeyRing()
            for key in privateKeyRing:
                if key["keyId"] == receiverPublicKeyId:
                    recieverPrivKey = key
                    break
            if recieverPrivKey is None:
                raise ValueError("[main server - decrypt]could not find reciever private key")
        if senderPrivateKeyId != KEY_ID_PLACEHOLDER:
            publicKeyRing = user.loadPublicKeyRing()
            for key in publicKeyRing:
                if key["keyId"] == senderPrivateKeyId:
                    senderPubKey = key
                    break
            if senderPubKey is None:
                raise ValueError("[main server - decrypt]could not find sender public key")

        return senderPubKey, recieverPrivKey

    def receive(self, source: str, senderPub: rsa.RSAPublicKey, receiverPriv: rsa.RSAPrivateKey) -> str:
        encryptedData = []
        with open(source, "rb") as f:
            f.read(32)  # preskoci zaglavlje sa key id-jevima (16 + 16 bajtova)
            while True:
                header = f.read(4)
                if len(header) < 4: #Ako nije 4 onda je EOF, cita cak i poslednji kraci
                    break
                chunk_len = int.from_bytes(header, "big")
                chunk = f.read(chunk_len)
                encryptedData.append(chunk)
        message = self.pgpSvc.pgpDecrypt(encryptedData,senderPub,receiverPriv)
        return message