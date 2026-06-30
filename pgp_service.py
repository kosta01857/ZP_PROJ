from auth_service import AuthService
from compression_service import CompressionService
from email_service import EmailService
from encryption_service import EncryptionService
from segmentation_service import SegmentationService
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from exception import SignatureVerificationError
from send_options import SendOptions

class PgpService:
    authService = AuthService()
    compressionService = CompressionService()
    emailService = EmailService()
    encryptionService = EncryptionService()
    segmentationService = SegmentationService()

    def generateKs(self) -> int:
        return secrets.randbits(128)


    def splitData(self, data: bytes, ksSize) -> tuple[bytes,bytes]:
        encryptedMessage = data[ksSize:]
        encryptedKs = data[0:ksSize]
        return encryptedMessage, encryptedKs

    def splitMessage(self, data: bytes, sigSize) -> tuple[bytes, bytes]:
        dataLen = len(data)
        messageLen = dataLen - sigSize
        message = data[0:messageLen]
        digest = data[messageLen:]
        return message, digest


    def pgpEncrypt(self,originalMessage: bytes, receiverPU: rsa.RSAPublicKey,
              senderPR: rsa.RSAPrivateKey, options: SendOptions) -> list[str]:
        message = originalMessage
        if options.sign:
            signature = self.authService.sign(message, senderPR)
            message = message+ signature
        if options.compress:
            message = self.compressionService.compress(message)
        if options.encrypt:
            Ks = self.generateKs()
            message = self.encryptionService.encryptMessage(message, Ks, options.algorithm)
            encryptedKey = self.encryptionService.encryptKs(Ks, receiverPU)
            message = encryptedKey + message
        message = self.emailService.encodeOptions(message,options)
        if options.radix64:
            message = self.emailService.toRadix64(message, options)
        message = self.emailService.encodeOptions(message,options) 
        return self.segmentationService.split(message)


    def pgpDecrypt(self, encryptedData: list[bytes], senderPU: rsa.RSAPublicKey,
                 receiverPR: rsa.RSAPrivateKey) -> str:
        
        encryptedData = self.segmentationService.reassemble(encryptedData)
        message , options = self.emailService.decodeOptions(encryptedData)
        #ignorisano gore
        if options.radix64:
            data = self.emailService.fromRadix64(data)
        if options.encrypt:
            ksSize = receiverPR.key_size // 8
            data, encryptedKs = self.splitData(data, ksSize)
            Ks = self.encryptionService.decryptKs(encryptedKs, receiverPR)
            data = self.encryptionService.decryptMessage(data, Ks, options.algorithm)
        if options.compress:
            data = self.compressionService.decompress(data)
        if options.sign:
            data, signature = self.splitMessage(data, senderPU.key_size // 8)
            if (not self.authService.verify(message, signature, senderPU)):
                raise SignatureVerificationError("Signature verification failed")
        
        return message.decode()



