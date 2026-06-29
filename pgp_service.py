from auth_service import AuthService
from compression_service import CompressionService
from email_service import EmailService
from encryption_service import EncryptionService
from segmentation_service import SegmentationService
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from exception import SignatureVerificationError

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


    def pgpEncrypt(self,message: bytes, receiverPU: rsa.RSAPublicKey,
              senderPR: rsa.RSAPrivateKey, algorithm: str) -> list[str]:
        signature = self.authService.sign(message, senderPR)
        signedMessage = message + signature
        compressedMessage = self.compressionService.compress(signedMessage)
        Ks = self.generateKs()
        encryptedMessage = self.encryptionService.encryptMessage(compressedMessage, Ks, algorithm)
        encryptedKey = self.encryptionService.encryptKs(Ks, receiverPU)
        radix64Message = self.emailService.toRadix64(encryptedKey + encryptedMessage, algorithm)
        return self.segmentationService.split(radix64Message)


    def pgpDecrypt(self, encryptedData: list[str], senderPU: rsa.RSAPublicKey,
                 receiverPR: rsa.RSAPrivateKey) -> str:
        encryptedData = self.segmentationService.reassemble(encryptedData)
        encryptedData, algorithm = self.emailService.fromRadix64(encryptedData)
        ksSize = receiverPR.key_size // 8
        encryptedMessage, encryptedKs = self.splitData(encryptedData, ksSize)
        Ks = self.encryptionService.decryptKs(encryptedKs, receiverPR)
        message = self.encryptionService.decryptMessage(encryptedMessage, Ks, algorithm)
        decompressedMessage = self.compressionService.decompress(message)
        message, signature = self.splitMessage(decompressedMessage, senderPU.key_size // 8)
        if (not self.authService.verify(message, signature, senderPU)):
            raise SignatureVerificationError("Signature verification failed")

        return message.decode()



