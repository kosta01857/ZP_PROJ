from auth_service import AuthService
from compression_service import CompressionService
from email_service import EmailService
from encryption_service import EncryptionService
from segmentation_service import SegmentationService
import secrets
import rsa

class MainService:

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


    def send(self,message: bytes, PU: rsa.PublicKey, PR: rsa.PrivateKey, algorithm: str) -> list[str]:
        signature = self.authService.sign(message, PR)
        signedMessage = message + signature
        compressedMessage = self.compressionService.compress(signedMessage)
        Ks = self.generateKs()
        encryptedMessage = self.encryptionService.encryptMessage(compressedMessage, Ks, algorithm)
        encryptedKey = self.encryptionService.encryptKs(Ks, PU)
        radix64Message = self.emailService.toRadix64(encryptedKey + encryptedMessage, algorithm)
        return self.segmentationService.split(radix64Message)


    def receive(self, encryptedData: list[str], PU: rsa.PublicKey, PR: rsa.PrivateKey) -> str:
        encryptedData = self.segmentationService.reassemble(encryptedData)
        encryptedData, algorithm = self.emailService.fromRadix64(encryptedData)
        ksSize = rsa.common.byte_size(PR.n)
        encryptedMessage, encryptedKs = self.splitData(encryptedData, ksSize)
        Ks = self.encryptionService.decryptKs(encryptedKs, PR)
        message = self.encryptionService.decryptMessage(encryptedMessage, Ks, algorithm)
        decompressedMessage = self.compressionService.decompress(message)
        message, signature = self.splitMessage(decompressedMessage, rsa.common.byte_size(PU.n))
        if (not self.authService.verify(message, signature, PU)):
            print("fail")
        return message




