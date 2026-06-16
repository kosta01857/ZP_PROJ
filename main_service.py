from auth_service import AuthService
from compression_service import CompressionService
from email_service import EmailService
from encryption_service import EncryptionService
from segmentation_service import SegmentationService

class MainService:

    authService = AuthService()
    compressionService = CompressionService()
    emailService = EmailService()
    encryptionService = EncryptionService()
    segmentationService = SegmentationService()

    def generateKs(self):
        pass


    def splitData(self,data):
        pass

    def splitMessage(self, message):
        pass


    def send(self,message, PU, PR):
        signature = self.authService.sign(message, PR)
        signedMessage = message + signature
        compressedMessage = self.compressionService.compress(signedMessage)
        Ks = self.generateKs()
        encryptedKey = self.encryptionService.encryptKs(Ks, PU)
        encryptedMessage = self.encryptionService.encryptMessage(compressedMessage, Ks)
        radix64Message = self.emailService.toRadix64(encryptedKey + encryptedMessage)
        return self.segmentationService.split(radix64Message)


    def receive(self, encryptedData, PU, PR):
        encryptedData = self.segmentationService.reassemble(encryptedData)
        encryptedData = self.emailService.fromRadix64(encryptedData)
        encryptedKs, encryptedMessage = self.splitData(encryptedData)
        Ks = self.encryptionService.decryptKs(encryptedKs, PR)
        message = self.encryptionService.decryptMessage(encryptedMessage, Ks)
        decompressedMessage = self.compressionService.decompress(message)
        signature, message = self.splitMessage(decompressedMessage)
        if (not self.authService.verify(message, signature, PU)):
            print("fail")
        return message




