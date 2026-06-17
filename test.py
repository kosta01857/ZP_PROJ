from rsa_service import RsaService
from main_service import MainService
from encryption_service import EncryptionService
from compression_service import CompressionService
from segmentation_service import SegmentationService
from email_service import EmailService

def testPrintRsa():
    rsaSvc = RsaService()
    #rsaSvc.generateKeyPair(1000)
    rsaSvc.generateKeyPair(1024)
    rsaSvc.generateKeyPair(2048)


def testRsaExport():
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    rsaSvc.exportKeyPairToPem(pub, priv, {})

def testRsaImportExport():
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    rsaSvc.exportKeyPairToPem(pub, priv, {})
    privImp = rsaSvc.importPrivateRsaKey("priv.pem")
    pubImp =  rsaSvc.importPublicRsaKey("pub.pem")
    assert priv.n == privImp.n, "priv errror"
    assert pub.n == pubImp.n, "pub errror"
    print("success")



def testDigialSignature():
    message = "Some mock message".encode()
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    sig = rsaSvc.generateDigitanSignature(priv=priv, message=message)
    assert rsaSvc.verifyDigitalSignature(message,sig,pub) , "failed"
    print("success")

def testRsaEncryption():
    message = "Some mock message".encode()
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    C = rsaSvc.encryptMessage(message=message, pub=pub)
    assert rsaSvc.decryptMessage(C,priv=priv) == message , "failed"
    print("success")

def testKsEncryption():
    mainSvc =  MainService()
    encSvc =  EncryptionService()
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    ks = mainSvc.generateKs()
    encKs = encSvc.encryptKs(ks,pub)
    decryptedKs = encSvc.decryptKs(encKs,priv)
    assert ks == decryptedKs , "Ks do not match"
    print("success")


def testEncryptDecryptMessage():
    message = "Some mock message".encode()
    mainSvc =  MainService()
    encSvc =  EncryptionService()
    ks = mainSvc.generateKs()
    encryptedMessage = encSvc.encryptMessage(message, ks, "AES")
    decryptedMessage = encSvc.decryptMessage(encryptedMessage,ks, "AES")
    assert decryptedMessage == message, "Messages do not match, AES"
    encryptedMessage = encSvc.encryptMessage(message, ks, "3DES")
    decryptedMessage = encSvc.decryptMessage(encryptedMessage,ks, "3DES")
    assert decryptedMessage == message, "Messages do not match, 3DES"
    print("Success")

def testCompressDecompress():
    message = "Some mock message".encode()
    cdSvc = CompressionService()
    compressedMessage = cdSvc.compress(message)
    decompressedMessage = cdSvc.decompress(compressedMessage)
    assert message == decompressedMessage, "Compression/Decompression doesn't work"
    print("Success")
    
def testSegmentSvc():
    import secrets
    msg = str(secrets.token_bytes(100000))
    segSvc = SegmentationService()
    segSvc.split(msg,{})
    reassembledMsg = segSvc.reassemble({})
    assert msg == reassembledMsg, "error, segmentation doesnt work"
    print("success")


testSegmentSvc()
def testEmailService():
    message = "Some mock message".encode()
    emailSvc = EmailService()
    messageToRadix = emailSvc.toRadix64(message)
    messageFromRadix = emailSvc.fromRadix64(messageToRadix)
    assert messageFromRadix == message, "Radix error"
    print ("Success")


