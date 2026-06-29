from rsa_service import RsaService
from pgp_service import PgpService 
from encryption_service import EncryptionService
from compression_service import CompressionService
from segmentation_service import SegmentationService
from email_service import EmailService
from main_service import MainService
<<<<<<< HEAD
from user import User
=======
from user_service import UserService
>>>>>>> origin/main

def testPrintRsa():
    rsaSvc = RsaService()
    #rsaSvc.generateKeyPair(1000)
    rsaSvc.generateKeyPair(1024)
    rsaSvc.generateKeyPair(2048)


def testRsaExport():
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    rsaSvc.exportKeyPairToPem(pub, priv, b"password", "test")

def testRsaImportExport():
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    rsaSvc.exportKeyPairToPem(pub, priv, b"password", "test")
    privImp = rsaSvc.importPrivateRsaKey("test_priv.pem", b"password")
    pubImp = rsaSvc.importPublicRsaKey("test_pub.pem")
    assert priv.private_numbers().public_numbers.n == privImp.private_numbers().public_numbers.n, "priv errror"
    assert pub.public_numbers().n == pubImp.public_numbers().n, "pub errror"
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
    pgpSvc = PgpService()
    encSvc =  EncryptionService()
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    ks = pgpSvc.generateKs()
    encKs = encSvc.encryptKs(ks,pub)
    decryptedKs = encSvc.decryptKs(encKs,priv)
    assert ks == decryptedKs , "Ks do not match"
    print("success")


def testEncryptDecryptMessage():
    message = "Some mock message".encode()
    pgpSvc =  PgpService()
    encSvc =  EncryptionService()
    ks = pgpSvc.generateKs()
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


def testEmailService():
    message = "Some mock message".encode()
    emailSvc = EmailService()
    messageToRadix = emailSvc.toRadix64(message, "AES")
    messageFromRadix, _ = emailSvc.fromRadix64(messageToRadix)
    assert messageFromRadix == message, "Radix error"
    print ("Success")

def e2eCoreTest():
    pgpSvc = PgpService()
    rsaSvc = RsaService()
    senderPriv, senderPub = rsaSvc.generateKeyPair(2048)
    receiverPriv, receiverPub = rsaSvc.generateKeyPair(2048)
    message = "Some mock message".encode()
    chunks = pgpSvc.pgpEncrypt(message, receiverPub,senderPriv, "AES")
    receivedeMsg = pgpSvc.pgpDecrypt(chunks,senderPub, receiverPriv)
    assert receivedeMsg == message.decode(), "e2e core test failed, messages do not match"
    print("success")

def testWrongPassword():
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    rsaSvc.exportKeyPairToPem(pub, priv, b"correct_password", "test")
    result = rsaSvc.importPrivateRsaKey("test_priv.pem", b"wrong_password")
    assert result is None, "expected None for wrong password"
    print("success")

def mainSvcTest():
    mainSvc = MainService()
    message = "mock message"
    rsaSvc = RsaService()
    senderPriv, senderPub = rsaSvc.generateKeyPair(2048)
    receiverPriv, receiverPub = rsaSvc.generateKeyPair(2048)
    mainSvc.send(message,"test_dest",senderPriv, receiverPub, "AES")
    receivedMessage =mainSvc.receive("test_dest",senderPub, receiverPriv)
    assert receivedMessage == message, "main svc doesnt work, messages dont match"
    print("success")
    
def userServiceTest():
    userSvc = UserService()
    name = "TestUser"
    email = "test@example.com"
    user = userSvc.createUser(name, email)
    found = userSvc.findUserByEmail(email)
    assert found is not None, "User was not created"
    assert found.email == email, "Email mismatch"
    assert found.name == name, "Name mismatch"
    print("createUser OK")
    result = userSvc.deleteUser(email)
    assert result is True, "User was not deleted"
    found_after = userSvc.findUserByEmail(email)
    assert found_after is None, "User still exists after delete"
    print("deleteUser OK")
    print("UserService test SUCCESS")
    


def testUserPrivateKeyRing():
    user = User("kosta","kosta012001@gmail.com")
    password = "123"
    pub,priv = user.newKeyPair(1024,password)
    ring = user.loadPrivateKeyRing()
    rsaSvc = RsaService()
    private_key = ring[0]
    key_filename = private_key["pem_file"]
    importedPriv = rsaSvc.importPrivateRsaKey(key_filename,password.encode())
    assert importedPriv.private_numbers().d == priv.private_numbers().d, "failed , keys do not match"
    print("success")