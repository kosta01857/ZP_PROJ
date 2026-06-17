from rsa_service import RsaService
from main_service import MainService
from encryption_service import EncryptionService

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


testKsEncryption()
