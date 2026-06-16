from rsa_service import RsaService

def testPrintRsa():
    rsaSvc = RsaService()
    #rsaSvc.generateKeyPair(1000)
    rsaSvc.generateKeyPair(1024)
    rsaSvc.generateKeyPair(2048)


def testRsaExport():
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    rsaSvc.exportKeyPairToPem(priv,pub, {})

def testRsaImportExport():
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    rsaSvc.exportKeyPairToPem(priv,pub, {})
    privImp = rsaSvc.importPrivateRsaKey("priv.pem")
    pubImp =  rsaSvc.importPublicRsaKey("pub.pem")
    assert priv.n == privImp.n, "priv errror"
    assert pub.n == pubImp.n, "pub errror"

     
testRsaImportExport()
      