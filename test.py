from rsa_service import RsaService
from pgp_service import PgpService
from encryption_service import EncryptionService
from compression_service import CompressionService
from segmentation_service import SegmentationService
from email_service import EmailService
from main_service import MainService
from user import User
from user_service import UserService
from exception import SignatureVerificationError
from send_options import SendOptions
import os

def testPrintRsa():
    rsaSvc = RsaService()
    #rsaSvc.generateKeyPair(1000)
    rsaSvc.generateKeyPair(1024)
    rsaSvc.generateKeyPair(2048)


def testRsaExport():
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    rsaSvc.exportKeyPairToPem(pub, priv, b"password", "test_pub.pem", "test_priv.pem")

def testRsaImportExport():
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    rsaSvc.exportKeyPairToPem(pub, priv, b"password", "test_pub.pem", "test_priv.pem")
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
    msg = secrets.token_bytes(100000)
    segSvc = SegmentationService()
    chunks = segSvc.split(msg)
    reassembledMsg = segSvc.reassemble([chunk for _, chunk in chunks])
    assert msg == reassembledMsg, "error, segmentation doesnt work"
    print("success")


def testEmailService():
    message = "Some mock message".encode()
    emailSvc = EmailService()
    messageToRadix = emailSvc.toRadix64(message)
    messageFromRadix = emailSvc.fromRadix64(messageToRadix)
    assert messageFromRadix == message, "Radix error"
    print ("Success")

def e2eCoreTest():
    pgpSvc = PgpService()
    rsaSvc = RsaService()
    senderPriv, senderPub = rsaSvc.generateKeyPair(2048)
    receiverPriv, receiverPub = rsaSvc.generateKeyPair(2048)
    message = "Some mock message".encode()
    chunks = pgpSvc.pgpEncrypt(message, receiverPub, senderPriv, SendOptions())
    receivedeMsg = pgpSvc.pgpDecrypt([chunk for _, chunk in chunks], senderPub, receiverPriv)
    assert receivedeMsg == message.decode(), "e2e core test failed, messages do not match"
    print("success")

def testWrongPassword():
    rsaSvc = RsaService()
    priv, pub = rsaSvc.generateKeyPair(2048)
    rsaSvc.exportKeyPairToPem(pub, priv, b"correct_password", "test_pub.pem", "test_priv.pem")
    result = rsaSvc.importPrivateRsaKey("test_priv.pem", b"wrong_password")
    assert result is None, "expected None for wrong password"
    print("success")

def mainSvcTest():
    mainSvc = MainService()
    message = "mock message"
    rsaSvc = RsaService()
    senderPriv, senderPub = rsaSvc.generateKeyPair(2048)
    receiverPriv, receiverPub = rsaSvc.generateKeyPair(2048)
    mainSvc.send(message, "test_dest", senderPriv, receiverPub, SendOptions())
    receivedMessage = mainSvc.receive("test_dest", senderPub, receiverPriv)
    assert receivedMessage == message, "main svc doesnt work, messages dont match"
    print("success")
    
def userServiceTest():
    userSvc = UserService()
    name = "Anja"
    email = "Anja@egmail.com"
    user = userSvc.createUser(name, email)
    found = userSvc.findUserByEmail(email)
    assert found is not None, "User was not created"
    assert found.email == email, "Email doesn't match"
    assert found.name == name, "Name doesn't match"
    print("createUser ok")
    result = userSvc.deleteUser(email)
    assert result is True, "User was not deleted"
    found_after = userSvc.findUserByEmail(email)
    assert found_after is None, "User still exists after delete"
    print("deleteUser ok")
    print("success")
    


def testUserPrivateKeyRing():
    user = User("kosta","kosta012001@gmail.com")
    password = "123"
    pub,priv = user.newKeyPair(1024,password)
    ring = user.loadPrivateKeyRing()
    rsaSvc = RsaService()
    private_key = ring[-1]
    key_filename = private_key["pemFile"]
    importedPriv = rsaSvc.importPrivateRsaKey(key_filename,password.encode())
    assert importedPriv.private_numbers().d == priv.private_numbers().d, "failed , keys do not match"
    print("success")

def testUserPublicKeyRing():
    user = User("ana", "ana@gmail.com")
    password = "123"
    pub, priv = user.newKeyPair(1024, password)
    pubRing = user.loadPublicKeyRing()

    assert len(pubRing) > 0, "public key ring is empty"

    publiKey = pubRing[-1]
    assert publiKey["email"] == "ana@gmail.com", "email doesn't match"
    assert publiKey["name"] == "ana", "name doesn't match"
    assert publiKey["keySize"] == 1024, "key size mismatch"
    print("user public key success")

def testDeleteKeyPair():
    user = User("ogi", "ogi@gmail.com")
    password = "123"
    pub, priv = user.newKeyPair(1024, password)
    ring = user.loadPrivateKeyRing()
    assert len(ring) > 0, "key was not created"
    keyId = ring[-1]["keyId"]

    result = user.deleteKeyPair(ring[-1])
    assert result == True, "delete failed"
    ring_after = user.loadPrivateKeyRing()

    for k in ring_after:
        assert k["keyId"] != keyId, "key not deleted"

    print("delete success")


def testWrongDecryptionKey():
    """Decrypting with the wrong private key should raise ValueError, not crash."""
    pgpSvc = PgpService()
    rsaSvc = RsaService()
    senderPriv, senderPub = rsaSvc.generateKeyPair(2048)
    receiverPriv, receiverPub = rsaSvc.generateKeyPair(2048)
    wrongPriv, _ = rsaSvc.generateKeyPair(2048)

    chunks = pgpSvc.pgpEncrypt("secret".encode(), receiverPub, senderPriv, SendOptions())
    try:
        pgpSvc.pgpDecrypt([chunk for _, chunk in chunks], senderPub, wrongPriv)
        assert False, "expected ValueError but no exception was raised"
    except ValueError:
        print("success")


def testWrongSenderKey():
    """Verifying with the wrong sender public key should raise SignatureVerificationError."""
    pgpSvc = PgpService()
    rsaSvc = RsaService()
    senderPriv, senderPub = rsaSvc.generateKeyPair(2048)
    receiverPriv, receiverPub = rsaSvc.generateKeyPair(2048)
    _, wrongPub = rsaSvc.generateKeyPair(2048)

    chunks = pgpSvc.pgpEncrypt("secret".encode(), receiverPub, senderPriv, SendOptions())
    try:
        pgpSvc.pgpDecrypt([chunk for _, chunk in chunks], wrongPub, receiverPriv)
        assert False, "expected SignatureVerificationError but no exception was raised"
    except SignatureVerificationError:
        print("success")


def testTamperedMessage():
    """Any modification to the message file should be detected."""
    rsaSvc = RsaService()
    senderPriv, senderPub = rsaSvc.generateKeyPair(2048)
    receiverPriv, receiverPub = rsaSvc.generateKeyPair(2048)
    mainSvc = MainService()

    mainSvc.send("original", "test_tampered_msg", senderPriv, receiverPub, SendOptions())

    with open("test_tampered_msg", "rb") as f:
        data = bytearray(f.read())
    mid = len(data) // 2
    data[mid] = (data[mid] ^ 0xFF)
    with open("test_tampered_msg", "wb") as f:
        f.write(data)

    try:
        mainSvc.receive("test_tampered_msg", senderPub, receiverPriv)
        assert False, "expected exception for tampered message but none raised"
    except Exception:
        print("success")
    finally:
        os.remove("test_tampered_msg")


def testDuplicateKeyImport():
    """Importing the same public key twice should raise ValueError on the second import."""
    rsaSvc = RsaService()
    _, pub = rsaSvc.generateKeyPair(1024)
    rsaSvc.exportPublicKeyToPem(pub, "test_pub_dup.pem")

    user = User("duptest", "duptest@test.com")
    user.importPublicKey("Alice", "alice@test.com", "test_pub_dup.pem")
    try:
        user.importPublicKey("Alice", "alice@test.com", "test_pub_dup.pem")
        assert False, "expected ValueError on duplicate import but none raised"
    except ValueError:
        pass

    os.remove("test_pub_dup.pem")
    print("success")


def testE2E3DES():
    """End-to-end encrypt/decrypt using 3DES."""
    pgpSvc = PgpService()
    rsaSvc = RsaService()
    senderPriv, senderPub = rsaSvc.generateKeyPair(2048)
    receiverPriv, receiverPub = rsaSvc.generateKeyPair(2048)
    message = "Some mock message".encode()
    chunks = pgpSvc.pgpEncrypt(message, receiverPub, senderPriv, SendOptions(algorithm="3DES"))
    received = pgpSvc.pgpDecrypt([chunk for _, chunk in chunks], senderPub, receiverPriv)
    assert received == message.decode(), "3DES e2e failed: messages do not match"
    print("success")


def testMixedKeySizes():
    """Sign with 1024-bit key, encrypt for 2048-bit key — different signature size."""
    pgpSvc = PgpService()
    rsaSvc = RsaService()
    senderPriv, senderPub = rsaSvc.generateKeyPair(1024)
    receiverPriv, receiverPub = rsaSvc.generateKeyPair(2048)
    message = "Mixed key size test".encode()
    chunks = pgpSvc.pgpEncrypt(message, receiverPub, senderPriv, SendOptions())
    received = pgpSvc.pgpDecrypt([chunk for _, chunk in chunks], senderPub, receiverPriv)
    assert received == message.decode(), "mixed key size e2e failed"
    print("success")


def _roundtrip(options: SendOptions):
    pgpSvc = PgpService()
    rsaSvc = RsaService()
    senderPriv, senderPub = rsaSvc.generateKeyPair(1024)
    receiverPriv, receiverPub = rsaSvc.generateKeyPair(1024)
    message = "Options roundtrip test".encode()
    chunks = pgpSvc.pgpEncrypt(message, receiverPub, senderPriv, options)
    received = pgpSvc.pgpDecrypt([chunk for _, chunk in chunks], senderPub, receiverPriv)
    assert received == message.decode(), f"roundtrip failed for {options.__dict__}"


def testAllOptionCombinations():
    """Test every combination of sign/encrypt/compress/radix64 with both algorithms."""
    from itertools import product
    for sign, encrypt, compress, radix64 in product([True, False], repeat=4):
        algorithms = ["AES", "3DES"] if encrypt else ["AES"]
        for algorithm in algorithms:
            _roundtrip(SendOptions(
                sign=sign, encrypt=encrypt,
                compress=compress, radix64=radix64,
                algorithm=algorithm,
            ))
    print("success")


if __name__ == "__main__":
    tests = [
        ("testPrintRsa",           testPrintRsa),
        ("testRsaExport",          testRsaExport),
        ("testRsaImportExport",    testRsaImportExport),
        ("testDigialSignature",    testDigialSignature),
        ("testRsaEncryption",      testRsaEncryption),
        ("testKsEncryption",       testKsEncryption),
        ("testEncryptDecryptMessage", testEncryptDecryptMessage),
        ("testCompressDecompress", testCompressDecompress),
        ("testSegmentSvc",         testSegmentSvc),
        ("testEmailService",       testEmailService),
        ("testWrongPassword",      testWrongPassword),
        ("e2eCoreTest",            e2eCoreTest),
        ("mainSvcTest",            mainSvcTest),
        ("userServiceTest",        userServiceTest),
        ("testUserPrivateKeyRing", testUserPrivateKeyRing),
        ("testUserPublicKeyRing",  testUserPublicKeyRing),
        ("testDeleteKeyPair",      testDeleteKeyPair),
        ("testWrongDecryptionKey", testWrongDecryptionKey),
        ("testWrongSenderKey",     testWrongSenderKey),
        ("testTamperedMessage",    testTamperedMessage),
        ("testDuplicateKeyImport", testDuplicateKeyImport),
        ("testE2E3DES",            testE2E3DES),
        ("testMixedKeySizes",      testMixedKeySizes),
        ("testAllOptionCombinations", testAllOptionCombinations),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        print(f"\n--- {name} ---")
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"FAILED: {e}")
            failed += 1

    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
