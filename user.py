from rsa_service import RsaService
import os
import uuid
import hashlib
from pathlib import Path
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class User:
    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        self.path = os.path.join(BASE_DIR, "storage", "users", self.name)
        self.publicKeyRingPath = os.path.join(BASE_DIR, "storage", "users",
                                                   self.name, "public_ring")
        self.privateKeyRingPath = os.path.join(BASE_DIR, "storage", "users",
                                                  self.name, "private_ring")
        self.createFolders()
        self.publicJson = os.path.join(self.publicKeyRingPath,"public_keys.json")
        self.privateJson = os.path.join(self.privateKeyRingPath,"private_keys.json")
        self._initialize_json_file(Path(self.privateJson))
        self._initialize_json_file(Path(self.publicJson))
        self.rsaSvc = RsaService()

    
    
    def _deriveKeyId(self, pub: rsa.RSAPublicKey) -> str:
        pub_bytes = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha1(pub_bytes).hexdigest()[-16:]

    def createFolders(self):
        os.makedirs(self.path, exist_ok=True)
        os.makedirs(self.publicKeyRingPath, exist_ok=True)
        os.makedirs(self.privateKeyRingPath, exist_ok=True)

    def loadPrivateKeyRing(self) -> list[dict]:
        with open(self.privateJson, "r") as f:
            return json.load(f)

    def loadPublicKeyRing(self) -> list[dict]:
        with open(self.publicJson, "r") as f:
            return json.load(f)

    
    def newKeyPair(self, size:int, password:str) -> tuple[rsa.RSAPublicKey,rsa.RSAPrivateKey]:
        priv, pub = self.rsaSvc.generateKeyPair(size)
        keyId = self._deriveKeyId(pub)
        fileUuid = uuid.uuid4()
        filename = os.path.join(self.privateKeyRingPath,f"{fileUuid}.pem")
        filenamePub = os.path.join(self.privateKeyRingPath,f"{fileUuid}_pub.pem")
        self.rsaSvc.exportPrivateKeyToPem(priv,password.encode(),filename)
        self.rsaSvc.exportPublicKeyToPem(pub,filenamePub)
        privateKey = {
            "keyId" : keyId,
            "keySize": size,
            "pemFile" : filename
        }
        publicKey = {
            "keyId" : keyId,
            "name": self.name,
            "email" : self.email,
            "keySize": pub.key_size,
            "pemFile" : filenamePub
        }
        keys = self.loadPrivateKeyRing()
        keys.append(privateKey)
        with open(self.privateJson, "w") as f:
            json.dump(keys,f,indent=4)

        keysPub = self.loadPublicKeyRing()
        keysPub.append(publicKey)
        with open(self.publicJson, "w") as f:
            json.dump(keysPub,f,indent=4)
        return pub,priv

      
    def _initialize_json_file(self, filePath: Path):
            """Initializes a file with an empty JSON array if it's new/empty."""
            if not filePath.exists() or filePath.stat().st_size == 0:
                with open(filePath, "w", encoding="utf-8") as f:
                    json.dump([], f) 

    def importPublicKey(self, username: str, email:str, filename:str) -> rsa.RSAPublicKey:
        pub =  self.rsaSvc.importPublicRsaKey(filename)
        keyId = self._deriveKeyId(pub)
        fileUuid = uuid.uuid4()
        destFilename = os.path.join(self.publicKeyRingPath,f"{fileUuid}.pem")
        self.rsaSvc.exportPublicKeyToPem(pub, destFilename)
        publicKey = {
            "keyId" : keyId,
            "name": username,
            "email" : email,
            "keySize": pub.key_size,
            "pemFile" : destFilename
        }
        keys = self.loadPublicKeyRing()
        keys.append(publicKey)
        with open(self.publicJson, "w") as f:
            json.dump(keys,f,indent=4)
        return pub