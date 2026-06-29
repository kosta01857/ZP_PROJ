from rsa_service import RsaService
import os
import uuid
from pathlib import Path
import json
from cryptography.hazmat.primitives.asymmetric import rsa

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
        rsaSvc = RsaService()
        priv, pub = rsaSvc.generateKeyPair(size)
        keyId = uuid.uuid4()
        filename = os.path.join(self.privateKeyRingPath,f"{keyId}.pem")
        rsaSvc.exportPrivateKeyToPem(priv,password.encode(),filename)
        rsaSvc.exportPublicKeyToPem(pub,filename)
        privateKey = {
            "keyID" : f"{keyId}",
            "keySize": size,
            "pemFile" : filename
        }
        publicKey = {
            "keyID": f"{keyId}",
            "name": self.name,
            "email": self.email,
            "keySize": size
        }
        keys = self.loadPrivateKeyRing()
        keys.append(privateKey)
        with open(self.privateJson, "w") as f:
            json.dump(keys,f,indent=4)

        pubKeys = []

        if os.path.exists(self.publicJson):
            with open(self.publicJson, "r") as f:
                pubKeys = json.load(f)

        pubKeys.append(publicKey)

        with open(self.publicJson, "w") as f:
            json.dump(pubKeys, f, indent=4)

        return pub,priv

      
    def _initialize_json_file(self, filePath: Path):
            if not filePath.exists() or filePath.stat().st_size == 0:
                with open(filePath, "w", encoding="utf-8") as f:
                    json.dump([], f) 
    
    def deleteKeyPair(self, keyID: str) -> bool:
        privKeys = self.loadPrivateKeyRing()
        keyToDel = None
        for key in privKeys:
            if key["keyID"] == keyID:
                keyToDel = key
                break

        if keyToDel is None: return False
        pemPath = keyToDel["pemFile"]
        if os.path.exists(pemPath):
            os.remove(pemPath)

        newList = []
        for k in privKeys:
            if k["keyID"] != keyID:
                newList.append(k)
        privKeys = newList

        with open(self.privateJson, "w") as f:
            json.dump(privKeys, f, indent=4)

        if os.path.exists(self.publicJson):
            with open(self.publicJson, "r") as f:
                pubKeys = json.load(f)

            newList = []
            for k in pubKeys:
                if k["keyID"] != keyID:
                    newList.append(k)
            pubKeys = newList

            with open(self.publicJson, "w") as f:
                json.dump(pubKeys, f, indent=4)

        return True
