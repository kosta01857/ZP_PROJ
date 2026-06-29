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
        self.public_key_ring_path = os.path.join(BASE_DIR, "storage", "users",
                                                   self.name, "public_ring")
        self.private_key_ring_path = os.path.join(BASE_DIR, "storage", "users",
                                                  self.name, "private_ring")
        self.createFolders()
        self.public_json = os.path.join(self.public_key_ring_path,"public_keys.json")
        self.private_json = os.path.join(self.private_key_ring_path,"private_keys.json")
        self._initialize_json_file(Path(self.private_json))
        self._initialize_json_file(Path(self.public_json))

    
    
    def createFolders(self):
        os.makedirs(self.path, exist_ok=True)
        os.makedirs(self.public_key_ring_path, exist_ok=True)
        os.makedirs(self.private_key_ring_path, exist_ok=True)

    
    def newKeyPair(self, size:int, password:str) -> tuple[rsa.RSAPublicKey,rsa.RSAPrivateKey]:
        rsaSvc = RsaService()
        priv, pub = rsaSvc.generateKeyPair(size)
        key_id = uuid.uuid4()
        filename = os.path.join(self.private_key_ring_path,f"{key_id}.pem")
        rsaSvc.exportPrivateKeyToPem(priv,password.encode(),filename)
        private_key = {
            "key_id" : f"{key_id}",
            "key_size": size,
            "pem_file" : filename
        }
        keys = []
        with open(self.private_json, "r") as f:
            keys = json.load(f)
        keys.append(private_key)
        with open(self.private_json, "w") as f:
            json.dump(keys,f,indent=4)
        return pub,priv

    def loadPrivateKeyRing(self) -> list[dict]:
        with open(self.private_json, "r") as f:
            return json.load(f)
      
    def _initialize_json_file(self, file_path: Path):
            """Initializes a file with an empty JSON array if it's new/empty."""
            if not file_path.exists() or file_path.stat().st_size == 0:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump([], f) 