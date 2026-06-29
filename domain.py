from rsa_service import RsaService
import os
import uuid
class User:
    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        self.path = os.path.join(BASE_DIR, "storage", "users", self.name)
        self.createFolders()
        #self.getOtherPublicKeys()

    
    
    
    def createFolders(self):
        os.makedirs(self.path, exist_ok=True)
        os.makedirs(os.path.join(self.path, "public_ring"), exist_ok=True)
        os.makedirs(os.path.join(self.path, "private_ring"), exist_ok=True)

    
    def newKeyPair(self, size:int, password:str):
        rsaSvc = RsaService()
        priv, pub = rsaSvc.generateKeyPair(size)
        filename = f"{uuid.uuid4()}"
        rsaSvc.exportKeyPairToPem(pub,priv,password.encode(),filename)
      
    

    
       
        
    