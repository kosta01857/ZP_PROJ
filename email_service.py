import base64

class EmailService:
    def toRadix64(self, message: bytes, algorithm: str)-> str:
        algorithmByte = (
            b'\x01'
            if algorithm == "AES"
            else b'\x02'
        )
        return base64.b64encode(algorithmByte + message).decode("ascii")

    def fromRadix64(self, message:str)-> tuple[bytes,str]:

        rawMessage = base64.b64decode(message.encode("ascii"))
        algorithmBytes = rawMessage[0]
        algorithm = ""
        message = rawMessage[1:]
        if algorithmBytes ==  1:
            algorithm = "AES"
        else:
            algorithm = "3DES"
        
        return  message, algorithm 

