import base64

class EmailService:
    def toRadix64(self, message: bytes)-> str:
        return base64.b64encode(message).decode("utf-8")

    def fromRadix64(self, message:str)-> bytes:
        return base64.b64decode(message.encode("utf-8"))

