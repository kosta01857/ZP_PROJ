import base64
from send_options import SendOptions

class EmailService:
    def decodeFlags(self,flags_bytes: bytes):
        
        flags = flags_bytes[0]
        encrypt = bool(flags & (1 << 0))
        sign = bool(flags & (1 << 1))
        compress = bool(flags & (1 << 2))
        radix64 = bool(flags & (1 << 3))
        algorithm = "AES" if (flags & (1 << 4)) else "3DES"

        return SendOptions(encrypt, sign, compress, radix64, algorithm)

    def encodeFlags(self, opt: SendOptions):

        flags = 0
        if opt.encrypt:
            flags |= 1 << 0
        if opt.sign:
            flags |= 1 << 1
        if opt.compress:
            flags |= 1 << 2
        if opt.radix64:
            flags |= 1 << 3
        if opt.algorithm == "AES":
            flags |= 1 << 4

        return flags.to_bytes(1, byteorder="big")
    
    #Enkoduje opcije i spaja ih sa porukom
    def encodeOptions(self,message:bytes, options:SendOptions)->bytes:
        opt = self.encodeFlags(options)
        return opt + message
    #Dekoduje: prvi bajt flag opcije, ostatak je poruka

    def decodeOptions(self, originalMessage:bytes)->tuple[bytes,SendOptions]:
        optionBytes = originalMessage[0:1]
        message = originalMessage[1:]
        options = self.decodeFlags(optionBytes)
        return message, options

    def toRadix64(self, message: bytes)-> bytes:
        return base64.b64encode(message)

    def fromRadix64(self, originalMessage: bytes)-> bytes:
        message = base64.b64decode(originalMessage)
        return  message
    

