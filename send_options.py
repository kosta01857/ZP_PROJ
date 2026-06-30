class SendOptions:
    def __init__(self, encrypt=True, sign=True, compress=True, radix64=True, algorithm="AES"):
        self.encrypt = encrypt
        self.sign = sign
        self.compress = compress
        self.radix64 = radix64
        self.algorithm = algorithm
    
    
    