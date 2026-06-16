import rsa

class RsaService:
    def generateKeyPair(self, size):
        assert size == 1024 or size == 2048 , 'key size not valid'
        public, private = rsa.newkeys(nbits=size)
        return private, public



