import zlib
# Koristi zlib da kompresuje i dekompresuje (zip)
class CompressionService:

    def compress(self, message: bytes) -> bytes:
        return zlib.compress(message)

    def decompress(self, message: bytes) -> bytes:
        return zlib.decompress(message)
