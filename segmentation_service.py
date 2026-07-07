class SegmentationService:
#Deli na chunkove od 50000, pravi listu tuplova gde je prvi element duzina chunka, drugi chunk
    def split(self, message: bytes) -> list[tuple[int,bytes]]:
        chunks = []
        while len(message) > 50000:
            chunk = message[:50000]
            chunks.append((len(chunk), chunk))
            message = message[50000:]
        chunks.append((len(message), message))
        return chunks


    def reassemble(self, chunks: list[bytes]) -> bytes:
           message = bytes()
           for chunk in chunks:
                message += chunk
           return message


