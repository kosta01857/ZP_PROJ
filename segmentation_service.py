class SegmentationService:

    def split(self, message: bytes) -> list[bytes]:
        chunks = []
        byte_length = len(message)

        while byte_length > 50000:
            chunk = message[0:50000]
            chunks.append(chunk)
            message = message[50000:]
            byte_length = len(message)
        chunks.append(message)
        return chunks


    def reassemble(self, chunks: list[bytes]) -> bytes:
           message = bytes()
           for chunk in chunks:
                message += chunk
           return message


