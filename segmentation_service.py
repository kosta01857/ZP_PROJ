from user import User
class SegmentationService:

    def split(self, message: str) -> list[str]:
        chunks = []
        byte_length = len(message.encode('ascii'))

        while byte_length > 50000:
            chunk = message[0:50000]
            chunks.append(chunk)
            message = message[50000:]
            byte_length = len(message.encode('ascii'))
        chunks.append(message)
        return chunks


    def reassemble(self, chunks: list[str]) -> str:
           message = "" 
           for chunk in chunks:
                message += chunk
           message.replace("\n","")
           return message


