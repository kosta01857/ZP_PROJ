from domain import User
class SegmentationService:
    def resolveFileName(self, user: User) -> str:
        return "testfile_segmentation"

    def split(self, message: str, user: User):
        chunks = []
        byte_length = len(message.encode('utf-8'))

        while byte_length > 50000:
            chunk = message[0:50000]
            chunks.append(chunk)
            message = message[50000:]
            byte_length = len(message.encode('utf-8'))
        chunks.append(message)

        fileName = self.resolveFileName(user)
        with open(fileName, "w") as f:
            for chunk in chunks:
                f.write(chunk + "\n")

    def reassemble(self, user: User) -> str:
        fileName = self.resolveFileName(user)
        with open(fileName, "r") as f:
            return f.read().replace("\n", "")


