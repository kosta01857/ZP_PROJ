import json
import os
from user import User


class UserService:

    def __init__(self):
        self.users = []
        self.BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        self.storagePath = os.path.join(self.BASE_DIR, "storage")
        self.usersFile = os.path.join(self.storagePath, "users.json")
        os.makedirs(self.storagePath, exist_ok=True)
        if not os.path.exists(self.usersFile):
            with open(self.usersFile, "w") as f:
                json.dump([], f, indent=4)
        self.loadUsers()

    def loadUsers(self):
        self.users.clear()
        with open(self.usersFile, "r") as f: 
            data = json.load(f)

        for userData in data:
            user = User(
                userData["name"],
                userData["email"]
            )
            self.users.append(user)

    def saveUsers(self):
        userList = []
        for user in self.users:
            userList.append({
                "name": user.name,
                "email": user.email
            })

        with open(self.usersFile, "w") as f:
            json.dump(userList, f, indent=4)

    def createUser(self, name:str, email:str)-> User:

        if self.findUserByEmail(email) is not None:
            raise Exception("Email already taken.")

        user = User(name, email)
        self.users.append(user)
        self.saveUsers()
        return user

    def deleteUser(self, email:str)-> bool:

        user = self.findUserByEmail(email)
        if user is None: return False
        self.users.remove(user)
        self.saveUsers()
        return True

    def findUserByEmail(self, email:str)-> User:
        for user in self.users:
            if user.email == email:
                return user

        return None

    def getUsers(self):
        return self.users