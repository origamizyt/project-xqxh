# models.py
# Defines the data models used in the interface.

class User:
    def __init__(self, username):
        self.username = username
    def toJsonObject(self):
        return {
            'username': self.username
        }