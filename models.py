# models.py
# Defines the data models used in the interface.

import json

class Config:
    def __init__(self, data):
        self.data = data
    def __getattr__(self, name):
        item = self.data[name]
        if isinstance(item, (dict, list, tuple)):
            return Config(item)
        else:
            return item
    def __getitem__(self, index):
        item = self.data[index]
        if isinstance(item, (dict, list, tuple)):
            return Config(item)
        else:
            return item
    @staticmethod
    def getConfig(filename):
        config_file = open(filename)
        data = json.load(config_file)
        config_file.close()
        return Config(data)

config = Config.getConfig("config.json")

class User:
    def __init__(self, username):
        self.username = username
    def toJsonObject(self):
        return {
            'username': self.username
        }

class UploadResult:
    def __init__(self, success, data):
        self.success = success
        self.data = data
    def toJson(self):
        return json.dumps({"success": self.success, "data": self.data})

class FaceData:
    def __init__(self, user_id, data):
        self.user_id = user_id
        self.data = data
