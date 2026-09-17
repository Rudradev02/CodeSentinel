from services.user_service import validate_user_access

class User:
    def __init__(self, id: int, name: str):
        self.id = id
        self.name = name

    def is_valid(self):
        return validate_user_access(self)
