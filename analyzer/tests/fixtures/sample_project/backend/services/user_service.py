from models.user import User

def get_user(user_id: int):
    return User(id=user_id, name="Alice")

def validate_user_access(user: User):
    return user.id > 0
