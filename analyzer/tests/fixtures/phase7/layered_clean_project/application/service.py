from domain.model import UserEntity

class UserService:
    def create_user(self, user_id: str, email: str) -> UserEntity:
        return UserEntity(user_id, email)
