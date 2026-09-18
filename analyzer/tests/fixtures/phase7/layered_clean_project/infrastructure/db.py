from domain.model import UserEntity

class UserRepository:
    def save(self, user: UserEntity):
        return f"saved {user.user_id}"
