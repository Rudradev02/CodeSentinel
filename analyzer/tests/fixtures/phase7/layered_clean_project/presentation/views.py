from application.service import UserService

def get_user_view(user_id: str):
    service = UserService()
    return service.create_user(user_id, "user@example.com")
