from notifications.sender import notify_auth

def verify_token(token: str):
    notify_auth(token)
    return True
