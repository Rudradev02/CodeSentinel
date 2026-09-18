from auth.tokens import verify_token

def process_invoice(token: str):
    return verify_token(token)
