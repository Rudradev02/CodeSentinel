from infrastructure.repo import DatabaseConnection

class OrderEntity:
    def __init__(self, order_id: str):
        self.order_id = order_id
        self.db = DatabaseConnection()
