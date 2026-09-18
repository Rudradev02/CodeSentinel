from services.math_helpers import calculate_tax

def compute_total(subtotal: float) -> float:
    return subtotal + calculate_tax(subtotal)
