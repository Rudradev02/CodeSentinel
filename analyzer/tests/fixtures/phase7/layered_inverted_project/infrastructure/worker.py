from presentation.views import render_order_page

def background_job(order_id: str):
    return render_order_page(order_id)
