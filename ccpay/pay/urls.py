from . import views as pay_view
from django.urls import path


urlpatterns = [
    path('', pay_view.checkout, name='checkout'),
    path('payment_success/', pay_view.payment_success, name='payment_success'),
    path('payment_cancel/', pay_view.payment_cancel, name='payment_cancel'),
]