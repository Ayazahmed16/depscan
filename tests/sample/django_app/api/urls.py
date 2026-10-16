from django.urls import path, re_path

from .views import reports, status

urlpatterns = [
    path('reports/', reports),
    re_path(r'^status/$', status),
]
