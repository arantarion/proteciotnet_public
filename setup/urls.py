from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('', include('proteciotnet_server.urls')),
    path('report/', include('proteciotnet_server.urls')),
    path('admin/', admin.site.urls),
]
