from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, CourseViewSet, EventViewSet, TaskViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'courses', CourseViewSet)
router.register(r'events', EventViewSet)
router.register(r'tasks', TaskViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
