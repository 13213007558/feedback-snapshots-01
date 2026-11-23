from __future__ import annotations

from django.urls import path

from csp.tests import views

urlpatterns = [
    path("django/direct/<int:show_scripts>/", views.django_direct),
    path("django/deferred/<int:show_scripts>/", views.django_deferred),
    path("django/report-tweak/<int:show_scripts>/", views.django_report_tweak),
    path("jinja/direct/<int:show_scripts>/", views.jinja_direct),
    path("jinja/deferred/<int:show_scripts>/", views.jinja_deferred),
]
