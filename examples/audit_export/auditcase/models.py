from django.db import models

from simple_history.models import HistoricalRecords


class CaseFile(models.Model):
    """A tracked archive object whose raw content must never be exported."""

    case_secret = models.CharField(max_length=200)
    department = models.CharField(max_length=50)
    approved = models.BooleanField(default=False)

    history = HistoricalRecords()
