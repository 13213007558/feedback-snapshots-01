"""Row-level access rule for the annual review.

The rule is expressed against columns of the *history* table, so a
``deleted`` event is still filtered correctly even though its live object no
longer exists.
"""

from django.db.models import Q


def legal_department_access():
    return Q(department="LEGAL")
