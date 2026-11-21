from datetime import timedelta

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings
from django.utils import timezone

from simple_history.models import HistoricalRecords
from simple_history.tests.models import CustomerProfile
from simple_history.utils import (
    apply_masked_fields_to_history_attrs,
    bulk_create_with_history,
    bulk_update_with_history,
)


class FieldMaskingTestCase(TestCase):
    """
    Fields configured via ``SIMPLE_HISTORY_FIELD_MASKING`` must never have
    their values persisted in the history table; only a ``<field>_changed``
    flag is recorded. Normal saves and bulk writes must behave consistently.
    """

    def assert_history_rows_masked(self, queryset):
        """Every persisted history row stores NULL for the masked fields."""
        rows = queryset.values(
            "national_id", "home_phone", "national_id_changed", "home_phone_changed"
        )
        self.assertTrue(rows.exists())
        for row in rows:
            self.assertIsNone(row["national_id"])
            self.assertIsNone(row["home_phone"])
        return list(rows)

    def test_masking_configuration_applied_to_history_model(self):
        history_model = CustomerProfile.history.model
        self.assertEqual(
            history_model._history_masked_fields, ["home_phone", "national_id"]
        )
        self.assertTrue(history_model._meta.get_field("national_id").null)
        self.assertTrue(history_model._meta.get_field("home_phone").null)
        self.assertEqual(
            history_model._meta.get_field("national_id_changed").get_internal_type(),
            "BooleanField",
        )
        self.assertEqual(
            history_model._meta.get_field("home_phone_changed").get_internal_type(),
            "BooleanField",
        )

    def test_create_masks_values_and_sets_flags(self):
        CustomerProfile.objects.create(
            name="Ada", national_id="ID-SECRET-1", home_phone="555-1"
        )
        rows = self.assert_history_rows_masked(CustomerProfile.history.all())
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0]["national_id_changed"], True)
        self.assertIs(rows[0]["home_phone_changed"], True)

    def test_create_with_empty_masked_fields_sets_flag_false(self):
        CustomerProfile.objects.create(name="Ada")
        rows = self.assert_history_rows_masked(CustomerProfile.history.all())
        self.assertIs(rows[0]["national_id_changed"], False)
        self.assertIs(rows[0]["home_phone_changed"], False)

    def test_update_records_change_flag_without_old_value(self):
        profile = CustomerProfile.objects.create(name="Ada", national_id="ID-SECRET-1")
        profile.national_id = "ID-SECRET-2"
        profile.save()
        # Unrelated update: the masked field did not change
        profile.name = "Ada Lovelace"
        profile.save()

        rows = CustomerProfile.history.order_by("history_date", "history_id").values(
            "history_type", "national_id", "national_id_changed", "home_phone_changed"
        )
        self.assertEqual([row["history_type"] for row in rows], ["+", "~", "~"])
        self.assertIs(rows[1]["national_id_changed"], True)
        self.assertIs(rows[2]["national_id_changed"], False)
        self.assertIs(rows[1]["home_phone_changed"], False)
        for row in rows:
            self.assertIsNone(row["national_id"])

        # The restricted values must not appear anywhere in the history table
        self.assertFalse(
            CustomerProfile.history.filter(
                national_id__in=["ID-SECRET-1", "ID-SECRET-2"]
            ).exists()
        )

    def test_update_via_save_with_update_fields(self):
        profile = CustomerProfile.objects.create(name="Ada", home_phone="555-1")
        profile.name = "Grace"
        profile.save(update_fields=["name"])
        record = CustomerProfile.history.order_by(
            "-history_date", "-history_id"
        ).first()
        self.assertIs(record.home_phone_changed, False)
        self.assertIsNone(record.home_phone)

    def test_delete_record_is_masked(self):
        profile = CustomerProfile.objects.create(name="Ada", national_id="ID-SECRET-1")
        profile.delete()
        record = CustomerProfile.history.get(history_type="-")
        self.assertIsNone(record.national_id)
        self.assertIs(record.national_id_changed, False)

    def test_bulk_create_with_history_masks_values(self):
        objs = [
            CustomerProfile(name="bulk-a", national_id="ID-BULK-1"),
            CustomerProfile(name="bulk-b", home_phone="555-9"),
        ]
        bulk_create_with_history(objs, CustomerProfile)

        rows = self.assert_history_rows_masked(
            CustomerProfile.history.filter(history_type="+")
        )
        rows_by_flag = {row["national_id_changed"] for row in rows}
        self.assertEqual(rows_by_flag, {True, False})
        self.assertFalse(
            CustomerProfile.history.filter(national_id="ID-BULK-1").exists()
        )

    def test_bulk_update_with_history_matches_normal_save(self):
        changed = CustomerProfile.objects.create(name="a", national_id="ID-OLD-1")
        untouched = CustomerProfile.objects.create(name="b", national_id="ID-OLD-2")

        changed.national_id = "ID-NEW-1"
        untouched.name = "b-renamed"
        bulk_update_with_history(
            [changed, untouched],
            CustomerProfile,
            fields=["name", "national_id"],
        )

        changed_record = changed.history.first()
        self.assertEqual(changed_record.history_type, "~")
        self.assertIsNone(changed_record.national_id)
        self.assertIs(changed_record.national_id_changed, True)

        untouched_record = untouched.history.first()
        self.assertEqual(untouched_record.history_type, "~")
        self.assertIsNone(untouched_record.national_id)
        self.assertIs(untouched_record.national_id_changed, False)

        self.assertFalse(
            CustomerProfile.history.filter(
                national_id__in=["ID-OLD-1", "ID-OLD-2", "ID-NEW-1"]
            ).exists()
        )

    def test_instance_readback_does_not_expose_masked_values(self):
        profile = CustomerProfile.objects.create(name="Ada", national_id="ID-SECRET-1")
        profile.national_id = "ID-SECRET-2"
        profile.save()

        first_record = CustomerProfile.history.order_by(
            "history_date", "history_id"
        ).first()
        instance = first_record.instance
        self.assertIsNone(instance.national_id)
        self.assertIsNone(instance.home_phone)
        # Non-masked fields still read back normally
        self.assertEqual(instance.name, "Ada")

    def test_as_of_does_not_expose_restricted_old_values(self):
        create_date = timezone.now()
        profile = CustomerProfile(
            name="Ada", national_id="ID-SECRET-OLD", home_phone="555-OLD"
        )
        profile._history_date = create_date
        profile.save()
        profile.national_id = "ID-SECRET-NEW"
        profile.home_phone = "555-NEW"
        profile._history_date = create_date + timedelta(minutes=1)
        profile.save()

        between = create_date + timedelta(seconds=30)

        # Model-level as_of queryset
        snapshots = CustomerProfile.history.as_of(between)
        snapshot = snapshots.get(pk=profile.pk)
        self.assertIsNone(snapshot.national_id)
        self.assertIsNone(snapshot.home_phone)
        self.assertEqual(snapshot.name, "Ada")

        # Instance-level as_of
        snapshot = profile.history.as_of(between)
        self.assertIsNone(snapshot.national_id)
        self.assertIsNone(snapshot.home_phone)

        # No historical record reachable through as_of contains the old values
        for record in CustomerProfile.history.all():
            self.assertNotIn(record.national_id, ("ID-SECRET-OLD", "ID-SECRET-NEW"))
            self.assertNotIn(record.home_phone, ("555-OLD", "555-NEW"))

    def test_diff_against_does_not_leak_masked_values(self):
        profile = CustomerProfile.objects.create(name="Ada", national_id="ID-SECRET-1")
        profile.national_id = "ID-SECRET-2"
        profile.save()

        new_record, old_record = CustomerProfile.history.all()[:2]
        delta = new_record.diff_against(old_record)
        self.assertNotIn("national_id", delta.changed_fields)
        self.assertNotIn("home_phone", delta.changed_fields)


class MaskedFieldsConfigurationTestCase(TestCase):
    """Configuration handling for masked fields."""

    def test_masked_fields_option_merges_with_app_setting(self):
        records = HistoricalRecords(masked_fields=["name"])
        self.assertEqual(
            records.get_masked_fields(CustomerProfile),
            ["home_phone", "name", "national_id"],
        )

    def test_unknown_masked_field_option_raises(self):
        records = HistoricalRecords(masked_fields=["does_not_exist"])
        with self.assertRaises(ImproperlyConfigured):
            records.get_masked_fields(CustomerProfile)

    def test_unknown_masked_field_setting_raises(self):
        with override_settings(
            SIMPLE_HISTORY_FIELD_MASKING={"tests": {"CustomerProfile": ["nope"]}}
        ):
            with self.assertRaises(ImproperlyConfigured):
                HistoricalRecords().get_masked_fields(CustomerProfile)

    def test_update_flag_unknown_when_old_value_not_captured(self):
        history_model = CustomerProfile.history.model
        profile = CustomerProfile(name="Ada", national_id="ID-SECRET-1")
        attrs = {"national_id": "ID-SECRET-1"}
        apply_masked_fields_to_history_attrs(history_model, profile, attrs, "~")
        self.assertIsNone(attrs["national_id"])
        self.assertIsNone(attrs["national_id_changed"])
