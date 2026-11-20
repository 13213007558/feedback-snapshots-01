"""Isolation guarantees for per-plugin named-schema resolution.

Two platform plugins each declare a nested type named ``Invoice``. Because each
plugin owns an isolated `~marshmallow.class_registry.Registry` and selects it
through ``class Meta: registry = ...``, the same bare name resolves to a
different schema depending on the plugin. The historical process-wide registry
keeps working for code that does not opt in.
"""

import pytest

from marshmallow import Schema, class_registry, fields
from marshmallow.exceptions import RegistryError


def _plugin_schema(registry, module, name, attrs):
    """Build a schema class that belongs to one plugin's isolated registry."""
    namespace = {"__module__": module, "Meta": type("Meta", (), {"registry": registry})}
    namespace.update(attrs)
    return type(name, (Schema,), namespace)


def test_same_nested_name_resolves_to_each_plugin_own_schema():
    plugin_a = class_registry.Registry(name="plugin_a")
    plugin_b = class_registry.Registry(name="plugin_b")

    # Both plugins call their nested type "Invoice", but with different shapes.
    _plugin_schema(
        plugin_a,
        "plugin_a.schemas",
        "Invoice",
        {"amount": fields.Integer(), "currency": fields.String()},
    )
    _plugin_schema(
        plugin_b,
        "plugin_b.schemas",
        "Invoice",
        {"invoice_id": fields.UUID(), "lines": fields.Integer()},
    )

    order_a = _plugin_schema(
        plugin_a,
        "plugin_a.schemas",
        "Order",
        {"invoice": fields.Nested("Invoice")},
    )
    order_b = _plugin_schema(
        plugin_b,
        "plugin_b.schemas",
        "Order",
        {"invoice": fields.Nested("Invoice")},
    )

    payload_a = {"invoice": {"amount": 10, "currency": "USD"}}
    payload_b = {
        "invoice": {"invoice_id": "12345678-1234-5678-1234-567812345678", "lines": 3}
    }

    loaded_a = order_a().load(payload_a)
    loaded_b = order_b().load(payload_b)

    # The bare name "Invoice" was selected unambiguously per plugin.
    assert loaded_a["invoice"] == {"amount": 10, "currency": "USD"}
    assert loaded_b["invoice"]["lines"] == 3
    assert plugin_a.get_class("Invoice").__module__ == "plugin_a.schemas"
    assert plugin_b.get_class("Invoice").__module__ == "plugin_b.schemas"


def test_scoped_schemas_never_touch_the_global_registry():
    plugin = class_registry.Registry(name="private")
    scoped = _plugin_schema(
        plugin, "private_plugin.schemas", "PrivateInvoice", {"x": fields.Integer()}
    )

    assert "PrivateInvoice" not in class_registry._registry
    assert "private_plugin.schemas.PrivateInvoice" not in class_registry._registry
    assert plugin.get_class("PrivateInvoice") is scoped


def test_unauthorized_reference_raises_configuration_error():
    plugin_a = class_registry.Registry(name="plugin_a")
    plugin_b = class_registry.Registry(name="plugin_b")

    _plugin_schema(
        plugin_a, "plugin_a.schemas", "Invoice", {"amount": fields.Integer()}
    )
    _plugin_schema(plugin_b, "plugin_b.schemas", "Secret", {"token": fields.String()})

    # A schema living only in the global registry is also off-limits to a scope.
    class GlobalInvoice(Schema):
        global_field = fields.Integer()

    # Plugin B references a name it never declared and which exists elsewhere.
    rogue = _plugin_schema(
        plugin_b,
        "plugin_b.schemas",
        "RogueOrder",
        {"invoice": fields.Nested("Invoice")},
    )
    rogue_global = _plugin_schema(
        plugin_b,
        "plugin_b.schemas",
        "RogueGlobalOrder",
        {"invoice": fields.Nested("GlobalInvoice")},
    )

    with pytest.raises(RegistryError, match="not registered or authorized"):
        rogue().load({"invoice": {"amount": 1}})
    with pytest.raises(RegistryError, match="not registered or authorized"):
        rogue_global().load({"invoice": {"global_field": 1}})


def test_authorized_reference_resolves_after_registration():
    plugin = class_registry.Registry(name="plugin")
    invoice = _plugin_schema(
        plugin, "plugin.schemas", "Invoice", {"amount": fields.Integer()}
    )
    order = _plugin_schema(
        plugin, "plugin.schemas", "Order", {"invoice": fields.Nested("Invoice")}
    )

    assert order().load({"invoice": {"amount": 7}})["invoice"]["amount"] == 7
    # Full, module-qualified paths resolve within the same scope as well.
    order_full = _plugin_schema(
        plugin,
        "plugin.schemas",
        "OrderFull",
        {"invoice": fields.Nested("plugin.schemas.Invoice")},
    )
    assert order_full().load({"invoice": {"amount": 9}})["invoice"]["amount"] == 9
    assert plugin.get_class("plugin.schemas.Invoice") is invoice


def test_reloading_a_plugin_only_mutates_its_own_registry():
    plugin_a = class_registry.Registry(name="plugin_a")
    plugin_b = class_registry.Registry(name="plugin_b")

    invoice_a_v1 = _plugin_schema(
        plugin_a, "plugin_a.schemas", "Invoice", {"amount": fields.Integer()}
    )
    invoice_b = _plugin_schema(
        plugin_b, "plugin_b.schemas", "Invoice", {"lines": fields.Integer()}
    )

    # Simulate re-importing plugin A: a fresh class object from the same module.
    invoice_a_v2 = _plugin_schema(
        plugin_a,
        "plugin_a.schemas",
        "Invoice",
        {"amount": fields.Integer(), "currency": fields.String()},
    )

    assert plugin_a.get_class("Invoice") is invoice_a_v2
    assert plugin_a.get_class("Invoice") is not invoice_a_v1
    # No duplicate accumulates in the reloaded scope.
    assert len(plugin_a._registry["Invoice"]) == 1
    # The other plugin is completely untouched.
    assert plugin_b.get_class("Invoice") is invoice_b
    assert len(plugin_b._registry["Invoice"]) == 1


def test_resolution_does_not_depend_on_import_order():
    # Registry B is populated and fully resolved before plugin A even exists.
    plugin_b = class_registry.Registry(name="plugin_b_first")
    _plugin_schema(plugin_b, "plugin_b.schemas", "Invoice", {"lines": fields.Integer()})
    order_b = _plugin_schema(
        plugin_b,
        "plugin_b.schemas",
        "Order",
        {"invoice": fields.Nested("Invoice")},
    )
    assert order_b().load({"invoice": {"lines": 2}})["invoice"]["lines"] == 2

    # Only now does plugin A declare its own same-named type.
    plugin_a = class_registry.Registry(name="plugin_a_later")
    _plugin_schema(
        plugin_a, "plugin_a.schemas", "Invoice", {"amount": fields.Integer()}
    )
    order_a = _plugin_schema(
        plugin_a,
        "plugin_a.schemas",
        "Order",
        {"invoice": fields.Nested("Invoice")},
    )

    # Neither plugin's answer changed because the other got imported later.
    assert order_a().load({"invoice": {"amount": 5}})["invoice"]["amount"] == 5
    assert order_b().load({"invoice": {"lines": 4}})["invoice"]["lines"] == 4
    assert plugin_a.get_class("Invoice").__module__ == "plugin_a.schemas"
    assert plugin_b.get_class("Invoice").__module__ == "plugin_b.schemas"


def test_legacy_global_named_resolution_still_works():
    class LegacyAddress(Schema):
        city = fields.String()

    class LegacyPerson(Schema):
        address = fields.Nested("LegacyAddress")

    loaded = LegacyPerson().load({"address": {"city": "Berlin"}})
    assert loaded["address"]["city"] == "Berlin"
    assert class_registry.get_class("LegacyAddress").__name__ == "LegacyAddress"
