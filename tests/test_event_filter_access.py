import asyncio

import pytest

from asyncua import Server, ua
from asyncua.server.event_filter_access import (
    EventFieldAccess,
    EventFilterAccessError,
    EventFieldAccessPolicy,
    EventFilterAccessValidator,
)

pytestmark = pytest.mark.asyncio


def _simple_operand(type_nodeid: ua.NodeId, namespace: int, name: str) -> ua.SimpleAttributeOperand:
    operand = ua.SimpleAttributeOperand()
    operand.TypeDefinitionId = type_nodeid
    operand.BrowsePath = [ua.QualifiedName(name, namespace)]
    operand.AttributeId = ua.AttributeIds.Value
    return operand


@pytest.fixture
async def record_event_server():
    server = Server()
    await server.init()
    namespace = await server.register_namespace("urn:record-event-filter")
    event_type = await server.create_custom_event_type(
        namespace,
        "RecordEvent",
        ua.ObjectIds.BaseEventType,
        [("PublicTemperature", ua.VariantType.Double), ("PrivateTestField", ua.VariantType.String)],
    )
    yield server, namespace, event_type
    await server.stop()


@pytest.fixture
async def subscription(record_event_server):
    server, _, _ = record_event_server
    params = ua.CreateSubscriptionParameters()
    params.RequestedPublishingInterval = 0
    params.RequestedLifetimeCount = 1000
    params.RequestedMaxKeepAliveCount = 100
    published_events: list[ua.EventFieldList] = []

    async def publish_callback(result, requestdata=None):
        for notification_data in result.NotificationMessage.NotificationData:
            if isinstance(notification_data, ua.EventNotificationList):
                published_events.extend(notification_data.Events)

    result = await server.iserver.isession.create_subscription(params, callback=publish_callback)
    return server, result.SubscriptionId, published_events


async def _create_event_monitored_item(server: Server, subscription_id: int, event_filter: ua.EventFilter,
                                       handle: int) -> ua.MonitoredItemCreateResult:
    params = ua.CreateMonitoredItemsParameters()
    params.SubscriptionId = subscription_id
    item = ua.MonitoredItemCreateRequest()
    item.ItemToMonitor.NodeId = ua.NodeId(ua.ObjectIds.Server)
    item.ItemToMonitor.AttributeId = ua.AttributeIds.EventNotifier
    item.MonitoringMode = ua.MonitoringMode.Reporting
    item.RequestedParameters.ClientHandle = handle
    item.RequestedParameters.Filter = event_filter
    params.ItemsToCreate = [item]
    results = await server.iserver.isession.create_monitored_items(params)
    return results[0]


async def test_resolvable_select_clause_admitted_without_policy(record_event_server):
    server, namespace, event_type = record_event_server
    validator = EventFilterAccessValidator(server.iserver.aspace)
    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [_simple_operand(event_type.nodeid, namespace, "PublicTemperature")]

    validator.validate_filter(event_filter)


async def test_unknown_browse_path_is_rejected(record_event_server):
    server, namespace, event_type = record_event_server
    validator = EventFilterAccessValidator(server.iserver.aspace)
    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [_simple_operand(event_type.nodeid, namespace, "DoesNotExist")]

    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(event_filter)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadNoMatch)


async def test_unknown_type_definition_is_rejected(record_event_server):
    server, namespace, _ = record_event_server
    validator = EventFilterAccessValidator(server.iserver.aspace)
    operand = _simple_operand(ua.NodeId(999_999, namespace), namespace, "PublicTemperature")
    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [operand]

    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(event_filter)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown)


async def test_non_event_type_definition_is_rejected(record_event_server):
    server, namespace, _ = record_event_server
    validator = EventFilterAccessValidator(server.iserver.aspace)
    plain_object = await server.nodes.objects.add_object(namespace, "PlainObject")
    operand = ua.SimpleAttributeOperand()
    operand.TypeDefinitionId = plain_object.nodeid
    operand.AttributeId = ua.AttributeIds.NodeId
    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [operand]

    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(event_filter)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadTypeDefinitionInvalid)


async def test_denied_select_clause_is_rejected(record_event_server):
    server, namespace, event_type = record_event_server
    private_operand = _simple_operand(event_type.nodeid, namespace, "PrivateTestField")
    policy = EventFieldAccessPolicy()
    policy.deny(EventFieldAccess.from_operand(private_operand))
    validator = EventFilterAccessValidator(server.iserver.aspace, policy)
    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [private_operand]

    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(event_filter)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)


async def test_denied_field_in_where_clause_is_rejected(record_event_server):
    server, namespace, event_type = record_event_server
    private_operand = _simple_operand(event_type.nodeid, namespace, "PrivateTestField")
    public_operand = _simple_operand(event_type.nodeid, namespace, "PublicTemperature")
    policy = EventFieldAccessPolicy()
    policy.deny(EventFieldAccess.from_operand(private_operand))
    validator = EventFilterAccessValidator(server.iserver.aspace, policy)

    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [public_operand]
    element = ua.ContentFilterElement()
    element.FilterOperator = ua.FilterOperator.Equals
    element.FilterOperands = [private_operand, ua.LiteralOperand(ua.Variant("secret"))]
    event_filter.WhereClause.Elements = [element]

    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(event_filter)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)


async def test_denied_field_behind_element_operand_is_rejected(record_event_server):
    server, namespace, event_type = record_event_server
    private_operand = _simple_operand(event_type.nodeid, namespace, "PrivateTestField")
    public_operand = _simple_operand(event_type.nodeid, namespace, "PublicTemperature")
    policy = EventFieldAccessPolicy()
    policy.deny(EventFieldAccess.from_operand(private_operand))
    validator = EventFilterAccessValidator(server.iserver.aspace, policy)

    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [public_operand]
    inner = ua.ContentFilterElement()
    inner.FilterOperator = ua.FilterOperator.IsNull
    inner.FilterOperands = [private_operand]
    outer = ua.ContentFilterElement()
    outer.FilterOperator = ua.FilterOperator.Not
    outer.FilterOperands = [ua.ElementOperand(Index=0)]
    event_filter.WhereClause.Elements = [inner, outer]

    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(event_filter)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)


async def test_allowlist_rejects_unlisted_field(record_event_server):
    server, namespace, event_type = record_event_server
    public_operand = _simple_operand(event_type.nodeid, namespace, "PublicTemperature")
    private_operand = _simple_operand(event_type.nodeid, namespace, "PrivateTestField")
    policy = EventFieldAccessPolicy(allow_by_default=False)
    policy.allow_operand(public_operand)
    validator = EventFilterAccessValidator(server.iserver.aspace, policy)

    allowed = ua.EventFilter()
    allowed.SelectClauses = [public_operand]
    validator.validate_filter(allowed)

    denied = ua.EventFilter()
    denied.SelectClauses = [private_operand]
    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(denied)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)


async def test_legal_public_predicate_keeps_short_circuit_operators(record_event_server):
    server, namespace, event_type = record_event_server
    public_operand = _simple_operand(event_type.nodeid, namespace, "PublicTemperature")
    validator = EventFilterAccessValidator(server.iserver.aspace)

    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [public_operand]
    greater = ua.ContentFilterElement()
    greater.FilterOperator = ua.FilterOperator.GreaterThan
    greater.FilterOperands = [public_operand, ua.LiteralOperand(ua.Variant(100.0))]
    negation = ua.ContentFilterElement()
    negation.FilterOperator = ua.FilterOperator.Not
    negation.FilterOperands = [ua.ElementOperand(Index=0)]
    event_filter.WhereClause.Elements = [greater, negation]

    validator.validate_filter(event_filter)


async def test_unsupported_operand_type_is_rejected(record_event_server):
    server, namespace, event_type = record_event_server
    public_operand = _simple_operand(event_type.nodeid, namespace, "PublicTemperature")
    validator = EventFilterAccessValidator(server.iserver.aspace)

    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [public_operand]
    element = ua.ContentFilterElement()
    element.FilterOperator = ua.FilterOperator.Equals
    attribute_operand = ua.AttributeOperand()
    attribute_operand.NodeId = event_type.nodeid
    element.FilterOperands = [attribute_operand, ua.LiteralOperand(ua.Variant(1))]
    event_filter.WhereClause.Elements = [element]

    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(event_filter)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadFilterOperandInvalid)


async def test_index_range_is_rejected(record_event_server):
    server, namespace, event_type = record_event_server
    validator = EventFilterAccessValidator(server.iserver.aspace)
    operand = _simple_operand(event_type.nodeid, namespace, "PublicTemperature")
    operand.IndexRange = "0:2"
    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [operand]

    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(event_filter)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadIndexRangeInvalid)


async def test_invalid_attribute_id_is_rejected(record_event_server):
    server, namespace, event_type = record_event_server
    validator = EventFilterAccessValidator(server.iserver.aspace)
    operand = _simple_operand(event_type.nodeid, namespace, "PublicTemperature")
    operand.AttributeId = 999
    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [operand]

    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(event_filter)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadAttributeIdInvalid)


async def test_empty_browse_path_reads_type_node_attribute(record_event_server):
    server, _, _ = record_event_server
    validator = EventFilterAccessValidator(server.iserver.aspace)
    operand = ua.SimpleAttributeOperand()
    operand.TypeDefinitionId = ua.NodeId(ua.ObjectIds.BaseEventType)
    operand.AttributeId = ua.AttributeIds.NodeId
    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [operand]

    validator.validate_filter(event_filter)


async def test_inherited_field_resolves_through_type_hierarchy(record_event_server):
    server, namespace, _ = record_event_server
    parent_type = await server.create_custom_event_type(
        namespace,
        "ParentRecordEvent",
        ua.ObjectIds.BaseEventType,
        [("InheritedField", ua.VariantType.Int32)],
    )
    child_type = await server.create_custom_event_type(
        namespace,
        "ChildRecordEvent",
        parent_type.nodeid,
        [("ChildField", ua.VariantType.String)],
    )
    validator = EventFilterAccessValidator(server.iserver.aspace)

    inherited = _simple_operand(child_type.nodeid, namespace, "InheritedField")
    child_field = _simple_operand(child_type.nodeid, namespace, "ChildField")
    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [inherited, child_field]

    validator.validate_filter(event_filter)


async def test_direct_select_of_public_field_creates_monitored_item(subscription, record_event_server):
    server, subscription_id, _ = subscription
    _, namespace, event_type = record_event_server
    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [_simple_operand(event_type.nodeid, namespace, "PublicTemperature")]

    result = await _create_event_monitored_item(server, subscription_id, event_filter, handle=1)

    assert result.StatusCode.is_good()


async def test_missing_where_clause_is_rejected(record_event_server):
    server, _, _ = record_event_server
    validator = EventFilterAccessValidator(server.iserver.aspace)
    event_filter = ua.EventFilter()
    event_filter.WhereClause = None

    with pytest.raises(EventFilterAccessError) as exc:
        validator.validate_filter(event_filter)
    assert exc.value.status_code == ua.StatusCode(ua.StatusCodes.BadEventFilterInvalid)


async def test_missing_event_filter_is_rejected(subscription, record_event_server):
    server, subscription_id, _ = subscription
    params = ua.CreateMonitoredItemsParameters()
    params.SubscriptionId = subscription_id
    item = ua.MonitoredItemCreateRequest()
    item.ItemToMonitor.NodeId = ua.NodeId(ua.ObjectIds.Server)
    item.ItemToMonitor.AttributeId = ua.AttributeIds.EventNotifier
    item.MonitoringMode = ua.MonitoringMode.Reporting
    item.RequestedParameters.ClientHandle = 7
    params.ItemsToCreate = [item]

    results = await server.iserver.isession.create_monitored_items(params)

    assert results[0].StatusCode == ua.StatusCode(ua.StatusCodes.BadEventFilterInvalid)


async def test_data_change_filter_on_event_notifier_is_rejected(subscription, record_event_server):
    server, subscription_id, _ = subscription
    params = ua.CreateMonitoredItemsParameters()
    params.SubscriptionId = subscription_id
    item = ua.MonitoredItemCreateRequest()
    item.ItemToMonitor.NodeId = ua.NodeId(ua.ObjectIds.Server)
    item.ItemToMonitor.AttributeId = ua.AttributeIds.EventNotifier
    item.MonitoringMode = ua.MonitoringMode.Reporting
    item.RequestedParameters.ClientHandle = 8
    item.RequestedParameters.Filter = ua.DataChangeFilter()
    params.ItemsToCreate = [item]

    results = await server.iserver.isession.create_monitored_items(params)

    assert results[0].StatusCode == ua.StatusCode(ua.StatusCodes.BadEventFilterInvalid)


async def test_private_select_does_not_create_monitored_item(subscription, record_event_server):
    server, subscription_id, _ = subscription
    _, namespace, event_type = record_event_server
    policy = EventFieldAccessPolicy()
    policy.deny(
        EventFieldAccess.from_operand(_simple_operand(event_type.nodeid, namespace, "PrivateTestField"))
    )
    server.set_event_field_policy(policy)

    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [_simple_operand(event_type.nodeid, namespace, "PrivateTestField")]
    result = await _create_event_monitored_item(server, subscription_id, event_filter, handle=2)

    assert result.StatusCode == ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
    monitored_service = server.iserver.subscription_service.subscriptions[subscription_id].monitored_item_srv
    assert monitored_service._monitored_events == {}


async def test_private_predicate_does_not_create_monitored_item(subscription, record_event_server):
    server, subscription_id, _ = subscription
    _, namespace, event_type = record_event_server
    private_operand = _simple_operand(event_type.nodeid, namespace, "PrivateTestField")
    policy = EventFieldAccessPolicy()
    policy.deny(EventFieldAccess.from_operand(private_operand))
    server.set_event_field_policy(policy)

    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [_simple_operand(event_type.nodeid, namespace, "PublicTemperature")]
    element = ua.ContentFilterElement()
    element.FilterOperator = ua.FilterOperator.Equals
    element.FilterOperands = [private_operand, ua.LiteralOperand(ua.Variant("secret"))]
    event_filter.WhereClause.Elements = [element]

    result = await _create_event_monitored_item(server, subscription_id, event_filter, handle=3)

    assert result.StatusCode == ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
    monitored_service = server.iserver.subscription_service.subscriptions[subscription_id].monitored_item_srv
    assert monitored_service._monitored_events == {}


async def test_public_predicate_creates_monitored_item_and_filters_events(subscription, record_event_server):
    server, subscription_id, published_events = subscription
    _, namespace, event_type = record_event_server
    public_operand = _simple_operand(event_type.nodeid, namespace, "PublicTemperature")

    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [public_operand]
    element = ua.ContentFilterElement()
    element.FilterOperator = ua.FilterOperator.GreaterThan
    element.FilterOperands = [public_operand, ua.LiteralOperand(ua.Variant(100.0))]
    event_filter.WhereClause.Elements = [element]

    result = await _create_event_monitored_item(server, subscription_id, event_filter, handle=4)
    assert result.StatusCode.is_good()

    generator = await server.get_event_generator(event_type)
    generator.event.PublicTemperature = 10.0
    await generator.trigger(message="cold")
    generator.event.PublicTemperature = 200.0
    await generator.trigger(message="hot")
    await asyncio.sleep(0.1)

    assert len(published_events) == 1
    assert published_events[0].EventFields[0].Value == 200.0


async def test_rejected_filter_never_reads_private_getter(subscription, record_event_server):
    server, subscription_id, _ = subscription
    _, namespace, event_type = record_event_server
    private_operand = _simple_operand(event_type.nodeid, namespace, "PrivateTestField")
    policy = EventFieldAccessPolicy()
    policy.deny(EventFieldAccess.from_operand(private_operand))
    server.set_event_field_policy(policy)

    event_filter = ua.EventFilter()
    event_filter.SelectClauses = [_simple_operand(event_type.nodeid, namespace, "PublicTemperature")]
    element = ua.ContentFilterElement()
    element.FilterOperator = ua.FilterOperator.Equals
    element.FilterOperands = [private_operand, ua.LiteralOperand(ua.Variant("secret"))]
    event_filter.WhereClause.Elements = [element]

    result = await _create_event_monitored_item(server, subscription_id, event_filter, handle=5)
    assert not result.StatusCode.is_good()

    generator = await server.get_event_generator(event_type)
    read_count = 0

    class PrivateGetter:
        def __get__(self, instance, owner=None):
            nonlocal read_count
            read_count += 1
            return instance.__dict__["_private_value"]

        def __set__(self, instance, value):
            instance.__dict__["_private_value"] = value

    generator.event.__class__.PrivateTestField = PrivateGetter()
    generator.event.PrivateTestField = "top-secret"
    generator.event.PublicTemperature = 21.0
    await generator.trigger(message="guarded")
    await asyncio.sleep(0.1)

    assert read_count == 0


async def test_modify_monitored_item_rejects_denied_filter(subscription, record_event_server):
    server, subscription_id, _ = subscription
    _, namespace, event_type = record_event_server
    policy = EventFieldAccessPolicy()
    policy.deny(
        EventFieldAccess.from_operand(_simple_operand(event_type.nodeid, namespace, "PrivateTestField"))
    )
    server.set_event_field_policy(policy)

    public_filter = ua.EventFilter()
    public_filter.SelectClauses = [_simple_operand(event_type.nodeid, namespace, "PublicTemperature")]
    created = await _create_event_monitored_item(server, subscription_id, public_filter, handle=6)
    assert created.StatusCode.is_good()

    private_filter = ua.EventFilter()
    private_filter.SelectClauses = [_simple_operand(event_type.nodeid, namespace, "PrivateTestField")]
    modify_params = ua.ModifyMonitoredItemsParameters()
    modify_params.SubscriptionId = subscription_id
    modify_request = ua.MonitoredItemModifyRequest()
    modify_request.MonitoredItemId = created.MonitoredItemId
    modify_request.RequestedParameters.Filter = private_filter
    modify_params.ItemsToModify = [modify_request]

    modify_results = server.iserver.subscription_service.modify_monitored_items(modify_params)
    assert modify_results[0].StatusCode == ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)


async def test_modify_monitored_item_accepts_legal_filter(subscription, record_event_server):
    server, subscription_id, _ = subscription
    _, namespace, event_type = record_event_server

    public_filter = ua.EventFilter()
    public_filter.SelectClauses = [_simple_operand(event_type.nodeid, namespace, "PublicTemperature")]
    created = await _create_event_monitored_item(server, subscription_id, public_filter, handle=9)
    assert created.StatusCode.is_good()

    legal_filter = ua.EventFilter()
    public_operand = _simple_operand(event_type.nodeid, namespace, "PublicTemperature")
    legal_filter.SelectClauses = [public_operand]
    element = ua.ContentFilterElement()
    element.FilterOperator = ua.FilterOperator.GreaterThan
    element.FilterOperands = [public_operand, ua.LiteralOperand(ua.Variant(0.0))]
    legal_filter.WhereClause.Elements = [element]

    modify_params = ua.ModifyMonitoredItemsParameters()
    modify_params.SubscriptionId = subscription_id
    modify_request = ua.MonitoredItemModifyRequest()
    modify_request.MonitoredItemId = created.MonitoredItemId
    modify_request.RequestedParameters.SamplingInterval = 100
    modify_request.RequestedParameters.QueueSize = 5
    modify_request.RequestedParameters.Filter = legal_filter
    modify_params.ItemsToModify = [modify_request]

    modify_results = server.iserver.subscription_service.modify_monitored_items(modify_params)
    assert modify_results[0].StatusCode.is_good()
    monitored_service = server.iserver.subscription_service.subscriptions[subscription_id].monitored_item_srv
    monitored_data = monitored_service._monitored_items[created.MonitoredItemId]
    assert monitored_data.where_clause_evaluator is not None
    assert monitored_data.filter is legal_filter
