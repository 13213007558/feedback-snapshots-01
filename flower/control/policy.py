import logging

logger = logging.getLogger(__name__)


ACTION_ALIASES = {
    'shutdown': 'worker.shutdown',
    'worker.shutdown': 'worker.shutdown',
    'pool_restart': 'worker.pool_restart',
    'pool.restart': 'worker.pool_restart',
    'worker.pool_restart': 'worker.pool_restart',
    'pool_grow': 'worker.pool_grow',
    'pool.grow': 'worker.pool_grow',
    'worker.pool_grow': 'worker.pool_grow',
    'pool_shrink': 'worker.pool_shrink',
    'pool.shrink': 'worker.pool_shrink',
    'worker.pool_shrink': 'worker.pool_shrink',
    'pool_autoscale': 'worker.pool_autoscale',
    'pool.autoscale': 'worker.pool_autoscale',
    'worker.pool_autoscale': 'worker.pool_autoscale',
    'queue_add_consumer': 'worker.queue_add_consumer',
    'queue.add': 'worker.queue_add_consumer',
    'worker.queue_add_consumer': 'worker.queue_add_consumer',
    'add_consumer': 'worker.queue_add_consumer',
    'queue_cancel_consumer': 'worker.queue_cancel_consumer',
    'queue.cancel': 'worker.queue_cancel_consumer',
    'worker.queue_cancel_consumer': 'worker.queue_cancel_consumer',
    'cancel_consumer': 'worker.queue_cancel_consumer',
    'task_time_limit': 'task.time_limit',
    'task.timeout': 'task.time_limit',
    'task.time_limit': 'task.time_limit',
    'task_rate_limit': 'task.rate_limit',
    'task.ratelimit': 'task.rate_limit',
    'task.rate_limit': 'task.rate_limit',
}

ACTION_COMMANDS = {
    'worker.shutdown': 'shutdown',
    'worker.pool_restart': 'pool_restart',
    'worker.pool_grow': 'pool_grow',
    'worker.pool_shrink': 'pool_shrink',
    'worker.pool_autoscale': 'autoscale',
    'worker.queue_add_consumer': 'add_consumer',
    'worker.queue_cancel_consumer': 'cancel_consumer',
    'task.time_limit': 'time_limit',
    'task.rate_limit': 'rate_limit',
}


def normalize_action(action):
    if action is None:
        return None
    name = str(action).strip().lower().replace('-', '_')
    return ACTION_ALIASES.get(name, name)


def _split_assignments(values):
    """Yield raw ``name=value`` fragments from repeated option values.

    Tornado splits a ``multiple`` option on commas before Flower sees it, so a
    comma-separated action list arrives as separate values.  Semicolons are
    kept as explicit separators; callers treat fragments without ``=`` as a
    continuation of the previous entry.
    """
    for value in values or ():
        for item in str(value).split(';'):
            item = item.strip()
            if item:
                yield item


def parse_group_actions(values):
    """Parse ``group=action1,action2`` entries into a group allowlist."""
    groups = {}
    last = None
    for item in _split_assignments(values):
        if '=' in item:
            group, actions = item.split('=', 1)
            last = group.strip()
            groups.setdefault(last, set())
        elif last is not None:
            # a continuation split off by Tornado's comma handling
            actions = item
        else:
            logger.warning("Ignoring control group fragment '%s'", item)
            continue
        allowed = {normalize_action(action)
                   for action in actions.split(',') if action.strip()}
        groups[last].update(allowed)
    return {group: frozenset(actions) for group, actions in groups.items()}


def parse_group_members(values, groups):
    """Parse operator membership.

    Both ``user=group`` and ``group=user1,user2`` entries are accepted.  A
    left-hand side that matches a configured group is treated as a member
    list; fragments without ``=`` continue the previous entry.
    """
    members = {}
    last = None
    for item in _split_assignments(values):
        if '=' in item:
            left, right = item.split('=', 1)
            left, right = left.strip(), right.strip()
        else:
            left, right = last, item
        if left is None:
            logger.warning("Ignoring control operator fragment '%s'", item)
            continue
        if left in groups:
            for user in right.split(','):
                user = user.strip()
                if user:
                    members[user] = left
            last = left
        elif right:
            members[left] = right
            last = right
    return members


class OperatorPolicy:
    """Two-or-more operator groups with different control allowlists."""

    def __init__(self, group_actions=None, group_members=None):
        self.group_actions = dict(group_actions or {})
        self.group_members = dict(group_members or {})
        self.enabled = bool(self.group_actions)

    @classmethod
    def from_options(cls, options):
        groups = parse_group_actions(
            getattr(options, 'control_groups', None) or ())
        members = parse_group_members(
            getattr(options, 'control_operators', None) or (), groups)
        for group in members.values():
            if group not in groups:
                logger.warning(
                    "Control operator references unknown group '%s'", group)
        return cls(groups, members)

    def group_for(self, user):
        if user is None:
            return None
        return self.group_members.get(str(user))

    def actions_for(self, user):
        group = self.group_for(user)
        if group is None:
            return frozenset()
        return self.group_actions.get(group, frozenset())

    def allows(self, user, action):
        if not self.enabled:
            return True
        return normalize_action(action) in self.actions_for(user)
