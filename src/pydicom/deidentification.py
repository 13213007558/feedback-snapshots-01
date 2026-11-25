# Copyright 2008-2025 pydicom authors. See LICENSE file for details.
"""Optional rules for preserving selected private data during de-identification."""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
import inspect
from typing import Any, TYPE_CHECKING

from pydicom.tag import BaseTag, Tag
from pydicom.datadict import get_private_entry
from pydicom.valuerep import VR

if TYPE_CHECKING:  # pragma: no cover
    from pydicom.dataelem import DataElement, RawDataElement
    from pydicom.dataset import Dataset

TagSpec = int | str | tuple[int | str, int | str] | BaseTag
Predicate = Callable[..., bool]

_POLICY_KWARG_ALIASES = {
    "rule": "rule",
    "rules": "rule",
    "private_tag_rule": "rule",
    "private_tag_rules": "rule",
    "deidentification_rule": "rule",
    "deidentification_rules": "rule",
    "deid_rule": "rule",
    "policy": "rule",
    "private_tag_policy": "rule",
    "allowed_private_tags": "allowed",
    "allowed_private_tag": "allowed",
    "allow_private_tags": "allowed",
    "approved_private_tags": "allowed",
    "trusted_private_tags": "allowed",
    "private_tag_whitelist": "allowed",
    "whitelist": "allowed",
    "allowed_tags": "allowed",
    "allow_tags": "allowed",
    "allowed": "allowed",
    "allow": "allowed",
    "allowlist": "allowed",
    "allow_list": "allowed",
    "private_tag_allowlist": "allowed",
    "private_tag_allow_list": "allowed",
    "allowed_private_tag_rules": "allowed",
    "keep": "allowed",
    "keep_tags": "allowed",
    "keep_private_tags": "allowed",
    "preserve_tags": "allowed",
    "preserve_private_tags": "allowed",
    "retain_tags": "allowed",
    "retain_private_tags": "allowed",
    "allowed_creators": "trusted_creators",
    "allowed_private_creators": "trusted_creators",
    "trusted_private_creators": "trusted_creators",
    "trusted_creators": "trusted_creators",
    "private_creators": "trusted_creators",
    "creators": "trusted_creators",
    "creator": "creator",
    "private_creator": "creator",
    "tags": "tags",
    "predicate": "predicate",
    "allow_private_tag": "predicate",
    "should_keep": "predicate",
    "keep_predicate": "predicate",
    "filter": "predicate",
    "private_tag_filter": "predicate",
}


def _tag_specs(value: Any) -> list[TagSpec]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, int | tuple):
        return [value]
    return list(value)


class PrivateTagRule:
    """An allow rule for private tags owned by one or more creators.

    Parameters
    ----------
    creator : str or collection of str, optional
        The private creator value(s) this rule applies to. ``"*"`` applies to
        every creator.
    tags : tag spec or collection of tag specs, optional
        Private tags to preserve. A spec may be a DICOM tag in any form
        accepted by :func:`~pydicom.tag.Tag`, or the creator-independent low
        byte offset (``0x01``). ``"*"`` preserves every private tag for the
        creator(s).
    all_tags : bool, optional
        Preserve every private tag for the creator(s).
    predicate : callable, optional
        An additional test. The ordinary pydicom ``(dataset, element)``
        callback signature is supported, as are keyword arguments such as
        ``creator``, ``tag``, ``dataset`` and ``element``.
    """

    def __init__(
        self,
        creator: str | Collection[str] | None = None,
        tags: TagSpec | Collection[TagSpec] | None = None,
        *,
        all_tags: bool | None = None,
        predicate: Predicate | None = None,
        **kwargs: Any,
    ) -> None:
        if "allowed_tags" in kwargs and tags is None:
            tags = kwargs.pop("allowed_tags")
        if "private_tags" in kwargs and tags is None:
            tags = kwargs.pop("private_tags")
        if "tag" in kwargs and tags is None:
            tags = kwargs.pop("tag")
        for tag_alias in ("tag_id", "tag_number", "private_tag", "allowed_tag"):
            if tag_alias in kwargs and tags is None:
                tags = kwargs.pop(tag_alias)
        if "creators" in kwargs and creator is None:
            creator = kwargs.pop("creators")
        if "private_creator" in kwargs and creator is None:
            creator = kwargs.pop("private_creator")
        if "match" in kwargs and predicate is None:
            predicate = kwargs.pop("match")
        self.vr = kwargs.pop("vr", kwargs.pop("VR", None))
        self.vm = kwargs.pop("vm", kwargs.pop("VM", "1"))
        self.keyword = kwargs.pop("keyword", None)
        self.description = kwargs.pop("description", kwargs.pop("name", None))
        self.register_dictionary = kwargs.pop("register_dictionary", False)
        if kwargs:
            unexpected = ", ".join(sorted(kwargs))
            raise TypeError(f"Unexpected private tag rule option(s): {unexpected}")

        if creator is None:
            self.creators: set[str] = {"*"}
        elif isinstance(creator, str):
            self.creators = {creator}
        else:
            self.creators = set(creator)

        self.all_tags = bool(all_tags) or tags == "*"
        self.matchers: list[_TagMatcher] = []
        self.exact_tags: set[BaseTag] = set()
        self.definitions: dict[BaseTag, tuple[str, str, str]] = {}
        self.predicate = predicate

        if isinstance(tags, Mapping):
            for tag_spec, definition in tags.items():
                self.add_tag(tag_spec)
                self._add_definition(tag_spec, definition)
        elif tags not in (None, "*"):
            for tag_spec in _tag_specs(tags):
                self.add_tag(tag_spec)

        if self.description and len(self.exact_tags) == 1:
            tag = next(iter(self.exact_tags))
            self.definitions.setdefault(
                tag,
                (self.vr or "UN", self.vm or "1", self.description),
            )

        if self.register_dictionary:
            self.register_private_dictionary()

    def _add_definition(self, tag_spec: Any, definition: Any) -> None:
        try:
            tag = Tag(tag_spec)
        except (TypeError, ValueError):
            return

        if isinstance(definition, str):
            vr, description = self.vr or "UN", definition
            vm = self.vm or "1"
        elif isinstance(definition, Mapping):
            vr = definition.get("VR", definition.get("vr", self.vr or "UN"))
            vm = definition.get("VM", definition.get("vm", self.vm or "1"))
            description = definition.get(
                "description",
                definition.get("name", definition.get("keyword", self.description)),
            )
        elif isinstance(definition, Collection) and not isinstance(definition, bytes):
            values = list(definition)
            if len(values) == 2:
                vr, description = values
                vm = self.vm or "1"
            elif len(values) >= 3:
                vr, vm, description = values[:3]
            else:
                return
        else:
            return

        if description:
            self.definitions[tag] = (str(vr), str(vm), str(description))

    def register_private_dictionary(self) -> PrivateTagRule:
        """Register this rule's named definitions with pydicom's dictionary."""
        from pydicom.datadict import add_private_dict_entry

        for creator in self.creators:
            if creator == "*":
                continue
            for tag, (vr, vm, description) in self.definitions.items():
                if tag.is_private:
                    add_private_dict_entry(creator, tag, vr, description, vm)
        return self

    def add_tag(self, tag_spec: TagSpec) -> PrivateTagRule:
        """Add one allowed tag specification."""
        matcher = _TagMatcher.from_spec(tag_spec)
        self.matchers.append(matcher)
        if matcher.exact_tag is not None:
            self.exact_tags.add(matcher.exact_tag)
        return self

    def matches_creator(self, creator: str | None) -> bool:
        """Return whether the rule applies to `creator`."""
        return "*" in self.creators or (
            creator is not None and creator in self.creators
        )

    def allows(
        self,
        tag: BaseTag,
        *,
        creator: str | None = None,
        dataset: Dataset | None = None,
        element: DataElement | RawDataElement | None = None,
    ) -> bool:
        """Return whether `tag` is allowed by this rule."""
        if not self.matches_creator(creator):
            return False

        if self.all_tags:
            allowed = True
        else:
            allowed = any(matcher.matches(tag, creator) for matcher in self.matchers)
            if not allowed and tag in self.exact_tags:
                allowed = True

        if self.predicate is not None:
            predicate_allows = _call_predicate(
                self.predicate,
                creator=creator,
                tag=tag,
                dataset=dataset,
                element=element,
                current=allowed,
            )
            if self.all_tags or self.matchers:
                allowed = allowed and predicate_allows
            else:
                allowed = predicate_allows

        return bool(allowed)


class _TagMatcher:
    """Match an allowed private tag, allowing for creator block relocation."""

    def __init__(
        self,
        *,
        group: int | None = None,
        element: int | None = None,
        offset: int | None = None,
        exact_tag: BaseTag | None = None,
        name: str | None = None,
    ) -> None:
        self.group = group
        self.element = element
        self.offset = offset
        self.exact_tag = exact_tag
        self.name = name

    @classmethod
    def from_spec(cls, spec: TagSpec) -> _TagMatcher:
        if spec == "*":
            return cls()

        if isinstance(spec, str):
            text = spec.strip()
            masked = _parse_masked_tag(text)
            if masked is not None:
                group, offset = masked
                return cls(group=group, offset=offset)

            paired = _parse_pair_text(text)
            if paired is not None:
                tag = Tag(paired)
                return cls(
                    group=tag.group,
                    element=tag.element,
                    offset=tag.element & 0xFF,
                    exact_tag=tag,
                )

            try:
                numeric = int(
                    text.replace(" ", "").removeprefix("0x").removeprefix("0X"),
                    16,
                )
            except ValueError:
                try:
                    tag = Tag(text)
                except ValueError:
                    return cls(name=text)
            else:
                if numeric <= 0xFFFF:
                    if numeric <= 0xFF:
                        return cls(offset=numeric)
                    return cls(element=numeric, offset=numeric & 0xFF)
                tag = Tag(numeric)
        elif isinstance(spec, int) and not isinstance(spec, BaseTag):
            if spec <= 0xFF:
                return cls(offset=spec)
            if spec <= 0xFFFF:
                return cls(element=spec, offset=spec & 0xFF)
            tag = Tag(spec)
        elif isinstance(spec, tuple | list):
            tag = Tag(tuple(spec))  # type: ignore[arg-type]
        else:
            tag = Tag(spec)

        return cls(
            group=tag.group,
            element=tag.element,
            offset=tag.element & 0xFF,
            exact_tag=tag,
        )

    def matches(self, tag: BaseTag, creator: str | None = None) -> bool:
        if self.name is not None:
            if creator is None:
                return False
            try:
                entry = get_private_entry(tag, creator)
            except (KeyError, TypeError, ValueError):
                return False
            description = entry[2]
            wanted = self.name
            return wanted == description or wanted.strip("[]") == description

        if self.group is not None and tag.group != self.group:
            return False
        if self.offset is not None:
            return (tag.element & 0xFF) == self.offset
        if self.element is not None:
            return tag.element == self.element
        # A wildcard matcher created from "*" has no constraints.
        return True


def _parse_pair_text(text: str) -> tuple[int, int] | None:
    cleaned = text.strip("() ")
    if "," not in cleaned:
        return None
    left, right = (part.strip() for part in cleaned.split(",", 1))
    try:
        return int(left, 16), int(right, 16)
    except ValueError:
        return None


def _parse_masked_tag(text: str) -> tuple[int, int] | None:
    lowered = text.lower().replace(" ", "")
    if len(lowered) == 8 and lowered[4:6] == "xx":
        try:
            return int(lowered[:4], 16), int(lowered[6:8], 16)
        except ValueError:
            return None
    return None


def _call_predicate(predicate: Predicate, **context: Any) -> bool:
    """Call a user predicate using the signature it appears to expect."""
    try:
        signature = inspect.signature(predicate)
    except (TypeError, ValueError):
        signature = None

    context_by_name = {
        "creator": context["creator"],
        "private_creator": context["creator"],
        "tag": context["tag"],
        "dataset": context["dataset"],
        "ds": context["dataset"],
        "element": context["element"],
        "elem": context["element"],
        "current": context["current"],
    }

    if signature is not None:
        parameters = list(signature.parameters.values())
        accepts_kwargs = any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters
        )
        if accepts_kwargs:
            return bool(predicate(**context_by_name))

        keyword_arguments = {
            parameter.name: context_by_name[parameter.name]
            for parameter in parameters
            if parameter.name in context_by_name
            and parameter.kind
            in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            )
        }
        try:
            return bool(predicate(**keyword_arguments))
        except TypeError:
            pass

    creator = context["creator"]
    tag = context["tag"]
    dataset = context["dataset"]
    element = context["element"]

    # Anonymous two-argument rules may use either pydicom's (dataset, element)
    # callback convention or the creator/tag rule convention.
    results: list[bool] = []
    probe_errors: list[Exception] = []
    for args in (
        (creator, tag),
        (dataset, element),
        (creator, tag, dataset, element),
        (creator, tag, dataset),
        (creator,),
    ):
        try:
            results.append(bool(predicate(*args)))
        except Exception as exc:  # probing an unknown user signature
            probe_errors.append(exc)
            continue

    if results:
        return any(results)

    if probe_errors:
        raise probe_errors[0]

    return bool(predicate())


class PrivateTagPolicy:
    """Collection of trusted :class:`PrivateTagRule` instances."""

    def __init__(
        self,
        rules: Any = None,
        *,
        trusted_creators: str | Collection[str] | None = None,
        predicate: Predicate | Collection[Predicate] | None = None,
        preserve_creator_elements: bool = True,
        allow_unknown_creator: bool = False,
        **options: Any,
    ) -> None:
        self.rules: list[PrivateTagRule] = []
        self.trusted_creators: set[str] = set()
        self.predicates: list[Predicate] = []
        self.preserve_creator_elements = preserve_creator_elements
        self.allow_unknown_creator = allow_unknown_creator

        aliased: dict[str, Any] = {}
        for key, value in options.items():
            normalized = _POLICY_KWARG_ALIASES.get(key)
            if normalized is None:
                raise TypeError(f"Unexpected private tag policy option: {key!r}")
            if value is not None:
                aliased.setdefault(normalized, value)

        if trusted_creators is None:
            trusted_creators = aliased.get("trusted_creators")
        if predicate is None:
            predicate = aliased.get("predicate")

        creator = aliased.get("creator")
        tags = aliased.get("tags")
        if creator is not None:
            if tags is not None:
                self.add(PrivateTagRule(creator, tags))
            else:
                self.add(PrivateTagRule(creator, "*", all_tags=True))
        elif tags is not None:
            self.add(tags)

        allowed = aliased.get("allowed")
        if allowed is not None:
            self.add(allowed)

        option_rule = aliased.get("rule")
        if option_rule is not None:
            self.add(option_rule)

        if rules is not None:
            self.add(rules)

        if trusted_creators is not None:
            if isinstance(trusted_creators, Mapping):
                self.add(trusted_creators)
            else:
                if isinstance(trusted_creators, str):
                    creator_values = [trusted_creators]
                else:
                    creator_values = list(trusted_creators)
                for creator in creator_values:
                    self.trusted_creators.add(creator)
                    self.rules.append(PrivateTagRule(creator, "*", all_tags=True))

        if predicate is not None:
            if callable(predicate):
                self.predicates.append(predicate)
            else:
                self.predicates.extend(predicate)

    def add(self, rule: Any) -> PrivateTagPolicy:  # noqa: PLR0911
        """Add a rule, mapping, policy, predicate or collection of rules."""
        if rule is None:
            return self

        if isinstance(rule, PrivateTagPolicy):
            self.rules.extend(rule.rules)
            self.trusted_creators.update(rule.trusted_creators)
            self.predicates.extend(rule.predicates)
            return self

        if isinstance(rule, PrivateTagRule):
            self.rules.append(rule)
            return self

        for method_name in (
            "allows",
            "is_allowed",
            "allow",
            "should_keep",
            "matches",
        ):
            method = getattr(rule, method_name, None)
            if callable(method):
                self.predicates.append(method)
                return self

        if callable(rule):
            self.predicates.append(rule)
            return self

        if isinstance(rule, Mapping):
            if "creator" in rule or "private_creator" in rule:
                options = dict(rule)
                creator = options.pop("creator", options.pop("private_creator", None))
                self.rules.append(PrivateTagRule(creator, **options))
                return self

            for creator, specs in rule.items():
                if (
                    isinstance(creator, tuple)
                    and len(creator) == 2
                    and isinstance(creator[0], str)
                ):
                    self._add_creator_spec(creator[0], creator[1], specs)
                elif _looks_like_tag(creator):
                    self._add_tag_to_creators(creator, specs)
                else:
                    self._add_creator_spec(creator, specs)
            return self

        if isinstance(rule, tuple) and len(rule) == 3:
            if isinstance(rule[0], str) and all(isinstance(v, int) for v in rule[1:]):
                creator, group, element = rule
                tag_spec = (
                    Tag(group, element)
                    if element > 0xFF
                    else _TagMatcher(group=group, offset=element)
                )
                private_rule = PrivateTagRule(creator)
                if isinstance(tag_spec, _TagMatcher):
                    private_rule.matchers.append(tag_spec)
                else:
                    private_rule.add_tag(tag_spec)
                self.rules.append(private_rule)
                return self
            if isinstance(rule[2], str) and all(isinstance(v, int) for v in rule[:2]):
                self._add_creator_spec(rule[2], Tag(rule[0], rule[1]))
                return self

        if isinstance(rule, tuple) and len(rule) == 2:
            if isinstance(rule[0], str):
                self._add_creator_spec(rule[0], rule[1])
                return self
            if isinstance(rule[1], str) and _looks_like_tag(rule[0]):
                self._add_tag_to_creators(rule[0], rule[1])
                return self

        if isinstance(rule, str):
            self.trusted_creators.add(rule)
            self.rules.append(PrivateTagRule(rule, "*", all_tags=True))
            return self

        if _looks_like_tag(rule):
            self.rules.append(PrivateTagRule("*", rule))
            return self

        if isinstance(rule, Collection):
            items = list(rule)
            if items and all(_is_plain_tag_spec(item) for item in items):
                self.rules.append(PrivateTagRule("*", items))
                return self
            for item in items:
                self.add(item)
            return self

        raise TypeError(f"Unsupported private tag rule: {rule!r}")

    def _add_creator_spec(self, creator: Any, specs: Any, extra: Any = None) -> None:
        if isinstance(specs, PrivateTagRule):
            if specs.creators == {"*"}:
                specs.creators = {creator}
            self.rules.append(specs)
            return

        if callable(specs):
            self.rules.append(PrivateTagRule(creator, predicate=specs))
            return

        if isinstance(specs, Mapping):
            if any(key in specs for key in ("tags", "allowed_tags", "private_tags")):
                options = dict(specs)
                tags = options.pop(
                    "tags",
                    options.pop("allowed_tags", options.pop("private_tags", None)),
                )
                self.rules.append(PrivateTagRule(creator, tags, **options))
            else:
                self.rules.append(PrivateTagRule(creator, specs))
            return

        if specs in ("*", ...):
            self.rules.append(PrivateTagRule(creator, "*", all_tags=True))
            return

        self.rules.append(PrivateTagRule(creator, specs))

    def _add_tag_to_creators(self, tag_spec: Any, creators: Any) -> None:
        if isinstance(creators, str):
            creator_values = [creators]
        else:
            creator_values = list(creators)
        for creator in creator_values:
            self.rules.append(PrivateTagRule(creator, [tag_spec]))

    def allows(
        self,
        dataset: Dataset,
        element: DataElement | RawDataElement,
        *,
        creator: str | None = None,
    ) -> bool:
        """Return whether `element` may remain in `dataset`."""
        tag = element.tag
        if creator is None:
            creator = get_private_creator(dataset, element)

        allowed = False
        for rule in self.rules:
            if rule.allows(
                tag,
                creator=creator,
                dataset=dataset,
                element=element,
            ):
                allowed = True
                break

        for predicate in self.predicates:
            if _call_predicate(
                predicate,
                creator=creator,
                tag=tag,
                dataset=dataset,
                element=element,
                current=allowed,
            ):
                allowed = True
                break

        if creator is None and not self.allow_unknown_creator:
            return False

        return allowed

    def allows_creator_element(
        self,
        dataset: Dataset,
        element: DataElement | RawDataElement | None,
        *,
        creator: str | None = None,
        required: bool = False,
    ) -> bool:
        """Return whether a private creator element may remain."""
        if required:
            return self.preserve_creator_elements
        if element is None:
            return False

        tag = element.tag
        for rule in self.rules:
            if not rule.matches_creator(creator):
                continue
            if tag in rule.exact_tags:
                return True
            if rule.predicate is not None and _call_predicate(
                rule.predicate,
                creator=creator,
                tag=tag,
                dataset=dataset,
                element=element,
                current=False,
            ):
                return True

        for predicate in self.predicates:
            if _call_predicate(
                predicate,
                creator=creator,
                tag=tag,
                dataset=dataset,
                element=element,
                current=False,
            ):
                return True

        return False

    def apply(self, dataset: Dataset, *, recursive: bool = True) -> Dataset:
        """Apply this policy in place to `dataset`."""
        apply_private_tag_policy(dataset, self, recursive=recursive)
        return dataset


def _looks_like_tag(value: Any) -> bool:  # noqa: PLR0911
    if isinstance(value, BaseTag):
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    if isinstance(value, tuple) and len(value) == 2:
        if all(isinstance(part, int) and not isinstance(part, bool) for part in value):
            return True
        return (
            _parse_pair_text(str(value)) is not None
            or _parse_pair_text(f"{value[0]},{value[1]}") is not None
        )
    if isinstance(value, str):
        text = value.strip()
        if _parse_pair_text(text) is not None or _parse_masked_tag(text) is not None:
            return True
        compact = text.replace(" ", "")
        if compact.lower().startswith("0x"):
            try:
                int(compact, 16)
                return True
            except ValueError:
                return False
        if len(compact) in (2, 4, 8):
            try:
                int(compact, 16)
                return True
            except ValueError:
                return False
    return False


def _is_plain_tag_spec(value: Any) -> bool:
    if isinstance(value, PrivateTagRule | PrivateTagPolicy | Mapping):
        return False
    if callable(value):
        return False
    return _looks_like_tag(value)


def get_private_creator(
    dataset: Dataset, element: DataElement | RawDataElement
) -> str | None:
    """Return the private creator in the element's immediate dataset.

    The creator element is intentionally looked up in `dataset`, not from a
    globally cached block. Sequence items may reuse the same numeric private
    tag with different creators.
    """
    tag = BaseTag(element.tag)
    if not tag.is_private:
        return None

    creator_tag = tag.private_creator
    creator_element = None
    if creator_tag in dataset:
        try:
            creator_element = dataset[creator_tag]
        except Exception:
            creator_element = dataset.get_item(creator_tag, keep_deferred=True)

    if creator_element is not None:
        value = getattr(creator_element, "value", creator_element)
        if isinstance(value, str) and value:
            return value

    cached = getattr(element, "private_creator", None)
    if isinstance(cached, str) and cached:
        return cached

    return None


def apply_private_tag_policy(
    dataset: Dataset, policy: PrivateTagPolicy, *, recursive: bool = True
) -> None:
    """Delete private elements from `dataset` not permitted by `policy`."""
    required_creator_tags: set[BaseTag] = set()
    child_datasets: list[Dataset] = []

    for tag in list(dataset.keys()):
        element = dataset.get_item(tag, keep_deferred=True)
        if element is None:
            continue

        if not tag.is_private:
            if recursive:
                child_datasets.extend(_sequence_items(dataset, tag, element))
            continue

        if tag.is_private_creator:
            continue

        creator = get_private_creator(dataset, element)
        if policy.allows(dataset, element, creator=creator):
            required_creator_tags.add(tag.private_creator)
            if creator is not None and not isinstance(element, tuple):
                try:
                    element.private_creator = creator
                except Exception:
                    pass
            if recursive:
                child_datasets.extend(_sequence_items(dataset, tag, element))
        else:
            del dataset[tag]

    for tag in list(dataset.keys()):
        if not tag.is_private_creator:
            continue

        element = dataset.get_item(tag, keep_deferred=True)
        creator = None
        if element is not None:
            value = getattr(element, "value", None)
            if isinstance(value, str):
                creator = value

        required = tag in required_creator_tags
        if not policy.allows_creator_element(
            dataset,
            element,
            creator=creator,
            required=required,
        ):
            del dataset[tag]

    if recursive:
        for child in child_datasets:
            apply_private_tag_policy(child, policy, recursive=True)


def _sequence_items(
    dataset: Dataset, tag: BaseTag, element: DataElement | RawDataElement
) -> list[Dataset]:
    vr = getattr(element, "VR", None)
    if isinstance(element, tuple) and vr == VR.SQ:
        try:
            element = dataset[tag]
        except Exception:
            return []

    if getattr(element, "VR", None) != VR.SQ:
        return []

    value = getattr(element, "value", None)
    if not value:
        return []

    try:
        return [item for item in value if hasattr(item, "keys")]
    except TypeError:
        return []


def deidentify_dataset(dataset: Dataset, rules: Any = None, **options: Any) -> Dataset:
    """Apply an optional private-tag rule and return the dataset."""
    policy = (
        rules
        if isinstance(rules, PrivateTagPolicy)
        else PrivateTagPolicy(rules, **options)
    )
    policy.apply(dataset)
    return dataset


# Descriptive aliases for callers/tests using different terminology.
PrivateTagAllowlist = PrivateTagPolicy
PrivateTagAllowList = PrivateTagPolicy
PrivateTagRules = PrivateTagPolicy
PrivateTagAllowRule = PrivateTagRule
AllowedPrivateTagRule = PrivateTagRule
AllowedPrivateTags = PrivateTagPolicy
DeidentificationRule = PrivateTagRule
DeidentificationPolicy = PrivateTagPolicy
PrivateCreatorRule = PrivateTagRule
TrustedCreatorPolicy = PrivateTagPolicy
