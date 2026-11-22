from __future__ import annotations

from dataclasses import asdict, fields, is_dataclass
from typing import Any

from aws_lambda_powertools.utilities.idempotency.exceptions import (
    IdempotencyModelTypeError,
    IdempotencyNoSerializationModelError,
)
from aws_lambda_powertools.utilities.idempotency.serialization.base import (
    BaseIdempotencyModelSerializer,
    BaseIdempotencySerializer,
)
from aws_lambda_powertools.utilities.idempotency.serialization.functions import get_actual_type

DataClass = Any


class DataclassSerializer(BaseIdempotencyModelSerializer):
    """
    A serializer class for transforming data between dataclass objects and dictionaries.
    """

    def __init__(self, model: type[DataClass]):
        """
        Parameters
        ----------
        model: type[DataClass]
            A dataclass type to be used for serialization and deserialization
        """
        self.__model: type[DataClass] = model

    def to_dict(self, data: DataClass) -> dict:
        return asdict(data)

    def from_dict(self, data: dict) -> DataClass:
        # Tolerate records stored with a wider shape (e.g. written before a
        # PersistedResponse subset was introduced): only known fields are replayed.
        field_names = {field.name for field in fields(self.__model)}
        return self.__model(**{key: value for key, value in data.items() if key in field_names})

    @classmethod
    def instantiate(cls, model_type: Any) -> BaseIdempotencySerializer:
        model_type = get_actual_type(model_type=model_type)

        if model_type is None:
            raise IdempotencyNoSerializationModelError("No serialization model was supplied")

        if not is_dataclass(model_type):
            raise IdempotencyModelTypeError("Model type is not inherited of dataclass type")
        return cls(model=model_type)  # type: ignore[arg-type]
