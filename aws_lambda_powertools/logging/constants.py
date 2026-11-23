# logger.powertools_handler is set with Powertools Logger handler; useful when there are many handlers
LOGGER_ATTRIBUTE_POWERTOOLS_HANDLER = "powertools_handler"
# logger.init attribute is set when Logger has been configured
LOGGER_ATTRIBUTE_PRECONFIGURED = "init"
LOGGER_ATTRIBUTE_HANDLER = "logger_handler"

# Record attributes used to preserve a buffered record's creation time state.
# They are internal bookkeeping and must never be serialized as log fields.
LOGGER_INTERNAL_RECORD_ATTRS = (
    "_powertools_log_keys",
    "_powertools_log_context",
    "_powertools_disclosure_snapshots",
    "_powertools_disclosure_payload",
)
