"""ALES INVARIANT cloud source connectors and the connector SPI."""

from .azure_blob_source import AzureBlobConnector
from .registry import ConnectorRegistry, RunResult
from .s3_source import S3Connector
from .spi import (
    CheckpointStore,
    ConnectorHealth,
    FileCheckpoint,
    InMemoryCheckpoint,
    PollingConnector,
    RemoteObject,
    SourceConnector,
    TrackedConnector,
    acl_narrowed,
)
from .webhook_source import (
    HandleResult,
    WebhookAuthError,
    WebhookConnector,
    WebhookError,
    WebhookPayloadError,
    WebhookReplayError,
    sign_body,
)

__all__ = [
    "AzureBlobConnector",
    "CheckpointStore",
    "ConnectorHealth",
    "ConnectorRegistry",
    "FileCheckpoint",
    "HandleResult",
    "InMemoryCheckpoint",
    "PollingConnector",
    "RemoteObject",
    "RunResult",
    "S3Connector",
    "SourceConnector",
    "TrackedConnector",
    "WebhookAuthError",
    "WebhookConnector",
    "WebhookError",
    "WebhookPayloadError",
    "WebhookReplayError",
    "acl_narrowed",
    "sign_body",
]
