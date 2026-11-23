"""Start a disposable control plane shared by the integration examples."""

from ales_sdk import InvariantClient, new_source
from ales_sdk.revoke_demo import DEV_COMPOSE_TENANT, DEV_COMPOSE_TOKEN

READER = {"type": "user", "id": "support-reader"}
PURPOSE = "support"


def client() -> InvariantClient:
    return InvariantClient("http://127.0.0.1:8787", DEV_COMPOSE_TENANT, auth_token=DEV_COMPOSE_TOKEN)


def register_handbook(api: InvariantClient) -> dict:
    source = new_source(
        api.tenant_id,
        "handbook",
        "Returns within 30 days.",
        "examples",
        principal_scope=[READER["id"]],
        purpose_scope=[PURPOSE],
    )
    api.register_source(source)
    return source


if __name__ == "__main__":
    import uvicorn
    from ales_server import create_app

    tokens = {
        DEV_COMPOSE_TOKEN: {
            "tenant_id": DEV_COMPOSE_TENANT,
            "subject": "local-example",
            "roles": ["ingest", "revoke", "read"],
        }
    }
    uvicorn.run(
        create_app("sqlite://", tokens=tokens, env={}, outbox_interval=0), host="127.0.0.1", port=8787
    )
