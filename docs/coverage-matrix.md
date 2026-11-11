# Coverage matrix

Each row is an adapter. A coverage claim is made only for paths in `Can block` that are marked enforcing and whose status is conformant. Adapters that observe but cannot block are labelled `OBSERVE_ONLY` and are excluded from coverage claims (see `docs/guarantees.md`).

Legend:

- **Enters:** where context from a source is registered with an envelope.
- **Derives:** where new objects are created with `parent_refs`.
- **Retrieves:** where content is returned and authorization is required.
- **Can block:** whether the adapter can refuse use at the retrieval or handoff point.

| Adapter | Enters | Derives | Retrieves | Can block | Conformance status |
|---|---|---|---|---|---|
| pgvector wrapper | Pending | Pending | Pending | Pending | pending conformance |
| Redis cache wrapper | Pending | Pending | Pending | Pending | pending conformance |
| LangGraph middleware | Pending | Pending | Pending | Pending | pending conformance |
| Filesystem source connector | Pending | Not applicable (source only) | Not applicable | Pending | pending conformance |

Notes:

- Every row is pending. No adapter is currently claimed as conformant.
- Filling in a cell requires a concrete answer to the corresponding question in `docs/integration-guide.md`, such as the function or hook name, not a general statement.
- A row becomes `OBSERVE_ONLY` if its `Can block` column is `no` for any protected path. Such a row is excluded from coverage totals.
- The filesystem connector is a source, so it registers envelopes but has no derivatives. Its retrieval is covered by the other adapters that read its output.
