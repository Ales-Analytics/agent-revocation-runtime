# Run an integration

For the packaged RAG demo, install the checkout with `python -m pip install .` and run `ales quickstart`. For the four individual integrations below, start a disposable HTTP control plane from the repository root in one terminal:

```bash
python -m pip install .
python -m examples.local
```

Leave it running and use a second terminal for the commands in each guide. The server binds to loopback on port 8787 and uses in-memory SQLite. Restarting it clears its tenant data. The dev Compose stack on the same port also accepts these examples. Use synthetic content here.

| Integration | What you can observe |
|---|---|
| [RAG source](revoke-rag-source/README.md) | One ACL edit invalidates retrieval, cache replay and memory reads across 12 checkpoints. |
| [TypeScript client](typescript/README.md) | An ESM consumer posts a source, checks its exact version and observes the decision after deletion. |
| [LangGraph](langgraph/README.md) | A compiled graph filters the retrieval node's output. |
| [LlamaIndex](llamaindex/README.md) | An ingestion callback stamps node lineage and the guarded retriever filters a revoked chunk. |
| [Cache only](cache/README.md) | A guarded cache hit becomes a blocked read before a purge worker runs. |
