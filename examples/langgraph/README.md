# Guard a LangGraph retrieval node

The node returns one handbook record with its context ID and version. The guard filters its output before downstream nodes receive state. Start the [local example server](../README.md) first. From the repository root:

```bash
python -m pip install ".[demo]"
python -m examples.langgraph.demo
```

Expected output:

```text
Documents returned: 1
Documents returned: 0 (ANCESTOR_DELETED)
```
