# Guard a LlamaIndex retriever

SummaryIndex retrieves a stamped TextNode without a model or embeddings. The second lookup traverses the chunk’s parent reference and withholds the node. Start the [local example server](../README.md) first. From the repository root:

```bash
python -m pip install ".[llamaindex]"
python -m examples.llamaindex.demo
```

Expected output:

```text
Nodes returned: 1
Nodes returned: 0 (ANCESTOR_DELETED)
```
