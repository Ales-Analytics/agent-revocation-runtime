# Check a cached answer

GuardedCache registers the answer as a derivative. DictRedis holds the bytes in process. The HTTP control plane decides whether the reader may replay them. Start the [local example server](../README.md) first. From the repository root:

```bash
python -m examples.cache.demo
```

Expected output:

```text
Cached answer: 30 days
Cached answer withheld: ANCESTOR_DELETED
```
