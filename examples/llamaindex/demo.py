"""Register a LlamaIndex node at ingestion and guard a model-free list retriever."""

from ales_adapters.llamaindex_adapter import GuardedLlamaRetriever, IngestionCallback
from llama_index.core import SummaryIndex
from llama_index.core.schema import TextNode

from examples.local import PURPOSE, READER, client, register_handbook


def main() -> None:
    with client() as api:
        handbook = register_handbook(api)
        nodes = IngestionCallback(api)(handbook, [TextNode(text="Returns within 30 days.")])
        retriever = GuardedLlamaRetriever(api, READER, PURPOSE, SummaryIndex(nodes).as_retriever())
        allowed, blocked = retriever.retrieve("What is the return window?")
        assert len(allowed) == 1 and not blocked
        print("Nodes returned: 1")
        api.submit_revocation({"source_id": handbook["context_id"], "reason": "deleted"})
        allowed, blocked = retriever.retrieve("What is the return window?")
        assert not allowed and "ANCESTOR_DELETED" in blocked[0].reasons
        print("Nodes returned: 0 (ANCESTOR_DELETED)")


if __name__ == "__main__":
    main()
