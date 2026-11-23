"""Filter a retrieval node's output before the next LangGraph node sees it."""

from typing import TypedDict

from ales_adapters.langgraph_middleware import guard_node
from langgraph.graph import END, START, StateGraph

from examples.local import PURPOSE, READER, client, register_handbook


class State(TypedDict, total=False):
    documents: list[dict]
    ales_blocked: list[dict]


def main() -> None:
    with client() as api:
        handbook = register_handbook(api)

        @guard_node(
            api,
            READER,
            PURPOSE,
            id_getter=lambda doc: doc["context_id"],
            version_getter=lambda doc: doc["object_version"],
        )
        def retrieve(state: State) -> State:
            return {
                "documents": [
                    {
                        "context_id": handbook["context_id"],
                        "object_version": "1",
                        "text": "Returns within 30 days.",
                    }
                ]
            }

        graph = StateGraph(State)
        graph.add_node("retrieve", retrieve)
        graph.add_edge(START, "retrieve")
        graph.add_edge("retrieve", END)
        run = graph.compile()
        assert len(run.invoke({"documents": []})["documents"]) == 1
        print("Documents returned: 1")
        api.submit_revocation({"source_id": handbook["context_id"], "reason": "deleted"})
        result = run.invoke({"documents": []})
        assert result["documents"] == [] and "ANCESTOR_DELETED" in result["ales_blocked"][0]["reasons"]
        print("Documents returned: 0 (ANCESTOR_DELETED)")


if __name__ == "__main__":
    main()
