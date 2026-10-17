"""FalkorDB connection helper."""
import os

from falkordb import FalkorDB


def get_graph():
    db = FalkorDB(
        host=os.getenv("FALKORDB_HOST", "localhost"),
        port=int(os.getenv("FALKORDB_PORT", "6379")),
        username=os.getenv("FALKORDB_USERNAME") or None,
        password=os.getenv("FALKORDB_PASSWORD") or None,
    )
    return db.select_graph(os.getenv("GRAPH_NAME", "graphshield"))
