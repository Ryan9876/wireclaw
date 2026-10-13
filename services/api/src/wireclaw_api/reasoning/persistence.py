"""Bounded reasoning audit metadata persistence."""

import json

from ..service import identifier, now
from ..storage import encode


def append_step(service, case_id: str, metadata: dict) -> None:
    with service.db.connect() as conn:
        sequence = conn.execute(
            "SELECT coalesce(max(sequence),0)+1 FROM reasoning_steps WHERE case_id=?", (case_id,)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO reasoning_steps VALUES(?,?,?,?,?)",
            (case_id, identifier(), sequence, now(), encode(metadata)),
        )


def steps(service, case_id: str) -> list[dict]:
    with service.db.connect() as conn:
        return [
            json.loads(row[0])
            for row in conn.execute(
                "SELECT metadata FROM reasoning_steps WHERE case_id=? ORDER BY sequence",
                (case_id,),
            )
        ]


def clear_steps(service, case_id: str) -> None:
    with service.db.connect() as conn:
        conn.execute("DELETE FROM reasoning_steps WHERE case_id=?", (case_id,))
