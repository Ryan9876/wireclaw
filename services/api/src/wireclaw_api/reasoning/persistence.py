"""Bounded reasoning audit metadata persistence."""

import json

from ..service import identifier, now
from ..storage import encode


def new_session_id() -> str:
    return identifier()


def append_step(service, case_id: str, session_id: str, metadata: dict) -> None:
    record = {**metadata, "reasoning_session_id": session_id}
    with service.db.connect() as conn:
        sequence = conn.execute(
            "SELECT coalesce(max(sequence),0)+1 FROM reasoning_steps WHERE case_id=?", (case_id,)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO reasoning_steps VALUES(?,?,?,?,?)",
            (case_id, identifier(), sequence, now(), encode(record)),
        )


def steps(service, case_id: str, session_id: str | None = None) -> list[dict]:
    with service.db.connect() as conn:
        query = "SELECT step_id,sequence,at,metadata FROM reasoning_steps WHERE case_id=?"
        params: tuple = (case_id,)
        if session_id is not None:
            query += " AND json_extract(metadata,'$.reasoning_session_id')=?"
            params += (session_id,)
        query += " ORDER BY sequence"
        records = []
        for row in conn.execute(query, params):
            step_id, sequence, timestamp, encoded_metadata = row
            record = json.loads(encoded_metadata)
            record.update(
                {
                    "step_id": step_id,
                    "case_id": case_id,
                    "sequence": sequence,
                    "at": timestamp,
                }
            )
            records.append(record)
        return records
