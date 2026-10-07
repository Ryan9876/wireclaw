"""Errors intentionally exclude raw tool output and packet-derived strings."""


class AnalyzerError(Exception):
    def __init__(self, code: str, capability: str = "", tool: str = ""):
        self.code, self.capability, self.tool = code, capability, tool
        super().__init__(code)

    def as_dict(self) -> dict:
        return {"code": self.code, "capability": self.capability, "tool": self.tool}
