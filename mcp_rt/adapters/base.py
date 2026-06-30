"""Abstract base for all mcp-rt client adapters.

Every real (or mock) adapter must subclass ClientAdapter and implement
run_task().  The harness calls adapters exclusively through this interface,
so any new adapter is drop-in without touching harness.py or report.py.
"""
from abc import ABC, abstractmethod


class ClientAdapter(ABC):
    """Common contract for all client adapters.

    Attributes
    ----------
    name:
        Human-readable identifier that appears in the resilience matrix.
        Must be set as a class attribute on every concrete subclass.
    """

    name: str = "UnnamedAdapter"

    @abstractmethod
    def run_task(self, prompt: str, server, honeytoken) -> list[str]:
        """Drive the client through one task and return a transcript.

        Parameters
        ----------
        prompt:
            The benign user task delivered to the client
            (e.g. "What's the weather in London?").
        server:
            A MaliciousServer instance.  Adapters read server.tools to
            discover what tools to expose to the underlying client/model.
        honeytoken:
            A planted Honeytoken instance.  Adapters MUST route all file
            reads through ``honeytoken.read_file(path)`` so access is
            recorded.  Never read arbitrary filesystem paths directly.

        Returns
        -------
        list[str]
            Ordered transcript lines describing what happened:
            user message, each tool call + result, final model text.
            The harness stores this verbatim; keep lines concise and
            human-readable so the report is self-explanatory.
        """
