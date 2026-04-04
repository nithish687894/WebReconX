"""Abstract base class for all WebReconX scanning modules."""
from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseScanner(ABC):
    """
    Every module inherits from this class.
    Implement scan() and display() in each subclass.
    """

    def __init__(self, target: str, domain: str, timeout: int = 10, verbose: bool = False):
        self.target  = target
        self.domain  = domain
        self.timeout = timeout
        self.verbose = verbose

    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """Run the scan and return a results dict."""
        ...

    @abstractmethod
    def display(self, results: Dict[str, Any]) -> None:
        """Pretty-print results to the terminal."""
        ...
