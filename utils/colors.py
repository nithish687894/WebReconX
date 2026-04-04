"""ANSI color utilities for terminal output."""

class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

    @staticmethod
    def strip(text: str) -> str:
        """Remove all ANSI codes from a string."""
        import re
        return re.sub(r'\033\[[0-9;]*m', '', text)
