"""Terminal banner and output formatting utilities."""
from utils.colors import Colors


BANNER = r"""
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
"""


def print_banner(version: str = "1.0.0") -> None:
    print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
    print(f"  {Colors.GREEN}Advanced Web Security Reconnaissance Framework{Colors.RESET}")
    print(f"  Version {version}  |  github.com/nithish687894/WebReconX\n")


def print_section(title: str) -> None:
    print(f"\n  {Colors.CYAN}┌{'─' * 64}┐{Colors.RESET}")
    print(f"  {Colors.CYAN}│{Colors.RESET} {Colors.BOLD}▶ {title:<62}{Colors.RESET}{Colors.CYAN}│{Colors.RESET}")
    print(f"  {Colors.CYAN}└{'─' * 64}┘{Colors.RESET}\n")


def print_result(msg: str) -> None:
    print(f"    {Colors.GREEN}[✓]{Colors.RESET} {msg}")


def print_error(msg: str) -> None:
    print(f"    {Colors.RED}[✗]{Colors.RESET} {msg}")


def print_info(msg: str) -> None:
    print(f"    {Colors.BLUE}[i]{Colors.RESET} {msg}")


def print_warning(msg: str) -> None:
    print(f"    {Colors.YELLOW}[!]{Colors.RESET} {msg}")


def print_high(msg: str) -> None:
    print(f"    {Colors.RED}[HIGH]{Colors.RESET}   {msg}")


def print_medium(msg: str) -> None:
    print(f"    {Colors.YELLOW}[MEDIUM]{Colors.RESET} {msg}")


def print_low(msg: str) -> None:
    print(f"    {Colors.GREEN}[LOW]{Colors.RESET}    {msg}")
