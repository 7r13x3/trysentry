"""
TrySentry — Logger
Blue & white theme.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn,
)

console = Console()

BLUE      = "bright_blue"
BLUE_DIM  = "blue"
WHITE     = "white"
WHITE_DIM = "grey70"


def info(msg: str):
    console.print(f"[{BLUE}][INFO][/{BLUE}]  [{WHITE}]{msg}[/{WHITE}]")


def ok(msg: str):
    console.print(f"[{BLUE}][ OK ][/{BLUE}]  [{WHITE}]{msg}[/{WHITE}]")


def warn(msg: str):
    console.print(f"[{BLUE}][WARN][/{BLUE}]  [{WHITE}]{msg}[/{WHITE}]")


def error(msg: str):
    console.print(f"[bold {BLUE}][FAIL][/bold {BLUE}]  "
                  f"[{WHITE}]{msg}[/{WHITE}]")


def alert(msg: str):
    console.print(f"[bold white on bright_blue] ALERT [/bold white on bright_blue] "
                  f"[{WHITE}]{msg}[/{WHITE}]")


def step(msg: str):
    console.print(f"[{BLUE}]▸[/{BLUE}] [{WHITE}]{msg}[/{WHITE}]")


def hint(msg: str):
    console.print(f"    [{WHITE_DIM}]{msg}[/{WHITE_DIM}]")


def line(char: str = "─", n: int = 64):
    console.print(f"[{BLUE_DIM}]{char * n}[/{BLUE_DIM}]")


def banner():
    logo = r"""
              ████████╗██████╗ ██╗   ██╗
              ╚══██╔══╝██╔══██╗╚██╗ ██╔╝
                 ██║   ██████╔╝ ╚████╔╝
                 ██║   ██╔══██╗  ╚██╔╝
                 ██║   ██║  ██║   ██║
                 ╚═╝   ╚═╝  ╚═╝   ╚═╝

              S E N T R Y

     Endpoint Detection & Response
                    v1.0.0
"""
    console.print(f"[bold {BLUE}]{logo}[/bold {BLUE}]")
    line("═", 64)


def menu(title: str, options: list):
    console.print(f"[bold {BLUE}]╔{'═' * 62}╗[/bold {BLUE}]")
    console.print(f"[bold {BLUE}]║[/bold {BLUE}]  "
                  f"[{WHITE}]{title:<60}[/{WHITE}]"
                  f"[bold {BLUE}]║[/bold {BLUE}]")
    console.print(f"[bold {BLUE}]╠{'═' * 62}╣[/bold {BLUE}]")
    for key, label in options:
        k = f"[{key:>3}]" if key else "     "
        console.print(
            f"[bold {BLUE}]║[/bold {BLUE}]  "
            f"[{BLUE}]{k}[/{BLUE}]  "
            f"[{WHITE}]{label:<53}[/{WHITE}]"
            f"[bold {BLUE}]║[/bold {BLUE}]"
        )
    console.print(f"[bold {BLUE}]╚{'═' * 62}╝[/bold {BLUE}]")
    console.print()


def table(title: str, columns: list, rows: list):
    t = Table(
        title=f"[bold {BLUE}]{title}[/bold {BLUE}]",
        border_style=BLUE_DIM,
        header_style=f"bold {BLUE}",
    )
    for col in columns:
        t.add_column(col, style=WHITE)
    for row in rows:
        t.add_row(*[str(x) for x in row])
    console.print(t)


def panel(title: str, body: str):
    console.print(Panel(
        f"[{WHITE}]{body}[/{WHITE}]",
        title=f"[bold {BLUE}]{title}[/bold {BLUE}]",
        border_style=BLUE,
    ))


def progress_bar(description: str):
    return Progress(
        SpinnerColumn(style=BLUE),
        TextColumn(f"[{WHITE}]{description}"),
        BarColumn(bar_width=30, style=BLUE_DIM, complete_style=BLUE),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )
