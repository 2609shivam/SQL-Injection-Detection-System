from rich.console import Console
from rich.panel import Panel

console = Console()

def show_request(flow):
    method = flow.request.method
    path = flow.request.path

    console.print(f"[cyan]{method}[/cyan] {path}")

def show_detection(flow, location, param, payload, reason, risk):
    color = {
        "LOW": "yellow",
        "MEDIUM": "orange3",
        "HIGH": "red"
    }.get(risk, "white")

    body = f"""
[bold]Method:[/bold] {flow.request.method}
[bold]URL:[/bold] {flow.request.pretty_url}
[bold]Location:[/bold] {location}
[bold]Parameter:[/bold] {param}
[bold]Payload:[/bold] {payload}
[bold]Reason:[/bold] {reason}
[bold]Risk:[/bold] {risk}
"""

    console.print(
        Panel(
            body.strip(),
            title="🚨 SQL Injection Detected",
            border_style=color
        )
    )
