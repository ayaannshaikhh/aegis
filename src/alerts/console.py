from __future__ import annotations
from typing import Dict, Any
from rich.console import Console

console = Console()

def emit_alert(payload: Dict[str, Any]) -> None:
    console.print(f"[bold red]ALERT[/bold red] score={payload['score']:.3f} "
                  f"(stat={payload['stat']:.3f}, ml={payload['ml']:.3f}) "
                  f"window={payload['start_ts']:.2f}-{payload['end_ts']:.2f}")
    console.print(f"  reasons: {payload.get('reasons', {})}")