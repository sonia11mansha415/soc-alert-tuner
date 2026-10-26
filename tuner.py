import json
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def load_data(filepath):
    if not os.path.exists(filepath):
        console.print(f"[bold red][!] File not found: {filepath}[/bold red]")
        return None
    with open(filepath, 'r') as f:
        return json.load(f)

def generate_exclusions(alert, reason_type):
    splunk_exclusion = ""
    kql_exclusion = ""
    
    if reason_type == "scanner":
        splunk_exclusion = f'| search NOT (src_ip="{alert.get("source_ip")}" AND user="{alert.get("user")}")'
        kql_exclusion = f'NOT (source.ip: "{alert.get("source_ip")}" and user.name: "{alert.get("user")}")'
    elif reason_type == "service_account":
        splunk_exclusion = f'| search NOT (user="{alert.get("user")}" AND process_name="{alert.get("process")}")'
        kql_exclusion = f'NOT (user.name: "{alert.get("user")}" and process.name: "{alert.get("process")}")'
        
    return splunk_exclusion, kql_exclusion

def analyze_alert(alert, baseline):
    src_ip = alert.get("source_ip")
    user = alert.get("user")
    process = alert.get("process")

    for scanner in baseline.get("approved_scanners", []):
        if src_ip == scanner.get("ip"):
            return {
                "verdict": "BENIGN_TUNING_CANDIDATE",
                "reason": f"Matches Known Scanner: {scanner.get('purpose')}",
                "type": "scanner"
            }

    for svc in baseline.get("service_accounts", []):
        if user == svc.get("username") and process in svc.get("authorized_tasks", []):
            return {
                "verdict": "BENIGN_TUNING_CANDIDATE",
                "reason": f"Authorized Routine Task: {svc.get('purpose')}",
                "type": "service_account"
            }

    return {
        "verdict": "TRUE_POSITIVE_THREAT",
        "reason": "No baseline match found. Anomaly requires immediate investigation.",
        "type": "malicious"
    }

def main():
    console.print(Panel.fit("[bold cyan]SOC Alert Tuning & False-Positive Optimizer[/bold cyan]", border_style="cyan"))

    baseline = load_data("baseline.json")
    alerts = load_data("alerts.json")

    if not baseline or not alerts:
        return

    table = Table(title="Alert Analysis Summary", header_style="bold magenta")
    table.add_column("Alert ID", style="dim", width=10)
    table.add_column("Rule Name", width=35)
    table.add_column("Verdict", width=25)
    table.add_column("Action / Recommendation", width=35)

    tuning_queue = []

    for alert in alerts:
        result = analyze_alert(alert, baseline)
        verdict = result["verdict"]
        
        if verdict == "BENIGN_TUNING_CANDIDATE":
            styled_verdict = "[bold green]Benign (Noise)[/bold green]"
            action = f"[yellow]Tune Rule[/yellow] ({result['reason']})"
            tuning_queue.append((alert, result["type"], result["reason"]))
        else:
            styled_verdict = "[bold red]True Positive (TP)[/bold red]"
            action = "[bold red]Escalate to Incident Response[/bold red]"

        table.add_row(alert.get("alert_id"), alert.get("rule_name"), styled_verdict, action)

    console.print(table)
    print("\n")

    if tuning_queue:
        console.print(Panel("[bold yellow]Auto-Generated SIEM Tuning Exclusions[/bold yellow]", border_style="yellow"))
        for alert, reason_type, reason in tuning_queue:
            splunk_q, kql_q = generate_exclusions(alert, reason_type)
            console.print(f"[bold cyan]Target Rule:[/bold cyan] {alert.get('rule_name')} (ID: {alert.get('alert_id')})")
            console.print(f"[dim]Context: {reason}[/dim]")
            console.print(f"[green]Splunk SPL Exclusion:[/green]\n  {splunk_q}")
            console.print(f"[blue]Elastic KQL Exclusion:[/blue]\n  {kql_q}\n")

if __name__ == "__main__":
    main()