"""
SecretGuard CLI - Main entry point
"""

from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from secretguard.scanner.engine import ScanEngine
from secretguard.reporters.json_reporter import JSONReporter
from secretguard.reporters.markdown_reporter import MarkdownReporter

app = typer.Typer(
    name="secretguard",
    help="🔐 AI-enhanced secret detection and remediation tool",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to scan for secrets"),
    format: str = typer.Option("console", help="Output format: console, json, markdown"),
    output: Optional[Path] = typer.Option(None, help="Output file path"),
    exclude: Optional[List[str]] = typer.Option(None, help="Patterns to exclude"),
    confidence: float = typer.Option(0.75, help="Minimum confidence threshold (0.0-1.0)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    remediate: bool = typer.Option(False, help="Include remediation suggestions"),
) -> None:
    """
    Scan a directory for exposed secrets and credentials
    """
    if not path.exists():
        console.print(f"[red]Error: Path '{path}' does not exist[/red]")
        raise typer.Exit(code=1)

    console.print(f"[cyan]🔍 Scanning {path}...[/cyan]")
    
    # Initialize scanner
    engine = ScanEngine(
        exclude_patterns=exclude or [],
        confidence_threshold=confidence,
        verbose=verbose,
    )
    
    # Run scan
    results = engine.scan(path)
    
    # Display results
    if format == "console":
        display_console_results(results, remediate)
    elif format == "json":
        reporter = JSONReporter()
        report_data = reporter.generate(results, include_remediation=remediate)
        if output:
            reporter.save(report_data, output)
            console.print(f"[green]✅ Report saved to {output}[/green]")
        else:
            print(report_data)
    elif format == "markdown":
        reporter = MarkdownReporter()
        report_data = reporter.generate(results, include_remediation=remediate)
        if output:
            reporter.save(report_data, output)
            console.print(f"[green]✅ Report saved to {output}[/green]")
        else:
            print(report_data)
    else:
        console.print(f"[red]Error: Unknown format '{format}'[/red]")
        raise typer.Exit(code=1)
    
    # Exit with error code if secrets found
    if results.total_secrets > 0:
        console.print(f"\n[yellow]⚠️  Found {results.total_secrets} potential secrets![/yellow]")
        raise typer.Exit(code=1)
    else:
        console.print("\n[green]✅ No secrets detected![/green]")


def display_console_results(results, include_remediation: bool = False) -> None:
    """Display scan results in console format"""
    table = Table(title="Secret Detection Results", show_header=True, header_style="bold magenta")
    table.add_column("File", style="cyan")
    table.add_column("Line", justify="right", style="yellow")
    table.add_column("Type", style="red")
    table.add_column("Confidence", justify="right", style="green")
    
    for finding in results.findings:
        table.add_row(
            str(finding.file_path),
            str(finding.line_number),
            finding.secret_type,
            f"{finding.confidence:.2%}",
        )
    
    console.print(table)
    
    if include_remediation and results.findings:
        console.print("\n[bold cyan]Remediation Suggestions:[/bold cyan]")
        for idx, finding in enumerate(results.findings, 1):
            console.print(f"\n{idx}. {finding.file_path}:{finding.line_number}")
            console.print(f"   [yellow]Issue:[/yellow] {finding.secret_type}")
            console.print(f"   [green]Fix:[/green] {finding.remediation_suggestion}")


@app.command()
def version() -> None:
    """Show version information"""
    from secretguard import __version__
    console.print(f"SecretGuard v{__version__}")


@app.command()
def init() -> None:
    """Initialize SecretGuard configuration in current directory"""
    config_path = Path(".secretguard.yml")
    
    if config_path.exists():
        console.print("[yellow]⚠️  .secretguard.yml already exists[/yellow]")
        return
    
    default_config = """# SecretGuard Configuration

# Paths to exclude from scanning
exclude:
  - "node_modules/**"
  - "vendor/**"
  - "*.test.js"
  - "*.test.py"

# Minimum confidence threshold (0.0-1.0)
confidence_threshold: 0.75

# Custom patterns (regex)
custom_patterns:
  # - name: "Custom API Key"
  #   pattern: "CUSTOM_[A-Z0-9]{32}"
  #   severity: high

# False positive patterns to ignore
ignore_patterns:
  - "example_api_key_here"
  - "REPLACE_WITH_YOUR_KEY"
  - "your_api_key_here"
"""
    
    config_path.write_text(default_config)
    console.print("[green]✅ Created .secretguard.yml[/green]")


if __name__ == "__main__":
    app()
