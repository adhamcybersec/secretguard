"""
SecretGuard CLI - Main entry point
"""

from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table

from secretguard.scanner.engine import ScanEngine
from secretguard.reporters.json_reporter import JSONReporter
from secretguard.reporters.markdown_reporter import MarkdownReporter
from secretguard.reporters.html_reporter import HTMLReporter
from secretguard.reporters.sarif_reporter import SARIFReporter
from secretguard.config.loader import ConfigLoader
from secretguard.config.allowlist import AllowlistManager
from secretguard.hooks.installer import PreCommitInstaller

app = typer.Typer(
    name="secretguard",
    help="🔐 AI-enhanced secret detection and remediation tool",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    path: Path = typer.Argument(".", help="Path to scan for secrets"),
    format: str = typer.Option(
        "console", help="Output format: console, json, markdown, html, sarif"
    ),
    output: Optional[Path] = typer.Option(None, help="Output file path"),
    exclude: Optional[List[str]] = typer.Option(None, help="Patterns to exclude"),
    confidence: Optional[float] = typer.Option(None, help="Minimum confidence threshold (0.0-1.0)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    remediate: bool = typer.Option(False, help="Include remediation suggestions"),
    config: Optional[Path] = typer.Option(None, help="Path to config file (.secretguard.yml)"),
    no_config: bool = typer.Option(False, help="Ignore config file"),
    staged: bool = typer.Option(False, "--staged", help="Only scan git-staged files"),
    no_ml: bool = typer.Option(False, "--no-ml", help="Disable ML-based detection (faster scans)"),
    verify: bool = typer.Option(
        False, "--verify", help="Attempt live verification of detected credentials"
    ),
) -> None:
    """
    Scan a directory for exposed secrets and credentials
    """
    if not path.exists():
        console.print(f"[red]Error: Path '{path}' does not exist[/red]")
        raise typer.Exit(code=1)

    # Load configuration
    cfg = None
    if not no_config:
        try:
            cfg = ConfigLoader.load(config)
            if cfg.exclude or cfg.custom_patterns or cfg.allowlist:
                console.print("[dim]📝 Loaded configuration from .secretguard.yml[/dim]")
        except Exception as e:
            console.print(f"[yellow]⚠️  Config file error: {e}[/yellow]")
            cfg = None

    # Merge config with CLI args (CLI args take precedence)
    exclude_patterns = list(exclude) if exclude else []
    if cfg and cfg.exclude:
        exclude_patterns.extend(cfg.exclude)

    confidence_threshold = (
        confidence if confidence is not None else (cfg.confidence_threshold if cfg else 0.75)
    )

    console.print(f"[cyan]🔍 Scanning {path}...[/cyan]")

    # Initialize scanner
    engine = ScanEngine(
        exclude_patterns=exclude_patterns,
        confidence_threshold=confidence_threshold,
        verbose=verbose,
        custom_patterns=cfg.custom_patterns if cfg else [],
        use_ml=not no_ml,
    )

    # Run scan
    if staged:
        staged_files = engine.get_staged_files(path)
        if not staged_files:
            console.print("[yellow]No staged files to scan[/yellow]")
            raise typer.Exit(code=0)
        console.print(f"[cyan]Scanning {len(staged_files)} staged files...[/cyan]")
        results = engine.scan_files(staged_files)
    else:
        results = engine.scan(path)

    # Apply allowlist filtering
    if cfg and (cfg.allowlist or cfg.ignore_patterns):
        allowlist_mgr = AllowlistManager(cfg.allowlist, cfg.ignore_patterns)
        original_count = len(results.findings)
        results.findings = [f for f in results.findings if not allowlist_mgr.should_ignore(f)]
        filtered_count = original_count - len(results.findings)

        if filtered_count > 0 and verbose:
            console.print(f"[dim]✓ Filtered {filtered_count} allowlisted findings[/dim]")

        results.total_secrets = len(results.findings)

    # Live credential verification
    if verify and results.findings:
        from secretguard.verifiers.github_verifier import GitHubVerifier
        from secretguard.verifiers.aws_verifier import AWSVerifier

        verifiers = [GitHubVerifier(), AWSVerifier()]
        console.print("[cyan]Verifying credentials...[/cyan]")
        for finding in results.findings:
            for v in verifiers:
                if v.can_verify(finding.secret_type, finding.matched_text):
                    vr = v.verify(finding.matched_text)
                    finding.is_verified = vr.is_valid
                    status = (
                        "[red]ACTIVE[/red]" if vr.is_valid else "[green]inactive/invalid[/green]"
                    )
                    if vr.error:
                        status = f"[yellow]error: {vr.error}[/yellow]"
                    console.print(f"  {v.service_name}: {status} — {vr.detail}")
                    break

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
    elif format == "html":
        reporter = HTMLReporter()
        report_data = reporter.generate(results, include_remediation=True)  # Always include in HTML
        if output:
            reporter.save(report_data, output)
            console.print(f"[green]✅ HTML report saved to {output}[/green]")
        else:
            # Save to temp file and print path
            temp_output = Path("secretguard-report.html")
            reporter.save(report_data, temp_output)
            console.print(f"[green]✅ HTML report: {temp_output.absolute()}[/green]")
    elif format == "sarif":
        reporter = SARIFReporter()
        report_data = reporter.generate(results)
        if output:
            reporter.save(report_data, output)
            console.print(f"[green]SARIF report saved to {output}[/green]")
        else:
            print(report_data)
    else:
        console.print(f"[red]Error: Unknown format '{format}'[/red]")
        raise typer.Exit(code=1)

    # Display scan errors if any
    if results.scan_errors:
        console.print(
            f"\n[yellow]Warning: {len(results.scan_errors)} file(s) had scan errors[/yellow]"
        )
        if verbose:
            for err in results.scan_errors:
                console.print(f"  [dim]{err}[/dim]")

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
    table.add_column("Severity", style="bold red")
    table.add_column("Confidence", justify="right", style="green")

    for finding in results.findings:
        table.add_row(
            str(finding.file_path),
            str(finding.line_number),
            finding.secret_type,
            finding.severity.value.upper(),
            f"{finding.confidence:.2%}",
        )

    console.print(table)

    if include_remediation and results.findings:
        console.print("\n[bold cyan]Remediation Suggestions:[/bold cyan]")
        for idx, finding in enumerate(results.findings, 1):
            console.print(f"\n{idx}. {finding.file_path}:{finding.line_number}")
            console.print(f"   [yellow]Issue:[/yellow] {finding.secret_type}")
            console.print(f"   [green]Fix:[/green] {finding.remediation_suggestion}")


@app.command("scan-history")
def scan_history(
    path: Path = typer.Argument(".", help="Path to git repository"),
    max_commits: int = typer.Option(100, "--max-commits", help="Maximum commits to scan"),
    branch: Optional[str] = typer.Option(None, "--branch", help="Branch to scan"),
    format: str = typer.Option("console", help="Output format: console, json, sarif"),
    output: Optional[Path] = typer.Option(None, help="Output file path"),
    confidence: float = typer.Option(0.75, help="Minimum confidence threshold"),
) -> None:
    """Scan git history for secrets in past commits"""
    from secretguard.scanner.git_history import GitHistoryScanner

    console.print(f"[cyan]Scanning git history (up to {max_commits} commits)...[/cyan]")

    scanner = GitHistoryScanner(confidence_threshold=confidence)
    results = scanner.scan_history(path, max_commits=max_commits, branch=branch)

    if results.scan_errors:
        for err in results.scan_errors:
            console.print(f"[red]Error: {err}[/red]")

    if format == "console":
        table = Table(title="Git History Findings", show_header=True, header_style="bold magenta")
        table.add_column("Commit", style="cyan", max_width=10)
        table.add_column("Author", style="yellow")
        table.add_column("File", style="cyan")
        table.add_column("Type", style="red")
        table.add_column("Severity", style="bold red")

        for f in results.findings:
            table.add_row(
                f.commit_hash[:8],
                f.commit_author,
                str(f.file_path),
                f.secret_type,
                f.severity.value.upper(),
            )
        console.print(table)
    elif format == "json":
        reporter = JSONReporter()
        report_data = reporter.generate(results)
        if output:
            reporter.save(report_data, output)
        else:
            print(report_data)
    elif format == "sarif":
        reporter = SARIFReporter()
        report_data = reporter.generate(results)
        if output:
            reporter.save(report_data, output)
        else:
            print(report_data)

    if results.total_secrets > 0:
        console.print(f"\n[yellow]Found {results.total_secrets} secrets in git history![/yellow]")
        raise typer.Exit(code=1)
    else:
        console.print("\n[green]No secrets found in git history.[/green]")


@app.command("ml-evaluate")
def ml_evaluate() -> None:
    """Evaluate the ML classifier with cross-validation metrics"""
    from secretguard.ml.classifier import SecretClassifier
    from secretguard.ml.training_data import TRAINING_DATA
    from rich.table import Table

    console.print("[cyan]Evaluating ML classifier (5-fold stratified CV)...[/cyan]")
    console.print(f"[dim]Training samples: {len(TRAINING_DATA)}[/dim]")

    clf = SecretClassifier()
    metrics = clf.evaluate()

    table = Table(title="ML Classifier Evaluation")
    table.add_column("Metric", style="cyan")
    table.add_column("Score", justify="right", style="green")

    for name, value in metrics.items():
        table.add_row(name.capitalize(), f"{value:.4f}")

    console.print(table)


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

    ConfigLoader.create_default_config(config_path)
    console.print("[green]✅ Created .secretguard.yml[/green]")
    console.print("[dim]Edit this file to customize SecretGuard behavior[/dim]")


@app.command("install-hook")
def install_hook() -> None:
    """Install pre-commit hook to prevent committing secrets"""
    try:
        if PreCommitInstaller.install():
            console.print("[green]✅ Pre-commit hook installed![/green]")
            console.print("[dim]Secrets will be scanned before each commit[/dim]")
            console.print("[dim]To bypass: git commit --no-verify (not recommended)[/dim]")
        else:
            console.print("[yellow]ℹ️  SecretGuard pre-commit hook already installed[/yellow]")
    except ValueError as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("uninstall-hook")
def uninstall_hook() -> None:
    """Uninstall pre-commit hook"""
    if PreCommitInstaller.uninstall():
        console.print("[green]✅ Pre-commit hook uninstalled[/green]")
    else:
        console.print("[yellow]ℹ️  SecretGuard pre-commit hook not found[/yellow]")


@app.command("hook-status")
def hook_status() -> None:
    """Check if pre-commit hook is installed"""
    if PreCommitInstaller.is_installed():
        console.print("[green]✅ Pre-commit hook is installed[/green]")
    else:
        console.print("[yellow]❌ Pre-commit hook is not installed[/yellow]")
        console.print("[dim]Install with: secretguard install-hook[/dim]")


if __name__ == "__main__":
    app()
