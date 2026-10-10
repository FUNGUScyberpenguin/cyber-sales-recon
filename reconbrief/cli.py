from pathlib import Path
from typing import Optional

import typer

import reconbrief
from reconbrief.deck import OutlineError, load_json, render_deck
from reconbrief.http import AddressGuard, HttpClient
from reconbrief.preflight import run_preflight
from reconbrief.recommend import ProfileError, load_offerings
from reconbrief.resolver import DnsResolver
from reconbrief.run import BadDomain, run_recon

app = typer.Typer(help="reconbrief: public-data recon for cybersecurity sales.", no_args_is_help=True)


@app.callback()
def main() -> None:
    """reconbrief: public-data recon for cybersecurity sales."""


@app.command()
def version() -> None:
    """Print the engine version."""
    typer.echo(f"reconbrief {reconbrief.__version__}")


@app.command()
def preflight() -> None:
    """Check that this network can reach every host a run needs."""
    result = run_preflight(HttpClient(AddressGuard(DnsResolver())))
    typer.echo(result.message())
    raise typer.Exit(0 if result.ok else 3)


@app.command()
def run(
    domain: str = typer.Argument(..., help="The prospect's domain, for example acme.com."),
    out: Path = typer.Option(Path("."), "--out", help="Folder for bundle.json and snapshot.json."),
    company: str = typer.Option("", "--company", help="The company's name, if the user gave one."),
    profile: Optional[Path] = typer.Option(None, "--profile", help="The firm profile file."),
    data_dir: Optional[Path] = typer.Option(None, "--data-dir", help="Where downloaded tools are cached."),
) -> None:
    """Research a domain from public data and write bundle.json and snapshot.json."""
    try:
        offerings = load_offerings(profile) if profile else None
        output = run_recon(domain, out, company, offerings, data_dir)
    except (BadDomain, ProfileError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2)
    if output.blocked is not None:
        typer.echo(output.blocked.message(), err=True)
        raise typer.Exit(3)
    typer.echo(f"Wrote {Path(out) / 'bundle.json'} and {Path(out) / 'snapshot.json'}")


@app.command()
def deck(
    outline: Path = typer.Argument(..., help="The slide outline (JSON)."),
    bundle: Path = typer.Option(..., "--bundle", help="The run's bundle.json."),
    out: Path = typer.Option(..., "--out", help="Where to write the .pptx."),
    template: Optional[Path] = typer.Option(None, "--template", help="The user's brand template."),
) -> None:
    """Render a slide outline into a .pptx."""
    try:
        path = render_deck(load_json(outline), load_json(bundle), out, template)
    except OutlineError as exc:
        typer.echo(f"Outline rejected: {exc}", err=True)
        raise typer.Exit(2)
    typer.echo(f"Wrote {path}")
