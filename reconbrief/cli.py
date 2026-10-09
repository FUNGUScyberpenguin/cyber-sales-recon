import typer

import reconbrief

app = typer.Typer(help="reconbrief: public-data recon for cybersecurity sales.", no_args_is_help=True)


@app.callback()
def main() -> None:
    """reconbrief: public-data recon for cybersecurity sales."""


@app.command()
def version() -> None:
    """Print the engine version."""
    typer.echo(f"reconbrief {reconbrief.__version__}")
