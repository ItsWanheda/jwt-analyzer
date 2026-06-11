import click
import json
from rich.console import Console
from rich.table import Table
from utils.io import read_token_from_file, read_text_file
from core.parser import parse_jwt
from core.security import check_none_algorithm, brute_force_secret
from core.diff import compare_payloads
from core.verification import verify_with_public_key
from core.forgery import forge_token
from config import Config

console = Console()
if not Config.is_rich_enabled():
    console = Console(force_terminal=False)

@click.group()
def cli():
    """JWT Analyzer v1.1 - Professional Security Tool"""
    pass

@cli.command()
@click.option('--token-file', required=True, help='Path to the JWT file')
def analyze(token_file):
    """Analyze a single JWT token."""
    try:
        token = read_token_from_file(token_file)
        data = parse_jwt(token)
        
        console.print("[bold blue]JWT Analysis Report[/bold blue]")
        console.print(f"Header: {data['header']}")
        console.print(f"Payload: {data['payload']}")
        
        if data['expiry_info']:
            exp_info = data['expiry_info']
            if exp_info['is_expired']:
                console.print(f"[bold red]⚠️  EXPIRED: Token expired {abs(exp_info['remaining_seconds']):.0f} seconds ago.[/bold red]")
            else:
                console.print(f"[bold green]✅ Valid: Token expires in {exp_info['remaining_seconds']:.0f} seconds.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

@cli.command()
@click.option('--token-file', required=True, help='Path to the JWT file')
def security(token_file):
    """Run security checks on the JWT."""
    try:
        token = read_token_from_file(token_file)
        if check_none_algorithm(token):
            console.print("[bold red][CRITICAL] Algorithm 'none' detected! Server may be vulnerable.[/bold red]")
        else:
            console.print("[bold green][OK] Algorithm is not 'none'.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

@cli.command()
@click.option('--token-file', required=True, help='Path to the JWT file')
@click.option('--wordlist', default=None, help='Path to the wordlist file')
def brute_force(token_file, wordlist):
    """Brute-force the JWT secret."""
    wordlist_path = wordlist if wordlist else Config.get_wordlist_path()
    try:
        token = read_token_from_file(token_file)
        with open(wordlist_path, 'r') as f:
            secrets = [line.strip() for line in f if line.strip()]
            
        console.print("[bold yellow]Starting brute-force attack...[/bold yellow]")
        found_secret = brute_force_secret(token, secrets)
        
        if found_secret:
            console.print(f"[bold green][+] SUCCESS! Secret found: '{found_secret}'[/bold green]")
        else:
            console.print("[bold red][-] Secret not found in wordlist.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

@cli.command()
@click.option('--token1', required=True, help='Path to first JWT file')
@click.option('--token2', required=True, help='Path to second JWT file')
def diff(token1, token2):
    """Compare two JWT payloads."""
    try:
        differences = compare_payloads(token1, token2)
        if not differences['added'] and not differences['removed'] and not differences['changed']:
            console.print("[bold green]Payloads are identical.[/bold green]")
            return
            
        table = Table(title="Payload Differences")
        table.add_column("Key", style="cyan")
        table.add_column("Old Value", style="white")
        table.add_column("New Value", style="white")
        
        for key, values in differences['changed'].items():
            table.add_row(key, str(values['old']), str(values['new']))
        for key, value in differences['added'].items():
            table.add_row(key, "-", str(value))
        for key, value in differences['removed'].items():
            table.add_row(key, str(value), "-")
            
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

@cli.command()
@click.option('--token-file', required=True, help='Path to the JWT file')
@click.option('--public-key', required=True, help='Path to the public key (PEM or JWK)')
@click.option('--output', default=None, help='Save report to file (JSON)')
def verify_rsa(token_file, public_key, output):
    """Verify a JWT using a public key."""
    try:
        token = read_token_from_file(token_file)
        key_content = read_text_file(public_key)
        result = verify_with_public_key(token, key_content)
        
        if result['status'] == 'valid':
            console.print("[bold green]✅ Token is valid![/bold green]")
            console.print(f"Payload: {result['payload']}")
        else:
            console.print(f"[bold red]❌ Token verification failed: {result['error']}[/bold red]")
            
        if output:
            with open(output, 'w') as f:
                json.dump(result, f, indent=2)
            console.print(f"[bold blue]Report saved to {output}[/bold blue]")
            
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

@cli.command()
@click.option('--token-file', required=True, help='Path to the original JWT file')
@click.option('--payload-file', required=True, help='Path to the new payload JSON file')
@click.option('--secret', required=True, help='Secret key for signing')
@click.option('--algorithm', default='HS256', help='Algorithm to use (default: HS256)')
@click.option('--output', default=None, help='Save forged token to file')
def forge(token_file, payload_file, secret, algorithm, output):
    """Forge a JWT token with a new payload."""
    try:
        token = read_token_from_file(token_file)
        with open(payload_file, 'r') as f:
            new_payload = json.load(f)
            
        forged_token = forge_token(token, new_payload, secret, algorithm)
        console.print(f"[bold green]✅ Token forged successfully![/bold green]")
        console.print(f"Forged Token: {forged_token}")
        
        if output:
            with open(output, 'w') as f:
                f.write(forged_token)
            console.print(f"[bold blue]Forged token saved to {output}[/bold blue]")
            
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

if __name__ == '__main__':
    cli()