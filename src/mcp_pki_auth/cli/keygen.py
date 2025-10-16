#!/usr/bin/env python3
"""
Key generation CLI tool for MCP PKI Authentication System.

Generates ed25519 key pairs for MCP authentication.
"""

import sys
from pathlib import Path
from typing import Optional

import click

from ..key_manager import KeyManager, KeyPair
from ..exceptions import MCPAuthError


@click.command()
@click.option(
    '--output-dir', '-o',
    type=click.Path(exists=False, file_okay=False, dir_okay=True, path_type=Path),
    default=Path.cwd(),
    help='Output directory for key files (default: current directory)'
)
@click.option(
    '--name', '-n',
    default='mcp-key',
    help='Base name for key files (default: mcp-key)'
)
@click.option(
    '--private-key-path',
    type=click.Path(exists=False, dir_okay=False, path_type=Path),
    help='Specific path for private key file'
)
@click.option(
    '--public-key-path', 
    type=click.Path(exists=False, dir_okay=False, path_type=Path),
    help='Specific path for public key file'
)
@click.option(
    '--overwrite', '-f',
    is_flag=True,
    help='Overwrite existing key files'
)
@click.option(
    '--show-fingerprint',
    is_flag=True,
    default=True,
    help='Show key fingerprint after generation (default: enabled)'
)
@click.option(
    '--quiet', '-q',
    is_flag=True,
    help='Suppress output except errors'
)
def main(
    output_dir: Path,
    name: str,
    private_key_path: Optional[Path],
    public_key_path: Optional[Path], 
    overwrite: bool,
    show_fingerprint: bool,
    quiet: bool
) -> None:
    """Generate ed25519 key pair for MCP authentication."""
    
    try:
        # Determine key paths
        if private_key_path is None:
            private_key_path = output_dir / f"{name}.pem"
        
        if public_key_path is None:
            public_key_path = output_dir / f"{name}.pub"
        
        # Check for existing files
        if not overwrite:
            if private_key_path.exists():
                click.echo(f"Error: Private key file already exists: {private_key_path}", err=True)
                click.echo("Use --overwrite to replace existing files", err=True)
                sys.exit(1)
            
            if public_key_path.exists():
                click.echo(f"Error: Public key file already exists: {public_key_path}", err=True)
                click.echo("Use --overwrite to replace existing files", err=True)
                sys.exit(1)
        
        # Generate key pair
        if not quiet:
            click.echo("Generating ed25519 key pair...")
        
        keypair = KeyManager.generate_keypair()
        
        # Save keys
        KeyManager.save_keypair(
            keypair=keypair,
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            overwrite=overwrite
        )
        
        if not quiet:
            click.echo(f"Private key saved to: {private_key_path}")
            click.echo(f"Public key saved to: {public_key_path}")
            
            if show_fingerprint:
                fingerprint = keypair.fingerprint
                click.echo(f"Key fingerprint: {fingerprint}")
                
                # Format fingerprint for easier reading
                formatted_fp = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
                click.echo(f"Formatted fingerprint: {formatted_fp}")
        
        # Validate generated keys
        if not KeyManager.validate_keypair(keypair):
            click.echo("Warning: Generated key pair failed validation", err=True)
            sys.exit(1)
            
        if not quiet:
            click.echo("Key generation completed successfully!")
            
    except MCPAuthError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@click.command()
@click.argument(
    'key_file',
    type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
def show_fingerprint(key_file: Path) -> None:
    """Show fingerprint of a key file."""
    
    try:
        # Try to load as private key first
        try:
            keypair = KeyManager.load_keypair(key_file)
            public_key = keypair.public_key
            key_type = "private"
        except:
            # Try as public key
            try:
                public_key = KeyManager.load_public_key(key_file)
                key_type = "public"
            except:
                click.echo(f"Error: Unable to load key from {key_file}", err=True)
                click.echo("File must be a valid MCP private or public key", err=True)
                sys.exit(1)
        
        fingerprint = KeyManager.get_fingerprint(public_key)
        formatted_fp = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        
        click.echo(f"Key file: {key_file}")
        click.echo(f"Key type: {key_type}")
        click.echo(f"Fingerprint: {fingerprint}")
        click.echo(f"Formatted: {formatted_fp}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@click.command()
@click.argument(
    'private_key_file',
    type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    '--output', '-o',
    type=click.Path(exists=False, dir_okay=False, path_type=Path),
    help='Output path for public key (default: private_key_file.pub)'
)
@click.option(
    '--overwrite', '-f',
    is_flag=True,
    help='Overwrite existing public key file'
)
def extract_public_key(
    private_key_file: Path,
    output: Optional[Path],
    overwrite: bool
) -> None:
    """Extract public key from private key file."""
    
    try:
        # Load private key
        keypair = KeyManager.load_keypair(private_key_file)
        
        # Determine output path
        if output is None:
            output = private_key_file.with_suffix('.pub')
        
        # Check for existing file
        if not overwrite and output.exists():
            click.echo(f"Error: Output file already exists: {output}", err=True)
            click.echo("Use --overwrite to replace existing file", err=True)
            sys.exit(1)
        
        # Save public key
        public_pem = KeyManager._public_key_to_mcp_pem(keypair.public_key)
        output.write_bytes(public_pem)
        
        click.echo(f"Public key extracted to: {output}")
        click.echo(f"Key fingerprint: {keypair.fingerprint}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# Create a CLI group for key management
@click.group()
def keygen_cli():
    """MCP PKI key generation and management tools."""
    pass


keygen_cli.add_command(main, name='generate')
keygen_cli.add_command(show_fingerprint, name='fingerprint') 
keygen_cli.add_command(extract_public_key, name='extract-public')


if __name__ == '__main__':
    main()