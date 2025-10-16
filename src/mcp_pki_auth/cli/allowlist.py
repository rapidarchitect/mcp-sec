#!/usr/bin/env python3
"""
Allowlist management CLI tool for MCP PKI Authentication System.

Manages access control lists with key metadata and fingerprint-based operations.
"""

import sys
import json
from pathlib import Path
from typing import Optional, List, Dict, Any

import click
from tabulate import tabulate

from ..acl_manager import ACLManager, KeyMetadata
from ..key_manager import KeyManager
from ..exceptions import MCPAuthError


@click.group()
@click.option(
    '--allowlist-path', '-p',
    type=click.Path(path_type=Path),
    default=Path("allowlist.json"),
    help='Path to allowlist JSON file'
)
@click.pass_context
def main(ctx: click.Context, allowlist_path: Path) -> None:
    """Manage MCP authentication allowlists."""
    ctx.ensure_object(dict)
    ctx.obj['allowlist_path'] = allowlist_path


@main.command()
@click.argument(
    'key_file',
    type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    '--description', '-d',
    required=True,
    help='Description for the key'
)
@click.option(
    '--added-by',
    help='Who is adding this key'
)
@click.option(
    '--metadata', '-m',
    help='JSON metadata to associate with the key'
)
@click.option(
    '--update',
    is_flag=True,
    help='Update existing key if it already exists'
)
@click.pass_context
def add(
    ctx: click.Context,
    key_file: Path,
    description: str,
    added_by: Optional[str],
    metadata: Optional[str],
    update: bool
) -> None:
    """Add a public key to the allowlist."""
    
    try:
        allowlist_path = ctx.obj['allowlist_path']
        
        # Load public key
        try:
            public_key = KeyManager.load_public_key(key_file)
        except:
            # Try loading as private key and extracting public key
            try:
                keypair = KeyManager.load_keypair(key_file)
                public_key = keypair.public_key
            except Exception as e:
                click.echo(f"Error: Unable to load key from {key_file}: {e}", err=True)
                sys.exit(1)
        
        # Parse metadata
        metadata_dict = None
        if metadata:
            try:
                metadata_dict = json.loads(metadata)
            except json.JSONDecodeError as e:
                click.echo(f"Error: Invalid JSON metadata: {e}", err=True)
                sys.exit(1)
        
        # Initialize ACL manager
        acl_manager = ACLManager(allowlist_path)
        
        # Add key
        fingerprint = acl_manager.add_key(
            public_key=public_key,
            description=description,
            added_by=added_by,
            metadata=metadata_dict,
            allow_update=update
        )
        
        click.echo(f"Successfully added key to allowlist")
        click.echo(f"Fingerprint: {fingerprint}")
        click.echo(f"Description: {description}")
        if added_by:
            click.echo(f"Added by: {added_by}")
        
    except MCPAuthError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('fingerprint')
@click.option(
    '--confirm', '-y',
    is_flag=True,
    help='Skip confirmation prompt'
)
@click.pass_context
def remove(ctx: click.Context, fingerprint: str, confirm: bool) -> None:
    """Remove a key from the allowlist by fingerprint."""
    
    try:
        allowlist_path = ctx.obj['allowlist_path']
        acl_manager = ACLManager(allowlist_path)
        
        # Get key info before removal
        key_metadata = acl_manager.get_key_metadata(fingerprint)
        if not key_metadata:
            click.echo(f"Error: Key with fingerprint {fingerprint} not found", err=True)
            sys.exit(1)
        
        # Confirmation
        if not confirm:
            click.echo(f"Key to remove:")
            click.echo(f"  Fingerprint: {fingerprint}")
            click.echo(f"  Description: {key_metadata.description}")
            click.echo(f"  Added: {key_metadata.added_at.isoformat()}")
            
            if not click.confirm("Are you sure you want to remove this key?"):
                click.echo("Cancelled.")
                return
        
        # Remove key
        if acl_manager.remove_key(fingerprint):
            click.echo(f"Successfully removed key: {key_metadata.description}")
        else:
            click.echo(f"Error: Key not found or already removed", err=True)
            sys.exit(1)
        
    except MCPAuthError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option(
    '--format', '-f',
    type=click.Choice(['table', 'json', 'csv']),
    default='table',
    help='Output format'
)
@click.option(
    '--search', '-s',
    help='Search in descriptions and metadata'
)
@click.option(
    '--show-keys',
    is_flag=True,
    help='Include public key data in output'
)
@click.pass_context
def list(
    ctx: click.Context,
    format: str,
    search: Optional[str],
    show_keys: bool
) -> None:
    """List all keys in the allowlist."""
    
    try:
        allowlist_path = ctx.obj['allowlist_path']
        
        if not allowlist_path.exists():
            click.echo("No allowlist found. Use 'add' command to create one.")
            return
        
        acl_manager = ACLManager(allowlist_path)
        keys = acl_manager.list_keys()
        
        # Apply search filter
        if search:
            search_lower = search.lower()
            filtered_keys = []
            for key in keys:
                if (search_lower in key.description.lower() or
                    (key.added_by and search_lower in key.added_by.lower()) or
                    (key.metadata and search_lower in json.dumps(key.metadata).lower())):
                    filtered_keys.append(key)
            keys = filtered_keys
        
        if not keys:
            click.echo("No keys found.")
            return
        
        if format == 'json':
            # JSON output
            output = []
            for key in keys:
                key_dict = key.to_dict()
                if not show_keys:
                    key_dict.pop('public_key', None)
                output.append(key_dict)
            
            click.echo(json.dumps(output, indent=2))
        
        elif format == 'csv':
            # CSV output
            import csv
            import io
            
            output = io.StringIO()
            fieldnames = ['fingerprint', 'description', 'added_at', 'added_by']
            if show_keys:
                fieldnames.append('public_key')
            
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for key in keys:
                row = {
                    'fingerprint': key.fingerprint,
                    'description': key.description,
                    'added_at': key.added_at.isoformat(),
                    'added_by': key.added_by or ''
                }
                if show_keys:
                    import base64
                    row['public_key'] = base64.b64encode(key.public_key_bytes).decode('ascii')
                
                writer.writerow(row)
            
            click.echo(output.getvalue().strip())
        
        else:
            # Table output
            headers = ['Fingerprint', 'Description', 'Added', 'Added By']
            rows = []
            
            for key in keys:
                fingerprint = key.fingerprint[:16] + '...' if len(key.fingerprint) > 20 else key.fingerprint
                added_at = key.added_at.strftime('%Y-%m-%d %H:%M')
                added_by = key.added_by or '-'
                
                rows.append([fingerprint, key.description, added_at, added_by])
            
            click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
            click.echo(f"\nTotal keys: {len(keys)}")
        
    except MCPAuthError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('fingerprint')
@click.option(
    '--format', '-f',
    type=click.Choice(['table', 'json']),
    default='table',
    help='Output format'
)
@click.pass_context
def show(ctx: click.Context, fingerprint: str, format: str) -> None:
    """Show detailed information about a specific key."""
    
    try:
        allowlist_path = ctx.obj['allowlist_path']
        acl_manager = ACLManager(allowlist_path)
        
        key_metadata = acl_manager.get_key_metadata(fingerprint)
        if not key_metadata:
            click.echo(f"Error: Key with fingerprint {fingerprint} not found", err=True)
            sys.exit(1)
        
        if format == 'json':
            click.echo(json.dumps(key_metadata.to_dict(), indent=2))
        else:
            # Table format
            click.echo(f"Key Details:")
            click.echo(f"  Fingerprint: {key_metadata.fingerprint}")
            click.echo(f"  Description: {key_metadata.description}")
            click.echo(f"  Added: {key_metadata.added_at.isoformat()}")
            click.echo(f"  Added by: {key_metadata.added_by or 'Unknown'}")
            
            if key_metadata.metadata:
                click.echo(f"  Metadata:")
                for key, value in key_metadata.metadata.items():
                    click.echo(f"    {key}: {value}")
            
            # Format fingerprint for easier reading
            formatted_fp = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
            click.echo(f"  Formatted fingerprint: {formatted_fp}")
        
    except MCPAuthError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument(
    'export_dir',
    type=click.Path(file_okay=False, path_type=Path)
)
@click.option(
    '--create-dir',
    is_flag=True,
    help='Create export directory if it does not exist'
)
@click.pass_context
def export(ctx: click.Context, export_dir: Path, create_dir: bool) -> None:
    """Export all public keys to PEM files."""
    
    try:
        allowlist_path = ctx.obj['allowlist_path']
        
        if not allowlist_path.exists():
            click.echo("Error: No allowlist found", err=True)
            sys.exit(1)
        
        if not export_dir.exists():
            if create_dir:
                export_dir.mkdir(parents=True, exist_ok=True)
            else:
                click.echo(f"Error: Export directory {export_dir} does not exist", err=True)
                click.echo("Use --create-dir to create it", err=True)
                sys.exit(1)
        
        acl_manager = ACLManager(allowlist_path)
        acl_manager.export_public_keys(export_dir)
        
        keys = acl_manager.list_keys()
        click.echo(f"Successfully exported {len(keys)} public keys to {export_dir}")
        
    except MCPAuthError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument(
    'import_dir',
    type=click.Path(exists=True, file_okay=False, path_type=Path)
)
@click.option(
    '--description',
    default="Imported key",
    help='Default description for imported keys'
)
@click.option(
    '--added-by',
    help='Who is importing the keys'
)
@click.pass_context
def import_keys(
    ctx: click.Context,
    import_dir: Path,
    description: str,
    added_by: Optional[str]
) -> None:
    """Import public keys from PEM files in a directory."""
    
    try:
        allowlist_path = ctx.obj['allowlist_path']
        acl_manager = ACLManager(allowlist_path)
        
        imported_count = acl_manager.import_public_keys(
            input_path=import_dir,
            default_description=description,
            added_by=added_by
        )
        
        click.echo(f"Successfully imported {imported_count} keys from {import_dir}")
        
    except MCPAuthError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.pass_context
def stats(ctx: click.Context) -> None:
    """Show allowlist statistics."""
    
    try:
        allowlist_path = ctx.obj['allowlist_path']
        
        if not allowlist_path.exists():
            click.echo("No allowlist found.")
            return
        
        acl_manager = ACLManager(allowlist_path)
        statistics = acl_manager.get_statistics()
        
        click.echo("Allowlist Statistics:")
        click.echo(f"  Total keys: {statistics['total_keys']}")
        click.echo(f"  Default policy: {statistics['default_policy']}")
        click.echo(f"  File path: {statistics['allowlist_path']}")
        click.echo(f"  Last updated: {statistics['last_updated']}")
        
    except MCPAuthError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()