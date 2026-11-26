#!/usr/bin/env python3
"""DNS Config Generator for BIND9"""

from pathlib import Path
import base64
import logging
import os

logger = logging.getLogger('dns_detector')

# Static DNS server IPs
TLD_SERVER_IP = "10.10.10.10"
ROOT_SERVER_IP = "10.5.5.5"

# rndc control channel, used by main.py to flush cached tunnel answers between
# configurations. The key file lives next to named.conf in each server's
# bind-mounted /etc/bind; the channel only listens on the container's loopback.
RNDC_KEY_NAME = "tunframe-rndc"
RNDC_KEY_FILE = "rndc.key"
RNDC_CONTAINER_KEY_PATH = f"/etc/bind/{RNDC_KEY_FILE}"
BIND_SERVERS = ("resolver", "root-simulator", "tld-simulator")  # config dir == container name


def rndc_preamble() -> str:
    """named.conf lines that enable rndc on 127.0.0.1 with the generated key."""
    return (
        f'include "{RNDC_CONTAINER_KEY_PATH}";\n'
        f'controls {{ inet 127.0.0.1 port 953 allow {{ 127.0.0.1; }} keys {{ "{RNDC_KEY_NAME}"; }}; }};\n\n'
    )


def write_rndc_keys(output_dir: str) -> None:
    """Write one fresh rndc key into the config directory of every BIND server."""
    secret = base64.b64encode(os.urandom(32)).decode()
    key = f'key "{RNDC_KEY_NAME}" {{ algorithm hmac-sha256; secret "{secret}"; }};\n'
    for server in BIND_SERVERS:
        path = Path(output_dir) / server / "config" / RNDC_KEY_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(key)
        path.chmod(0o600)


def generate_dns_config(template_file: str,
                        output_file: str,
                        replacements: dict[str, str]) -> None:
    """
    Generate DNS config from template with replacements

    Args:
        template_file: Path to template file
        output_file: Path to output file
        replacements: Dict of {placeholder: value} to replace
    """
    template = Path(template_file).read_text()

    config = rndc_preamble() + template
    for placeholder, value in replacements.items():
        config = config.replace(placeholder, value)

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(config)

    logger.info(f"[+] Generated: {output_file}")


def generate_all_configs(tunneling_domains: list[str],
                         tunnel_server_ip: str,
                         public_resolver: str,
                         template_dir: str,
                         output_dir: str) -> None:
    """
    Generate all DNS configs from templates

    Args:
        tunneling_domains: List of tunnel domains, each an eTLD+1 (e.g., ["example.com"])
        tunnel_server_ip: Tunnel/attacker server IP (e.g., "192.168.3.3")
        public_resolver: Public DNS resolver (e.g., "8.8.8.8")
        template_dir: Directory containing template files
        output_dir: Base output directory
    """

    # --- validate-except block: only generated when domains are present ---
    if tunneling_domains:
        tunnel_domains_list = "; ".join(f'"{d}"' for d in tunneling_domains)
        validate_except_block = f"validate-except {{ {tunnel_domains_list}; }};"
    else:
        validate_except_block = ""
        logger.warning("[!] No tunneling domains provided — validate-except block will be omitted")

    # --- Zone blocks: RESOLVER → ROOT ---
    resolver_zone_blocks = "".join(
        f'zone "{domain}" IN {{\n'
        f'    type forward;\n'
        f'    forwarders {{ {ROOT_SERVER_IP}; }};\n'
        f'}};\n'
        for domain in tunneling_domains
    )

    # --- Zone blocks: ROOT → TLD ---
    root_zone_blocks = "".join(
        f'zone "{domain}" IN {{\n'
        f'    type forward;\n'
        f'    forwarders {{ {TLD_SERVER_IP}; }};\n'
        f'}};\n'
        for domain in tunneling_domains
    )

    # --- Zone blocks: TLD → TUNNEL SERVER (attacker) ---
    tld_zone_blocks = "".join(
        f'zone "{domain}" IN {{\n'
        f'    type forward;\n'
        f'    forwarders {{ {tunnel_server_ip}; }};\n'
        f'}};\n'
        for domain in tunneling_domains
    )

    write_rndc_keys(output_dir)

    # --- TLD Config ---
    generate_dns_config(
        template_file=f"{template_dir}/tld.conf",
        output_file=f"{output_dir}/tld-simulator/config/named.conf",
        replacements={
            "{ZONE_BLOCKS}": tld_zone_blocks,
            "{VALIDATE_EXCEPT_BLOCK}": validate_except_block,
        }
    )

    # --- Root Config ---
    generate_dns_config(
        template_file=f"{template_dir}/root.conf",
        output_file=f"{output_dir}/root-simulator/config/named.conf",
        replacements={
            "{ZONE_BLOCKS}": root_zone_blocks,
            "{VALIDATE_EXCEPT_BLOCK}": validate_except_block,
        }
    )

    # --- Resolver Config ---
    generate_dns_config(
        template_file=f"{template_dir}/resolver.conf",
        output_file=f"{output_dir}/resolver/config/named.conf",
        replacements={
            "{PUBLIC_IP_RESOLVER}": public_resolver,
            "{ZONE_BLOCKS}": resolver_zone_blocks,
            "{VALIDATE_EXCEPT_BLOCK}": validate_except_block,
        }
    )

    logger.info("[+] All configs generated")
    logger.info(f"[+] {len(tunneling_domains)} tunnel domain(s) configured")
    if tunneling_domains:
        logger.info(f"[+] Tunneling domains: {tunneling_domains}")
