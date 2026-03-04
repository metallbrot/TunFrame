#!/usr/bin/env python3
"""DNS Config Generator for BIND9"""

from pathlib import Path
import logging

logger = logging.getLogger('dns_detector')

# Static DNS server IPs
TLD_SERVER_IP = "10.10.10.10"
ROOT_SERVER_IP = "10.5.5.5"


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

    config = template
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
        tunneling_domains: List of tunnel domains (e.g., ["tunnel.example.com"])
        tunnel_server_ip: Tunnel/attacker server IP (e.g., "192.168.3.3")
        public_resolver: Public DNS resolver (e.g., "8.8.8.8")
        template_dir: Directory containing template files
        output_dir: Base output directory
    """

    tunnel_domain = tunneling_domains[0] if tunneling_domains else ""
    tunnel_domain_tld = tunnel_domain.split(".")[-1] if "." in tunnel_domain else ""

    # --- validate-except block: only generated when domains are present ---
    if tunneling_domains:
        tunnel_domains_list = "; ".join(f'"{d}"' for d in tunneling_domains)
        validate_except_block = f"validate-except {{ {tunnel_domains_list}; }};"
    else:
        tunnel_domains_list = ""
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

    # --- TLD Config ---
    generate_dns_config(
        template_file=f"{template_dir}/tld.conf",
        output_file=f"{output_dir}/tld-simulator/config/named.conf",
        replacements={
            "{TUNNEL_DOMAIN}": tunnel_domain,
            "{TUNNEL_SERVER_IP}": tunnel_server_ip,
            "{TUNNEL_DOMAINS}": tunnel_domains_list,
            "{ZONE_BLOCKS}": tld_zone_blocks,
            "{VALIDATE_EXCEPT_BLOCK}": validate_except_block,
        }
    )

    # --- Root Config ---
    generate_dns_config(
        template_file=f"{template_dir}/root.conf",
        output_file=f"{output_dir}/root-simulator/config/named.conf",
        replacements={
            "{TUNNEL-DOMAIN-TLD}": tunnel_domain_tld,
            "{TLD_SERVER_IP}": TLD_SERVER_IP,
            "{TUNNEL_DOMAINS}": tunnel_domains_list,
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
            "{ROOT_SERVER_IP}": ROOT_SERVER_IP,
            "{TUNNEL_DOMAIN}": tunnel_domain,
            "{TUNNEL_DOMAINS}": tunnel_domains_list,
            "{ZONE_BLOCKS}": resolver_zone_blocks,
            "{VALIDATE_EXCEPT_BLOCK}": validate_except_block,
        }
    )

    logger.info("[+] All configs generated")
    logger.info(f"[+] {len(tunneling_domains)} tunnel domain(s) configured")
    if tunneling_domains:
        logger.info(f"[+] Tunneling domains: {tunneling_domains}")
