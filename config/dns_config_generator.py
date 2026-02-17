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
        tunnel_server_ip: Tunnel/attacker server IP (e.g., "10.5.5.5")
        public_resolver: Public DNS resolver (e.g., "8.8.8.8")
        template_dir: Directory containing template files
        output_dir: Base output directory
    """

    tunnel_domains_list = "; ".join(f'"{domain}"' for domain in tunneling_domains)
    tunnel_domain = tunneling_domains[0] if tunneling_domains else ""
    tunnel_domain_tld = tunnel_domain.split(".")[-1] if "." in tunnel_domain else ""

    # Zone blocks for RESOLVER → point to ROOT
    resolver_zone_blocks = []
    for domain in tunneling_domains:
        zone_block = f"""zone "{domain}" IN {{
    type forward;
    forwarders {{ {ROOT_SERVER_IP}; }};
}};
"""
        resolver_zone_blocks.append(zone_block)
    resolver_zone_blocks_str = "".join(resolver_zone_blocks)

    # Zone blocks for ROOT → point to TLD
    root_zone_blocks = []
    for domain in tunneling_domains:
        zone_block = f"""zone "{domain}" IN {{
    type forward;
    forwarders {{ {TLD_SERVER_IP}; }};
}};
"""
        root_zone_blocks.append(zone_block)
    root_zone_blocks_str = "".join(root_zone_blocks)

    # Zone blocks for TLD → point to TUNNEL SERVER (attacker)
    tld_zone_blocks = []
    for domain in tunneling_domains:
        zone_block = f"""zone "{domain}" IN {{
    type forward;
    forwarders {{ {tunnel_server_ip}; }};
}};
"""
        tld_zone_blocks.append(zone_block)
    tld_zone_blocks_str = "".join(tld_zone_blocks)

    # TLD Config
    generate_dns_config(
        template_file=f"{template_dir}/tld.conf",
        output_file=f"{output_dir}/tld-simulator/config/named.conf",
        replacements={
            "{TUNNEL_DOMAIN}": tunnel_domain,
            "{TUNNEL_SERVER_IP}": tunnel_server_ip,
            "{TUNNEL_DOMAINS}": tunnel_domains_list,
            "{ZONE_BLOCKS}": tld_zone_blocks_str,
        }
    )

    # Root Config
    generate_dns_config(
        template_file=f"{template_dir}/root.conf",
        output_file=f"{output_dir}/root-simulator/config/named.conf",
        replacements={
            "{TUNNEL-DOMAIN-TLD}": tunnel_domain_tld,
            "{TLD_SERVER_IP}": TLD_SERVER_IP,
            "{TUNNEL_DOMAINS}": tunnel_domains_list,
            "{ZONE_BLOCKS}": root_zone_blocks_str,
        }
    )

    # Resolver Config
    generate_dns_config(
        template_file=f"{template_dir}/resolver.conf",
        output_file=f"{output_dir}/resolver/config/named.conf",
        replacements={
            "{PUBLIC_IP_RESOLVER}": public_resolver,
            "{ROOT_SERVER_IP}": ROOT_SERVER_IP,
            "{TUNNEL_DOMAIN}": tunnel_domain,
            "{TUNNEL_DOMAINS}": tunnel_domains_list,
            "{ZONE_BLOCKS}": resolver_zone_blocks_str,
        }
    )

    logger.info("[+] All configs generated")
    logger.info(f"[+] {len(tunneling_domains)} tunnel domains configured")
    logger.info(f"[+] Tunneling domains: {tunneling_domains}")
