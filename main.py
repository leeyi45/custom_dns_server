import dns_handler
from ipaddress import IPv4Address
import logging
from operator import attrgetter
from typing import *
import yaml

import dhcp as dhcp
from yaml_helper import YamlHelper


def get_fallbacks(yaml_conf: YamlHelper) -> List[IPv4Address]:
    """
    Parse the YAML configuration object to determine which DNS servers to use
    as fallback
    """
    fallback_servers = yaml_conf.get_list("fallbacks")

    if not fallback_servers:
        if not yaml_conf.get_bool("dhcp-options/use-dhcp"):
            return []
        
        return dhcp.get_dhcp_options('addr????')[6]
    else:
        return list(map(IPv4Address, fallback_servers))


def main():
    with open("config.yml") as file:
        yaml_conf = YamlHelper(yaml.safe_load(file))

    fallbacks = get_fallbacks(yaml_conf)
    logging.info(f"Obtained fallback servers: [{', '.join(map(attrgetter('exploded'), fallbacks))}]")

    dns_server = dns_handler.get_dns_server(yaml_conf, fallbacks)
    logging.info("Starting DNS server...")
    dns_server.serve_forever()
    logging.info("DNS Server stopped.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s %(levelname)s]: %(message)s", datefmt="%H:%M")
    main()
