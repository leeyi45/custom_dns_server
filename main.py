from ipaddress import AddressValueError, IPv4Address
import logging
from operator import attrgetter, itemgetter
from typing import *
import yaml

import dhcp
from dns_handler import DNSServer
from yaml_helper import YamlHelper


def ipaddrlist_tostr(addresses: List[IPv4Address], joiner: str = ', ') -> str:
    return joiner.join(map(attrgetter('exploded'), addresses))


def get_dhcp_info(yaml_conf: YamlHelper) -> Dict[str, Any]:
    """
    Parse the YAML configuration object to determine which DNS servers to use
    as fallback
    """

    if yaml_conf.get_bool("dhcp-options/use-dhcp"):
        return dhcp.get_dhcp_options(IPv4Address("255.255.255.255"), "Ethernet")
    else:
        return {
            'local_dns': [],
            'local_domain': None,
            'local_dhcp': None
        }


def get_resolvers(yaml_conf: YamlHelper) -> Dict[bytes, List[IPv4Address]]:
    """
    Get the configuration for the resolvers for specific domains
    """
    # parse resolvers
    lookup_servers = {}

    if not yaml_conf:
        return lookup_servers

    for entry in yaml_conf.get_list('resolvers'):
        domain, server_list = list(entry.items())[0]

        if not isinstance(server_list, list):
            server_list = [server_list]

        if not domain.endswith('.'):
            domain += "."

        servers = lookup_servers.setdefault(domain.encode(), list())

        for server in server_list:
            try:
                # if specified, use the fallback server
                if server.casefold() == "fallback".casefold():
                    server = server.lower()
                else:
                    # otherwise just add the server to the list
                    server = IPv4Address(server)
                    
                servers.append(server)
            except AddressValueError:
                logging.error(f"While getting resolvers, invalid IP address: {server}")
                continue

    # remove domains with no valid lookup servers
    # empty lists are considered False, so we can just use itemgetter
    return dict(filter(itemgetter(1), lookup_servers.items()))


def get_dns_server(yaml_conf: YamlHelper) -> DNSServer:
    """
    Configure and return a DNSServer instance to use
    """
    lookup_servers = get_resolvers(yaml_conf)

    # Add the local domain on to the list of resolvers if there is one configured
    dhcp_info = get_dhcp_info(yaml_conf)
    if dhcp_info['local_domain']:
        lookup_servers[dhcp_info['local_domain'] + b'.'] = dhcp_info['local_dns']
    logging.info("Lookup table configured as such:\n" + '\n'.join(map(lambda each: f"\t- {each[0].decode()}: {ipaddrlist_tostr(each[1])}", lookup_servers.items())))

    # Use fallback servers if provided in config.yml, otherwise use dhcp_info
    fallback_servers = list(map(IPv4Address, yaml_conf.get_list("fallbacks") or dhcp_info['local_dns']))
    logging.info(f"Fallback servers configured as such: [{ipaddrlist_tostr(fallback_servers)}]")

    try:
        server_address = yaml_conf.get_as("dns-server/ip", IPv4Address)
    except AddressValueError:
        logging.error("Invalid IP address specified for the DNS server!")
        raise
    return DNSServer(server_address, fallback_servers=fallback_servers, lookup_servers=lookup_servers)


def main():
    with open("config.yml") as file:
        yaml_conf = YamlHelper(yaml.safe_load(file))

    dns_server = get_dns_server(yaml_conf)
    logging.info("Starting DNS server...")
    dns_server.serve_forever()
    logging.info("DNS Server stopped.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s %(levelname)s]: %(message)s", datefmt="%H:%M")
    main()
