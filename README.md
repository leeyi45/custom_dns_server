# private_dns

A DNS server written in python primarily using ```scapy```. This server is intended to replace your computer's main DNS server, giving you the ability to decide which DNS server to use for certain domains.

This server was created with VPNs in mind. Let's say your computer is configured to use primary DNS server located behind a VPN at `192.168.255.1`. You connect to that VPN using a domain name, say `myvpn.me`. When your computer tries to lookup `myvpn.me` at `192.168.255.1`, it cannot reach that IP address while your VPN is disconnected. To circumvent that, this server allows you to specify an alternate DNS server for `myvpn.me`. 
Now your computer can perform a DNS lookup for `myvpn.me`, while the rest of your DNS traffic is redirected through your VPN.

Alternatively, let's say that certain local domains are only accessible within the local network. You might want to resolve local domains using the local network's DNS server instead of your VPN server. Again, this server will provide you with the capability to redirect requests for the local domain to the local DNS server.

# Instructions to Run
After installing 'scapy' and 'pyyaml', simply run `python main.py` 

# Configuration
All configuration options for this server is provided in the ```config.yml``` file. The sections below explain each configuration option.

## Resolvers
The resolvers configuration section contains a series of entries describing which servers should be used for the corresponding domain

```yml
resolvers:
    - google.com: 8.8.8.8
    - facebook.com: [1.1.1.1, 2.2.2.2]
    
fallbacks: 192.168.255.1 # or you can provide multiple servers here too
```
The above configuration would lookup ```google.com``` sub-domains at ```8.8.8.8```
By specfiying two servers for ```facebook.com``` subdomains, the server will first query```1.1.1.1``` and then ```2.2.2.2``` if the former is unable to successfully fulfil the request

For domains with no configured resolver, the server will query servers specified by the ```fallbacks``` option. This option can be automatically configured using DHCP (see the next section)

```yml
- google.com: [8.8.8.8, fallback, 1.1.1.1]
```
Use ```fallback``` in the list of domains to specify that the server should use the fallback servers to query for that domain.

## DHCP Configuration
If a DHCP server is available on the network, you can configure the server to request DNS server information from it by sending a DHCPDISCOVER message.
To activate this functionality, set the `use-dhcp` option to be `true`.

```yml
dhcp-options:
  use-dhcp: true
  use-network-broadcast: true
  send-decline: true
  # local-iface: eth0 or "Ethernet"
  # local-addr: 192.168.10.5
  # dhcp-server: 192.168.10.1
```

### ```use-network-broadcast```
Set this to `true` to use the subnet's broadcast address when sending DHCPDISCOVER message instead of the universal broadcast address. For example, if the DHCP server is on the `192.168.10.0/24` network, setting this option to `true` will cause it to broadcast the DHCPDISCOVER message using `192.168.10.255` instead of `255.255.255.255`.
Turning this option will contain the server's DHCP packets to the local subnet, but may not work with networks that rely on DHCP relays

### `send-decline`
When a DHCP server receives a DHCPDISCOVER message, it will respond with a DHCPOFFER. Because the server isn't actually requesting for an IP address, this server can choose to reply with a DHCPDECLINE, informing the DHCP server that it is not requesting that IP address.

### `local-iface` and `local-addr`
`local-iface` informs this server that the DHCP server should be reached using the given network interface, while `local-addr` informs this server that the DHCP server can be reached using the network interface with that specified local IP address. If neither of these options are given, then the interface returned by `scapy`'s `conf.iface` variable is used

If both options are specified, then `local-iface` is ignored in favour of the value given by `local-addr`

### `dhcp-server` and `force-broadcast`
If this option is specified, this server will send DHCPDISCOVER messages straight to the IP address provided instead of sending a broadcast message. `force-broadcast` overrides this option, forcing this server to always use broadcast messages when sending DHCPDISCOVER.

## DNS Server Configuration
Configuration options pertaining to the DNS server
```yml
dns-server:
  ip: 127.0.0.1
```

### ```ip```
The IP address which the DNS server is supposed to bind to and listen for requests on.

## Full Sample ```config.yml```
```yml
fallbacks: 192.168.255.1

resolvers:
    - google.com: 8.8.8.8
    - facebook.com: 1.1.1.1

dhcp-options:
  use-dhcp: true
  use-network-broadcast: true
  send-decline: true

dns-server:
  ip: 127.0.0.1
```
