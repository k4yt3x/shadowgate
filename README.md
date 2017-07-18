# ShadowGate

Current Version: 0.1 alpha

#### What is ShadowGate?
ShadowGate is a protection software that works with iptables on Linux machines that host shadowsocks servers.  It is currently still a proof of concept. **Please respect the laws. The author of this software will not be reponsible for any bad consequences caused by unintended use of this software.**


#### Why do we need it?
The Great Firewall of China, or GFW for short, uses probing to test if the remote machine that a citizen is attempting to connect to is a VPN server.  Preventing unwanted IPs from probing can block the probes effectively outside of the server. This will confuse the firewall and prevent it from recognizing the shadowsocks / socks VPN host.


#### How does it work?
The shadowgate server hosts a port on the VPN server. When entering the right password, the iptables on VPN server will whitelist the IP address that entered the right password. This will allow the legit clients to connect.
