# VPN kill-switch (P2)

Sharza does not implement its own VPN client. It integrates with
[Vopono](https://github.com/jamesmcm/vopono), which creates a Linux
network namespace, runs OpenVPN/WireGuard inside it, and installs
nftables leak protection (including post-tunnel-down handling). The
daemon itself stays unprivileged; only the namespace-preparation unit
runs as root.

## How it works

1. `sharzad-vpn-netns.service` (root) creates `/run/netns/sharza-vpn`
   once at boot.
2. Vopono moves its tunnel's `tun` device into that namespace and
   installs nftables rules so traffic can only leave via the tunnel.
3. Worker roles (`bt`, `ed2k`, `g2`) are started with
   `NetworkNamespacePath=/run/netns/sharza-vpn` (see the drop-in in
   `packaging/systemd/sharzad@.service.d/vpn.conf`), so every peer
   socket they open is physically incapable of using the host's default
   route.
4. The supervisor stays in the root namespace, so the web UI and RPC
   remain reachable when the tunnel drops.

When the tunnel dies, the namespace has no route and traffic stops
entirely: no silent fallback, no leak window. This is a correctness
property, not a preference, which is why interface binding
(`SO_BINDTODEVICE`) was rejected.

## Setup

1. Install Vopono and configure a provider (OpenVPN or WireGuard).
2. Enable the namespace unit:
   ```
   sudo systemctl enable --now sharzad-vpn-netns.service
   ```
3. Run Vopono to create the tunnel into `/run/netns/sharza-vpn`:
   ```
   sudo vopono exec --provider <name> --server <srv> -- /bin/true
   ```
   (or the equivalent for your provider; Vopono creates the namespace
   name you give it, so pass `--namespace sharza-vpn`).
4. Install the worker drop-in and reload systemd:
   ```
   sudo mkdir -p /etc/systemd/system/sharzad@.service.d
   sudo cp packaging/systemd/sharzad@.service.d/vpn.conf \
       /etc/systemd/system/sharzad@.service.d/vpn.conf
   sudo systemctl daemon-reload
   ```
5. Restart the workers so they pick up the namespace:
   ```
   sudo systemctl restart sharzad@bt sharzad@ed2k sharzad@g2
   ```

## Verifying the kill-switch

With the tunnel up, confirm worker traffic egresses via the VPN
interface (`ip -n sharza-vpn addr`, `ip netns exec sharza-vpn curl
https://ifconfig.me`). With the tunnel killed mid-transfer, confirm no
packets leave the host interface (`tcpdump -i <host-iface>` stays
silent) and the web UI remains reachable. Network-namespace tests in
the tree skip loudly on hosts without `CAP_SYS_ADMIN`.

## Configuration

`vpn_netns_path` in `sharza.json` records the path the operator chose
(default empty, i.e. disabled). It is informational: the actual
placement happens through systemd's `NetworkNamespacePath=`, not
through the daemon.