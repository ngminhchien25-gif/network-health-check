"""Canned CLI output for `--demo` (mirrors real IOSv / IOSvL2 output).

Scenarios: R1 healthy | R2 packet loss + latency + down interface | SW1 err-disabled + half duplex | R3 unreachable.
"""

_PING_OK = (
    "Type escape sequence to abort.\n"
    "Sending 5, 100-byte ICMP Echos to {t}, timeout is 2 seconds:\n!!!!!\n"
    "Success rate is 100 percent (5/5), round-trip min/avg/max = 2/3/5 ms\n"
)

_R1_ROUTES = """Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       E1 - OSPF external type 1, E2 - OSPF external type 2
       * - candidate default, U - per-user static route

Gateway of last resort is not set

      1.0.0.0/32 is subnetted, 1 subnets
C        1.1.1.1 is directly connected, Loopback0
      2.0.0.0/32 is subnetted, 1 subnets
O        2.2.2.2 [110/2] via 10.0.12.2, 00:12:44, GigabitEthernet0/1
      10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks
C        10.0.12.0/30 is directly connected, GigabitEthernet0/1
L        10.0.12.1/32 is directly connected, GigabitEthernet0/1
      192.168.56.0/24 is variably subnetted, 2 subnets, 2 masks
C        192.168.56.0/24 is directly connected, GigabitEthernet0/0
L        192.168.56.11/32 is directly connected, GigabitEthernet0/0
"""

_R2_ROUTES = """Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area

Gateway of last resort is not set

      1.0.0.0/32 is subnetted, 1 subnets
O        1.1.1.1 [110/2] via 10.0.12.1, 00:03:02, GigabitEthernet0/1
      2.0.0.0/32 is subnetted, 1 subnets
C        2.2.2.2 is directly connected, Loopback0
      10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks
C        10.0.12.0/30 is directly connected, GigabitEthernet0/1
L        10.0.12.2/32 is directly connected, GigabitEthernet0/1
      192.168.56.0/24 is variably subnetted, 2 subnets, 2 masks
C        192.168.56.0/24 is directly connected, GigabitEthernet0/0
L        192.168.56.12/32 is directly connected, GigabitEthernet0/0
"""

_BRIEF_HDR = "Interface                  IP-Address      OK? Method Status                Protocol\n"

_R1_IF = _BRIEF_HDR + (
    "GigabitEthernet0/0         192.168.56.11   YES NVRAM  up                    up\n"
    "GigabitEthernet0/1         10.0.12.1       YES NVRAM  up                    up\n"
    "GigabitEthernet0/2         unassigned      YES NVRAM  administratively down down\n"
    "GigabitEthernet0/3         unassigned      YES NVRAM  administratively down down\n"
    "Loopback0                  1.1.1.1         YES NVRAM  up                    up\n"
)

_R2_IF = _BRIEF_HDR + (
    "GigabitEthernet0/0         192.168.56.12   YES NVRAM  up                    up\n"
    "GigabitEthernet0/1         10.0.12.2       YES NVRAM  up                    up\n"
    "GigabitEthernet0/2         unassigned      YES NVRAM  administratively down down\n"
    "GigabitEthernet0/3         unassigned      YES unset  down                  down\n"
    "Loopback0                  2.2.2.2         YES NVRAM  up                    up\n"
)

_SW1_IF = (
    "Port      Name               Status       Vlan       Duplex  Speed Type\n"
    "Gi0/0     UPLINK-TO-CLOUD    connected    1          a-full   auto unknown\n"
    "Gi0/1     TO-R1              connected    1          a-full   auto unknown\n"
    "Gi0/2     TO-R2              connected    1          half      10 unknown\n"
    "Gi0/3                        notconnect   1            auto   auto unknown\n"
    "Gi1/0                        notconnect   1            auto   auto unknown\n"
    "Gi1/1                        notconnect   1            auto   auto unknown\n"
    "Gi1/2     TEST-PORT          err-disabled 1            auto   auto unknown\n"
    "Gi1/3                        disabled     1            auto   auto unknown\n"
)

DEMO_OUTPUTS: dict[str, dict[str, str]] = {
    "R1": {
        "ping 2.2.2.2 repeat 5": _PING_OK.format(t="2.2.2.2"),
        "ping 10.0.12.2 repeat 5": _PING_OK.format(t="10.0.12.2"),
        "ping 192.168.56.13 repeat 5": _PING_OK.format(t="192.168.56.13"),
        "traceroute 2.2.2.2": (
            "Type escape sequence to abort.\nTracing the route to 2.2.2.2\n"
            "VRF info: (vrf in name/id, vrf out name/id)\n"
            "  1 2.2.2.2 5 msec 4 msec 3 msec\n"
        ),
        "show ip route": _R1_ROUTES,
        "show ip interface brief": _R1_IF,
    },
    "R2": {
        "ping 1.1.1.1 repeat 5": (
            "Type escape sequence to abort.\n"
            "Sending 5, 100-byte ICMP Echos to 1.1.1.1, timeout is 2 seconds:\n!.!.!\n"
            "Success rate is 60 percent (3/5), round-trip min/avg/max = 85/120/160 ms\n"
        ),
        "ping 10.0.12.1 repeat 5": _PING_OK.format(t="10.0.12.1"),
        "traceroute 1.1.1.1": (
            "Type escape sequence to abort.\nTracing the route to 1.1.1.1\n"
            "VRF info: (vrf in name/id, vrf out name/id)\n"
            "  1 1.1.1.1 90 msec 120 msec 140 msec\n"
        ),
        "show ip route": _R2_ROUTES,
        "show ip interface brief": _R2_IF,
    },
    "SW1": {
        "ping 192.168.56.11 repeat 5": _PING_OK.format(t="192.168.56.11"),
        "ping 192.168.56.12 repeat 5": _PING_OK.format(t="192.168.56.12"),
        "show interfaces status": _SW1_IF,
    },
}

# Devices that fail to connect in demo mode
DEMO_FAILURES = {"R3": "Timeout connecting to 192.168.56.14:22"}
