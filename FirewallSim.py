import random
import time
from enum import Enum
from typing import Dict, List, Optional, Tuple

class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    FTP = "FTP"
    SSH = "SSH"
    TELNET = "TELNET"
    ANY = "ANY"  

class PacketDirection(Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"

class FirewallRule:
    def __init__(self, 
                 name: str,
                 protocol: Protocol,
                 source_ip: str,
                 source_port: Optional[int],
                 destination_ip: str,
                 destination_port: Optional[int],
                 direction: PacketDirection,
                 action: str):
        self.name = name
        self.protocol = protocol
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.direction = direction
        self.action = action  
    
    def __str__(self):
        return (f"Rule '{self.name}': {self.protocol.value} {self.direction.value} "
                f"from {self.source_ip}:{self.source_port} to {self.destination_ip}:{self.destination_port} "
                f"-> {self.action}")

class Packet:
    def __init__(self,
                 protocol: Protocol,
                 source_ip: str,
                 source_port: int,
                 destination_ip: str,
                 destination_port: int,
                 direction: PacketDirection,
                 payload: str = "",
                 packet_id: Optional[int] = None):
        self.protocol = protocol
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.direction = direction
        self.payload = payload
        self.packet_id = packet_id or random.randint(1000, 9999)
        self.timestamp = time.time()
    
    def __str__(self):
        return (f"Packet #{self.packet_id}: {self.protocol.value} {self.direction.value} "
                f"from {self.source_ip}:{self.source_port} to {self.destination_ip}:{self.destination_port}")

class Firewall:
    def __init__(self, name: str = "Default Firewall"):
        self.name = name
        self.rules: List[FirewallRule] = []
        self.log: List[Dict] = []
        self.packet_counter = 0
        self.allowed_packets = 0
        self.blocked_packets = 0
        self.suspicious_patterns = [
            "DROP TABLE",
            "UNION SELECT",
            "<script>",
            "cmd.exe",
            "password=",
            "/etc/passwd",
            "bin/sh",
            "eval(",
            "r00t"
        ]
    
    def add_rule(self, rule: FirewallRule):
        """Add a new rule to the firewall."""
        self.rules.append(rule)
        print(f"Rule added: {rule}")
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule by name."""
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                removed_rule = self.rules.pop(i)
                print(f"Rule removed: {removed_rule}")
                return True
        print(f"Rule '{rule_name}' not found")
        return False
    
    def _is_ip_match(self, rule_ip: str, packet_ip: str) -> bool:
        """Check if the IP matches the rule (supports wildcards)."""
        if rule_ip == "*" or rule_ip == "any":
            return True
        if rule_ip == packet_ip:
            return True
        
        if "/" in rule_ip:
            base_ip, subnet = rule_ip.split("/")
            base_parts = base_ip.split(".")
            packet_parts = packet_ip.split(".")
            matching_octets = int(int(subnet) / 8)
            for i in range(matching_octets):
                if base_parts[i] != packet_parts[i]:
                    return False
            return True
        return False
    
    def _is_port_match(self, rule_port: Optional[int], packet_port: int) -> bool:
        """Check if the port matches the rule."""
        if rule_port is None:
            return True
        return rule_port == packet_port
    
    def inspect_payload(self, payload: str) -> Tuple[bool, Optional[str]]:
        """Inspect packet payload for suspicious patterns."""
        for pattern in self.suspicious_patterns:
            if pattern.lower() in payload.lower():
                return False, f"Suspicious pattern detected: '{pattern}'"
        return True, None
    
    def process_packet(self, packet: Packet) -> bool:
        """Process a packet and determine if it should be allowed or blocked."""
        self.packet_counter += 1
        
        
        if packet.payload:
            is_safe, reason = self.inspect_payload(packet.payload)
            if not is_safe:
                self._log_packet(packet, "BLOCK", reason)
                self.blocked_packets += 1
                return False
        
        
        for rule in self.rules:
            
            if (rule.protocol == packet.protocol or rule.protocol == Protocol.ANY) and \
               rule.direction == packet.direction and \
               self._is_ip_match(rule.source_ip, packet.source_ip) and \
               self._is_port_match(rule.source_port, packet.source_port) and \
               self._is_ip_match(rule.destination_ip, packet.destination_ip) and \
               self._is_port_match(rule.destination_port, packet.destination_port):
                
                
                if rule.action == "ALLOW":
                    self._log_packet(packet, "ALLOW", f"Matched rule: {rule.name}")
                    self.allowed_packets += 1
                    return True
                else:  
                    self._log_packet(packet, "BLOCK", f"Matched rule: {rule.name}")
                    self.blocked_packets += 1
                    return False
        
        
        self._log_packet(packet, "BLOCK", "No matching rule (default policy)")
        self.blocked_packets += 1
        return False
    
    def _log_packet(self, packet: Packet, action: str, reason: str):
        """Log packet processing information."""
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.timestamp)),
            "packet_id": packet.packet_id,
            "protocol": packet.protocol.value,
            "source": f"{packet.source_ip}:{packet.source_port}",
            "destination": f"{packet.destination_ip}:{packet.destination_port}",
            "direction": packet.direction.value,
            "action": action,
            "reason": reason
        }
        self.log.append(log_entry)
    
    def get_statistics(self) -> Dict:
        """Get firewall statistics."""
        return {
            "name": self.name,
            "total_rules": len(self.rules),
            "total_packets_processed": self.packet_counter,
            "packets_allowed": self.allowed_packets,
            "packets_blocked": self.blocked_packets,
            "block_rate": self.blocked_packets / self.packet_counter if self.packet_counter > 0 else 0
        }
    
    def display_log(self, count: int = 10):
        """Display the most recent log entries."""
        print(f"\n--- Last {min(count, len(self.log))} Log Entries ---")
        for entry in self.log[-count:]:
            print(f"{entry['timestamp']} | {entry['action']} | {entry['protocol']} {entry['direction']} | "
                  f"{entry['source']} -> {entry['destination']} | {entry['reason']}")


def simulation():
    
    fw = Firewall("Network Edge Firewall")
    
    
    fw.add_rule(FirewallRule("Allow HTTP", Protocol.HTTP, "*", None, "192.168.1.10", 80, 
                              PacketDirection.INBOUND, "ALLOW"))
    fw.add_rule(FirewallRule("Allow HTTPS", Protocol.HTTPS, "*", None, "192.168.1.10", 443, 
                              PacketDirection.INBOUND, "ALLOW"))
    fw.add_rule(FirewallRule("Block Telnet", Protocol.TELNET, "*", None, "192.168.1.*", None, 
                              PacketDirection.INBOUND, "BLOCK"))
    fw.add_rule(FirewallRule("Allow SSH from Admin", Protocol.SSH, "10.0.0.5", None, "192.168.1.10", 22, 
                              PacketDirection.INBOUND, "ALLOW"))
    fw.add_rule(FirewallRule("Allow Outbound", Protocol.TCP, "192.168.1.*", None, "*", None, 
                              PacketDirection.OUTBOUND, "ALLOW"))
    
    
    packets = [
        Packet(Protocol.HTTP, "203.0.113.5", 32105, "192.168.1.10", 80, PacketDirection.INBOUND),
        Packet(Protocol.HTTPS, "198.51.100.2", 49876, "192.168.1.10", 443, PacketDirection.INBOUND),
        Packet(Protocol.TELNET, "198.51.100.2", 54321, "192.168.1.10", 23, PacketDirection.INBOUND),
        Packet(Protocol.SSH, "10.0.0.5", 55555, "192.168.1.10", 22, PacketDirection.INBOUND),
        Packet(Protocol.SSH, "203.0.113.10", 55555, "192.168.1.10", 22, PacketDirection.INBOUND),
        Packet(Protocol.TCP, "192.168.1.10", 49999, "203.0.113.5", 80, PacketDirection.OUTBOUND),
        
        Packet(Protocol.HTTP, "203.0.113.100", 32105, "192.168.1.10", 80, PacketDirection.INBOUND, 
               payload="GET /login.php?username=admin&password=123456 HTTP/1.1"),
        Packet(Protocol.HTTP, "203.0.113.101", 32107, "192.168.1.10", 80, PacketDirection.INBOUND, 
               payload="GET /search.php?q=UNION SELECT username,password FROM users HTTP/1.1")
    ]
    
    print("\n--- Processing Packets ---")
    for packet in packets:
        result = "ALLOWED" if fw.process_packet(packet) else "BLOCKED"
        print(f"{packet} -> {result}")
    
    
    fw.display_log()
    
    print("\n--- Firewall Statistics ---")
    stats = fw.get_statistics()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"{key}: {value:.2%}")
        else:
            print(f"{key}: {value}")

if __name__ == "__main__":
    simulation()