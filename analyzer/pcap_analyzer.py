"""
PCAP and Wireshark packet analyzer for NetSentry
"""

import csv
from collections import Counter


class PcapAnalyzer:
    """Analyze PCAP files and Wireshark exports"""

    def __init__(self, filepath):
        self.filepath = filepath
        self.packets = []
        self.data = None

    def analyze(self):
        """Auto-detect and analyze packet file"""
        try:
            # Try CSV first (Wireshark export)
            if self.filepath.lower().endswith(".csv"):
                return self.analyze_csv()
            else:
                # Try generic parsing
                return self.analyze_generic()

        except Exception as e:
            print(f"Analysis error: {e}")
            return None

    def analyze_csv(self):
        """Analyze Wireshark CSV export"""
        try:
            packets = []

            with open(
                self.filepath,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                # Try to detect delimiter
                sample = f.read(1024)
                f.seek(0)

                if "," in sample:
                    delimiter = ","
                elif "\t" in sample:
                    delimiter = "\t"
                else:
                    delimiter = ","

                reader = csv.DictReader(
                    f,
                    delimiter=delimiter
                )

                if reader.fieldnames is None:
                    return None

                # Normalize field names
                reader.fieldnames = [
                    field.strip() if field else ""
                    for field in reader.fieldnames
                ]

                for row in reader:

                    if not any(row.values()):
                        continue

                    packet = self.parse_csv_row(row)

                    if packet:
                        packets.append(packet)

            return self.calculate_statistics(packets)

        except Exception as e:
            print(f"CSV parsing error: {e}")
            return None

    def parse_csv_row(self, row):
        """Parse a single CSV row"""
        try:
            packet = {}

            # Extract fields using case-insensitive matching
            def get_field(row_data, possible_names):
                for name in possible_names:

                    for key in row_data:

                        if (
                            key
                            and key.lower().strip()
                            == name.lower().strip()
                        ):
                            value = row_data[key]

                            if value is not None:
                                value = str(value).strip()

                            return value if value else None

                return None

            # Extract packet fields
            src_ip = get_field(
                row,
                [
                    "Source",
                    "Src IP",
                    "Source IP",
                    "ip.src"
                ]
            )

            dst_ip = get_field(
                row,
                [
                    "Destination",
                    "Dst IP",
                    "Dest IP",
                    "ip.dst",
                    "Dest"
                ]
            )

            src_port = get_field(
                row,
                [
                    "Source Port",
                    "Src Port",
                    "tcp.srcport",
                    "udp.srcport"
                ]
            )

            dst_port = get_field(
                row,
                [
                    "Dest Port",
                    "Destination Port",
                    "tcp.dstport",
                    "udp.dstport"
                ]
            )

            protocol = get_field(
                row,
                [
                    "Protocol",
                    "protocol",
                    "_ws.col.protocol"
                ]
            )

            flags = get_field(
                row,
                [
                    "TCP Flags",
                    "tcp.flags",
                    "Flags",
                    "Info"
                ]
            )

            timestamp = get_field(
                row,
                [
                    "Time",
                    "Timestamp",
                    "Time (s)",
                    "frame.time_relative"
                ]
            )

            info = get_field(
                row,
                [
                    "Info",
                    "Description"
                ]
            )

            # Default protocol for port-based traffic
            if not protocol and src_port:
                protocol = "TCP"

            packet["src_ip"] = src_ip
            packet["dst_ip"] = dst_ip
            packet["src_port"] = src_port
            packet["dst_port"] = dst_port
            packet["protocol"] = protocol or "TCP"
            packet["flags"] = flags or ""
            packet["timestamp"] = timestamp
            packet["info"] = info or ""

            # Detect TCP SYN
            packet["is_syn"] = self.is_syn_packet(flags)

            # Validate required fields
            if packet["src_ip"] and packet["dst_ip"]:
                return packet

            return None

        except Exception:
            return None

    @staticmethod
    def is_syn_packet(flags):
        """
        Determine whether TCP flags represent a SYN-only packet.

        Supports:
        - Wireshark textual flags: SYN
        - SYN, SYN-ACK, etc.
        - Numeric Wireshark flags: 0x0002
        """

        if not flags:
            return False

        flags_str = str(flags).strip()
        flags_lower = flags_str.lower()

        # ---------------------------------------------------------
        # Case 1: Wireshark textual representation
        # Example:
        # SYN
        # SYN, ACK
        # ---------------------------------------------------------
        if "syn" in flags_lower:

            # SYN-ACK is not an initial SYN probe
            if "ack" in flags_lower:
                return False

            return True

        # ---------------------------------------------------------
        # Case 2: Numeric TCP flags
        #
        # TCP flag values:
        # FIN = 0x0001
        # SYN = 0x0002
        # RST = 0x0004
        # PSH = 0x0008
        # ACK = 0x0010
        #
        # Your Wireshark CSV contains:
        # 0x0002
        # ---------------------------------------------------------
        if flags_lower.startswith("0x"):

            try:
                flag_value = int(flags_lower, 16)

                syn_flag = 0x0002
                ack_flag = 0x0010

                syn_set = bool(
                    flag_value & syn_flag
                )

                ack_set = bool(
                    flag_value & ack_flag
                )

                return syn_set and not ack_set

            except ValueError:
                return False

        # ---------------------------------------------------------
        # Case 3: Numeric flag without 0x prefix
        # ---------------------------------------------------------
        if flags_lower.isdigit():

            try:
                flag_value = int(flags_lower)

                syn_flag = 0x0002
                ack_flag = 0x0010

                syn_set = bool(
                    flag_value & syn_flag
                )

                ack_set = bool(
                    flag_value & ack_flag
                )

                return syn_set and not ack_set

            except ValueError:
                return False

        return False

    def analyze_generic(self):
        """Analyze generic text-based packet export"""
        try:
            packets = []

            with open(
                self.filepath,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                lines = f.readlines()

            for line in lines:

                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                packet = self.parse_generic_line(line)

                if packet:
                    packets.append(packet)

            return self.calculate_statistics(packets)

        except Exception as e:
            print(f"Generic parsing error: {e}")
            return None

    def parse_generic_line(self, line):
        """Parse a generic packet line"""
        try:

            # Support:
            # 192.168.71.128 → 192.168.71.1 TCP SYN 22

            if "→" in line or "->" in line:

                parts = line.replace(
                    "→",
                    "->"
                ).split("->")

                if len(parts) >= 2:

                    src_part = parts[0].strip()
                    rest = parts[1].strip()
                    rest_parts = rest.split()

                    src_ip = src_part.split()[-1]

                    dst_ip = (
                        rest_parts[0]
                        if rest_parts
                        else None
                    )

                    if not dst_ip:
                        return None

                    dst_port = None
                    is_syn = False

                    for part in rest_parts:

                        if part.upper() == "SYN":
                            is_syn = True

                        try:
                            port_num = int(part)

                            if 0 < port_num < 65536:
                                dst_port = str(port_num)

                        except ValueError:
                            pass

                    if src_ip and dst_ip:

                        return {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": None,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "flags": "SYN" if is_syn else "",
                            "is_syn": is_syn,
                            "timestamp": None,
                            "info": line
                        }

            return None

        except Exception:
            return None

    def calculate_statistics(self, packets):
        """Calculate packet statistics"""

        if not packets:
            return None

        # ---------------------------------------------------------
        # Basic packet counts
        # ---------------------------------------------------------
        total_packets = len(packets)

        syn_packets = len([
            packet
            for packet in packets
            if packet.get("is_syn", False)
        ])

        tcp_packets = len([
            packet
            for packet in packets
            if str(
                packet.get("protocol", "")
            ).upper() == "TCP"
        ])

        # ---------------------------------------------------------
        # Source and destination IPs
        # ---------------------------------------------------------
        src_ips = set(
            packet["src_ip"]
            for packet in packets
            if packet.get("src_ip")
        )

        dst_ips = set(
            packet["dst_ip"]
            for packet in packets
            if packet.get("dst_ip")
        )

        # ---------------------------------------------------------
        # Unique destination ports
        # ---------------------------------------------------------
        unique_dest_ports = set()

        for packet in packets:

            if packet.get("dst_port"):

                try:
                    unique_dest_ports.add(
                        int(packet["dst_port"])
                    )

                except (ValueError, TypeError):
                    pass

        unique_dest_ports = sorted(
            list(unique_dest_ports)
        )

        # ---------------------------------------------------------
        # Destination port distribution
        # ---------------------------------------------------------
        port_counter = Counter()

        for packet in packets:

            if packet.get("dst_port"):

                try:
                    port_counter[
                        int(packet["dst_port"])
                    ] += 1

                except (ValueError, TypeError):
                    pass

        # ---------------------------------------------------------
        # Primary source IP
        # ---------------------------------------------------------
        source_ip = None

        if src_ips:

            src_counter = Counter(
                packet["src_ip"]
                for packet in packets
                if packet.get("src_ip")
            )

            source_ip = src_counter.most_common(1)[0][0]

        # ---------------------------------------------------------
        # Primary destination IP
        # ---------------------------------------------------------
        dest_ip = None

        if dst_ips:

            dst_counter = Counter(
                packet["dst_ip"]
                for packet in packets
                if packet.get("dst_ip")
            )

            dest_ip = dst_counter.most_common(1)[0][0]

        # ---------------------------------------------------------
        # Protocol distribution
        # ---------------------------------------------------------
        protocol_counter = Counter(
            packet.get("protocol", "Unknown")
            for packet in packets
        )

        # ---------------------------------------------------------
        # First packet timestamp
        # ---------------------------------------------------------
        first_packet_time = None

        for packet in packets:

            if packet.get("timestamp"):

                first_packet_time = packet["timestamp"]
                break

        # ---------------------------------------------------------
        # TCP flag distribution
        # ---------------------------------------------------------
        flag_counter = Counter()

        for packet in packets:

            flags = packet.get("flags", "")

            if flags:
                flag_counter[flags] += 1

        # ---------------------------------------------------------
        # Return analysis results
        # ---------------------------------------------------------
        return {
            "total_packets": total_packets,
            "syn_packets": syn_packets,
            "tcp_packets": tcp_packets,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "unique_source_ips": len(src_ips),
            "unique_dest_ips": len(dst_ips),
            "unique_dest_ports": unique_dest_ports,
            "unique_dest_ports_count": len(unique_dest_ports),
            "port_distribution": dict(
                port_counter.most_common(20)
            ),
            "protocol_distribution": dict(
                protocol_counter
            ),
            "flag_distribution": dict(
                flag_counter
            ),
            "first_packet_time": first_packet_time,
            "packets": packets[:1000]
        }