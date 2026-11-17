"""
Nmap XML/text parser for NetSentry
"""

import xml.etree.ElementTree as ET


class NmapParser:
    """Parse Nmap XML and text output"""

    def __init__(self, filepath):
        self.filepath = filepath
        self.data = None

    def parse(self):
        """Auto-detect and parse Nmap output"""
        try:
            with open(
                self.filepath,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:
                content = f.read()

            # Try XML parsing first
            if content.strip().startswith("<?xml"):
                return self.parse_xml(content)
            else:
                return self.parse_text(content)

        except Exception as e:
            print(f"Parse error: {e}")
            return None

    def parse_xml(self, xml_content):
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_content)

            # Extract scan information
            scan_start = root.get("startstr", "Unknown")

            # Find host element
            host = root.find(".//host")

            if host is None:
                return None

            # Host state
            host_state_elem = host.find("status")

            host_state = (
                host_state_elem.get("state", "unknown")
                if host_state_elem is not None
                else "unknown"
            )

            # Target IP
            address_elem = host.find("address")

            target_ip = (
                address_elem.get("addr", "Unknown")
                if address_elem is not None
                else "Unknown"
            )

            # Parse ports
            ports = []
            ports_elem = host.find("ports")

            # Track Nmap extrapolated ports
            extrapolated_filtered = 0
            extrapolated_closed = 0

            if ports_elem is not None:

                # Parse individually listed ports
                for port_elem in ports_elem.findall("port"):

                    port_num = port_elem.get("portid", "0")
                    protocol = port_elem.get("protocol", "tcp")

                    # Port state
                    state_elem = port_elem.find("state")

                    state = (
                        state_elem.get("state", "unknown")
                        if state_elem is not None
                        else "unknown"
                    )

                    reason = (
                        state_elem.get("reason", "")
                        if state_elem is not None
                        else ""
                    )

                    # Service information
                    service_elem = port_elem.find("service")

                    service_name = (
                        service_elem.get("name", "")
                        if service_elem is not None
                        else ""
                    )

                    product = (
                        service_elem.get("product", "")
                        if service_elem is not None
                        else ""
                    )

                    version = (
                        service_elem.get("version", "")
                        if service_elem is not None
                        else ""
                    )

                    ports.append({
                        "port": int(port_num),
                        "protocol": protocol,
                        "state": state,
                        "reason": reason,
                        "service": service_name,
                        "product": product if product else "N/A",
                        "version": version if version else "N/A"
                    })

                # Nmap uses <extraports> when many ports
                # have the same state instead of listing
                # every port individually.
                for extra in ports_elem.findall("extraports"):

                    state = extra.get("state", "")
                    count = int(extra.get("count", 0))

                    if state == "filtered":
                        extrapolated_filtered += count

                    elif state == "closed":
                        extrapolated_closed += count

            # Sort individually listed ports
            ports.sort(key=lambda x: x["port"])

            # Calculate explicitly listed statistics
            open_ports = [
                p for p in ports
                if p["state"] == "open"
            ]

            closed_ports = [
                p for p in ports
                if p["state"] == "closed"
            ]

            filtered_ports = [
                p for p in ports
                if p["state"] == "filtered"
            ]

            # Include extrapolated ports reported by Nmap
            total_scanned = (
                len(ports)
                + extrapolated_filtered
                + extrapolated_closed
            )

            total_filtered = (
                len(filtered_ports)
                + extrapolated_filtered
            )

            total_closed = (
                len(closed_ports)
                + extrapolated_closed
            )

            return {
                "target_ip": target_ip,
                "host_state": host_state,
                "scan_start": scan_start,
                "ports": ports,
                "statistics": {
                    "total_scanned": total_scanned,
                    "open": len(open_ports),
                    "closed": total_closed,
                    "filtered": total_filtered
                },
                "scan_type": "XML",
                "open_ports": open_ports
            }

        except ET.ParseError as e:
            print(f"XML Parse error: {e}")
            return None

        except Exception as e:
            print(f"XML processing error: {e}")
            return None

    def parse_text(self, text_content):
        """Parse Nmap text output"""
        try:
            lines = text_content.split("\n")

            ports = []
            target_ip = None
            host_state = None

            for line in lines:

                line = line.strip()

                # Look for Nmap report line
                if "Nmap scan report for" in line:

                    parts = line.split()

                    for part in parts:

                        if self.is_ipv4(part):
                            target_ip = part
                            break

                # Look for host state
                if line.startswith("Host is"):

                    if "up" in line:
                        host_state = "up"

                    elif "down" in line:
                        host_state = "down"

                # Parse port lines
                if "/" in line and (
                    "open" in line
                    or "closed" in line
                    or "filtered" in line
                ):

                    try:
                        parts = line.split()

                        if len(parts) >= 3:

                            port_proto = parts[0]
                            state = parts[1]
                            service = (
                                parts[2]
                                if len(parts) > 2
                                else ""
                            )

                            port_num, protocol = port_proto.split("/")

                            ports.append({
                                "port": int(port_num),
                                "protocol": protocol,
                                "state": state,
                                "reason": "",
                                "service": service,
                                "product": "N/A",
                                "version": "N/A"
                            })

                    except (ValueError, IndexError):
                        pass

            if not target_ip:
                target_ip = "Unknown"

            if not host_state:
                host_state = "unknown"

            ports.sort(key=lambda x: x["port"])

            open_ports = [
                p for p in ports
                if p["state"] == "open"
            ]

            closed_ports = [
                p for p in ports
                if p["state"] == "closed"
            ]

            filtered_ports = [
                p for p in ports
                if p["state"] == "filtered"
            ]

            return {
                "target_ip": target_ip,
                "host_state": host_state,
                "scan_start": "Unknown",
                "ports": ports,
                "statistics": {
                    "total_scanned": len(ports),
                    "open": len(open_ports),
                    "closed": len(closed_ports),
                    "filtered": len(filtered_ports)
                },
                "scan_type": "Text",
                "open_ports": open_ports
            }

        except Exception as e:
            print(f"Text parse error: {e}")
            return None

    @staticmethod
    def is_ipv4(s):
        """Check if string is valid IPv4"""

        parts = s.split(".")

        if len(parts) != 4:
            return False

        try:
            return all(
                0 <= int(part) <= 255
                for part in parts
            )

        except ValueError:
            return False