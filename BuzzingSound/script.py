import struct
import sys
import os

try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
except ImportError:
    print("Error: Scapy is not installed.")
    print("Run: pip install scapy")
    sys.exit(1)

def parse_drone_pcap(pcap_file, output_kml="drone_route_new.kml"):
    if not os.path.exists(pcap_file):
        print(f"Error: File {pcap_file} not found.")
        return

    print(f"[*] Loading {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    print(f"[*] Scanning {len(packets)} packets...")
    
    coordinates = []
    found_count = 0

    for pkt in packets:
        if not pkt.haslayer(Dot11Beacon):
            continue
            
        try:
            dot11elt = pkt.getlayer(Dot11Elt)
        except Exception:
            continue

        while dot11elt:
            if dot11elt.ID == 221: # Vendor Specific Tag
                payload = dot11elt.info
                
                # Check for OUI: fa:0b:bc (Cen)
                if payload.startswith(b'\xfa\x0b\xbc'):
                    # Payload Structure for this Capture:
                    # [0-2] OUI (fa 0b bc)
                    # [3]   Type/Wrapper (0d) - This is the anchor
                    # [4-12] Flags/Headers
                    # [13-16] Latitude (4 bytes)
                    # [17-20] Longitude (4 bytes)
                    
                    # Verify the wrapper byte is 0x0d (ODID magic byte)
                    if len(payload) > 20 and payload[3] == 0x0d:
                        try:
                            # Extract Hex
                            lat_bytes = payload[13:17]
                            lon_bytes = payload[17:21]
                            
                            # Decode Little Endian Integers
                            lat_int = struct.unpack('<i', lat_bytes)[0]
                            lon_int = struct.unpack('<i', lon_bytes)[0]
                            
                            # Convert to Degrees
                            lat = lat_int / 10000000.0
                            lon = lon_int / 10000000.0
                            
                            # Filter for valid Kazakhstan coordinates to remove noise/errors
                            # Astana is approx Lat 51, Lon 71
                            if 40.0 < lat < 60.0 and 60.0 < lon < 90.0:
                                coordinates.append((lon, lat))
                                found_count += 1
                                
                        except Exception:
                            pass

            dot11elt = dot11elt.payload

    print(f"[*] Found {found_count} valid points.")
    
    if len(coordinates) > 0:
        generate_kml(coordinates, output_kml)
    else:
        print("[-] No valid coordinates found. offsets might still be wrong.")

def generate_kml(coords, filename):
    kml_content = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>Drone Path</name>
    <Style id="pathStyle">
      <LineStyle>
        <color>ff0000ff</color>
        <width>4</width>
      </LineStyle>
    </Style>
    <Placemark>
      <name>Drone Flight</name>
      <styleUrl>#pathStyle</styleUrl>
      <LineString>
        <tessellate>1</tessellate>
        <coordinates>
"""
    
    # Convert coords to string format
    coord_strings = [f"{lon},{lat},0" for lon, lat in coords]
    kml_content += "\n".join(coord_strings)
    
    kml_content += """
        </coordinates>
      </LineString>
    </Placemark>
  </Document>
</kml>"""
    
    with open(filename, "w") as f:
        f.write(kml_content)
        
    print(f"[+] Successfully created {filename}")
    print("[+] Upload this file to https://geojson.io to view the flag.")

if __name__ == "__main__":
    # Ensure this matches your filename
    parse_drone_pcap("newcap.pcapng")
