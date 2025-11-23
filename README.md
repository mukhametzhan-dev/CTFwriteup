<img width="755" height="587" alt="image" src="https://github.com/user-attachments/assets/c11e732b-2951-439e-ba96-8cb9f3edd241" /># CTF Write-up: "Buzzing Sound"  
**Category:** Forensics   
**Points:** 500
**Solved by:** @waveofem Team: K@pibaras
**Files:** `capture.pcapng`

### Task
> Can you figure out who was causing this buzzing sound?

**Hint №1:**  
*marc - имя дрона*  
*Куда он летит?*  
(Translation: "marc" is the drone's name. Where is it flying?)
<img width="960" height="1280" alt="image" src="https://github.com/user-attachments/assets/93315e17-59f7-4a6d-a4bd-a87cba989803" />

### Solution Overview
The provided `capture.pcapng` contains Wi-Fi traffic with 802.11 Beacon frames broadcast by a drone. Modern drones (especially those running on ESP32) transmit their **Open Drone ID (ODID)** telemetry inside **Vendor Specific tagged parameters** (Tag 221 / 0xDD).  
These tags contain packed binary GPS coordinates that, when extracted and plotted, reveal the drone’s flight path — and in this case, the flag.
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/d482b4a2-3d6f-4518-9dfc-a44d0b02cfb7" />
ESP32


Vendor Specific Tag
<img width="600" height="587" alt="image" src="https://github.com/user-attachments/assets/d24734d3-41cb-4ed2-bed5-7d677179b32c" />

### Step-by-Step Solution

#### 1. Understanding Where the Data Hides
- Drone ID data is **not** in standard beacon fields.
- It is hidden in **Vendor Specific Elements** → Tag Number **221** (0xDD).
- The vendor OUI in this capture is `fa:0b:bc` (belongs to certain drone manufacturers).
- Inside that tag, after a small header, we find the actual ODID message.

#### 2. ODID Message Structure (in this capture)
After the OUI `fa 0b bc`:
```
Byte  3       → 0x0d          (ODID "magic" wrapper byte)
Bytes 13-16   → Latitude      (signed 32-bit little-endian int)
Bytes 17-20   → Longitude     (signed 32-bit little-endian int)
```
Values are stored multiplied by **10⁷** (standard for ASTM F3411 Remote ID).

So conversion formula:
```python
lat = latitude_int / 10_000_000.0
lon = longitude_int / 10_000_000.0
```

#### 3. Full Automated Python Solver (Scapy)

```python
#!/usr/bin/env python3
# solve_drone.py - Extracts drone GPS path and generates KML with the flag

import struct
import sys
import os
from scapy.all import *

def parse_drone_pcap(pcap_file="capture.pcapng", output_kml="drone_route.kml"):
    if not os.path.exists(pcap_file):
        print(f"[!] File {pcap_file} not found.")
        return

    print(f"[*] Loading {pcap_file}...")
    packets = rdpcap(pcap_file)
    print(f"[*] Analyzing {len(packets)} packets...")

    coordinates = []
    found = 0

    for pkt in packets:
        if not pkt.haslayer(Dot11Beacon):
            continue

        layer = pkt[Dot11Beacon]
        elt = layer
        while isinstance(elt, Dot11Elt):
            if elt.ID == 221:  # Vendor Specific
                payload = bytes(elt.info)

                # Look for specific drone vendor OUI fa:0b:bc + ODID wrapper 0x0d
                if len(payload) > 20 and payload.startswith(b'\xfa\x0b\xbc') and payload[3] == 0x0d:
                    try:
                        lat_raw = payload[13:17]
                        lon_raw = payload[17:21]

                        lat_int = struct.unpack('<i', lat_raw)[0]
                        lon_int = struct.unpack('<i', lon_raw)[0]

                        lat = lat_int / 10_000_000.0
                        lon = lon_int / 10_000_000.0

                        # Filter for realistic Kazakhstan coordinates (Astana area)
                        if 50.0 < lat < 52.0 and 71.0 < lon < 72.0:
                            coordinates.append((lon, lat))
                            found += 1
                    except:
                        pass
            elt = elt.payload

    print(f"[+] Extracted {found} valid GPS points.")

    if coordinates:
        generate_kml(coordinates, output_kml)
    else:
        print("[-] No coordinates found. Check the capture file.")

def generate_kml(coords, filename):
    kml = '''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>Drone Flight Path</name>
    <Style id="redLine">
      <LineStyle>
        <color>ff0000ff</color>
        <width>5</width>
      </LineStyle>
    </Style>
    <Placemark>
      <name>Drone Trajectory</name>
      <styleUrl>#redLine</styleUrl>
      <LineString>
        <tessellate>1</tessellate>
        <coordinates>'''
    
    for lon, lat in coords:
        kml += f"\n          {lon},{lat},0"
    
    kml += "\n        </coordinates>\n      </LineString>\n    </Placemark>\n  </Document>\n</kml>"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(kml)
    
    print(f"[+] KML saved as {filename}")
    print("[+] Open it in Google Earth or https://geojson.io to see the flag!")

if __name__ == "__main__":
    parse_drone_pcap("capture.pcapng", "drone_route.kml")
```

**Usage:**
```bash
pip install scapy
python3 solve_drone.py
```

#### 4. Result
<img width="1125" height="511" alt="image" src="https://github.com/user-attachments/assets/4e04c226-7950-405a-8592-ed2af6277e4f" />

The script generates `drone_route.kml`. When opened in **Google Earth** (or uploaded to https://geojson.io), the path clearly draws large letters on the ground near **AITU University** in **Astana, Kazakhstan**:
<img width="1054" height="732" alt="image" src="https://github.com/user-attachments/assets/f5f7d697-d462-4799-9fb6-389b8866b020" />

```
GPS_4RT_STS
```

### Final Flag
**`GPS_4RT_STS`**

### Tools Used
- Wireshark (initial analysis)
- Scapy (Python)
- Google Earth / geojson.io (visualization)

<img width="1125" height="511" alt="image" src="https://github.com/user-attachments/assets/9c1abb82-e01e-45bc-ba21-422845348de4" />


That’s it — the drone literally wrote the flag in the sky! 🚁
