import xml.etree.ElementTree as ET
import json

"""
The script parses an XML file containing MAC prefixes and corresponding vendor names,
and creates a dictionary mapping MAC prefixes to vendor names.

Usage:
1. Ensure the 'vendorMacs.xml' file is present in the same directory as the script.
2. Run the script to generate the dictionary mapping.
3. save this to something useful
"""

tree = ET.parse('vendorMacs.xml')
root = tree.getroot()

mac_to_vendor = {entry.attrib['mac_prefix']: entry.attrib['vendor_name'] for entry in root}

print(json.dumps(mac_to_vendor, indent=4))
