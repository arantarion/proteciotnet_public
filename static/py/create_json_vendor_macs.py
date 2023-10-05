import xml.etree.ElementTree as ET
import json

tree = ET.parse('vendorMacs.xml')
root = tree.getroot()

mac_to_vendor = {entry.attrib['mac_prefix']: entry.attrib['vendor_name'] for entry in root}

print(json.dumps(mac_to_vendor, indent=4))
