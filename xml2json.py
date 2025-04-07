# xml2json.py
import xmltodict
import json
import sys

if len(sys.argv) != 3:
    print("Usage: python xml2json.py <input_xml> <output_json>")
    sys.exit(1)

input_xml = sys.argv[1]
output_json = sys.argv[2]

with open(input_xml, 'r') as f:
    xml_data = f.read()

data = xmltodict.parse(xml_data)
with open(output_json, 'w') as f:
    json.dump(data, f, indent=4)