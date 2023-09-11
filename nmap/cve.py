import hashlib
import json
import re
import sys

import requests
import xmltodict
from cpe import CPE


def extract_cve_ids(json_data):
    cve_ids = []
    for entry in json_data.get("vulnerabilities", []):
        cve_object = entry.get("cve", {})
        cve_id = cve_object.get("id")
        if cve_id:
            cve_ids.append(cve_id)
    return cve_ids


def merge_and_flatten(json_data):
    result = {}

    for ip_address, cve_lists in json_data.items():
        merged_list = []

        for cve_list in cve_lists:
            merged_list.extend(cve_list)

        result[ip_address] = merged_list

    return result


def _get_cpe_23_str(cpe_string):
    return CPE(cpe_string, CPE.VERSION_2_3).as_fs()


def getcpe(xmlfile):
    cpe, cve = {}, {}

    oo = xmltodict.parse(open('/opt/xml/' + xmlfile, 'r').read())
    # oo = xmltodict.parse(open('report_today.xml', 'r').read())
    o = json.loads(json.dumps(oo['nmaprun'], indent=4))

    for ik in o['host']:

        # this fix single host report
        if type(ik) is dict:
            i = ik
        else:
            i = o['host']

        lastportid = 0

        if '@addr' in i['address']:
            address = i['address']['@addr']
        elif type(i['address']) is list:
            for ai in i['address']:
                if ai['@addrtype'] == 'ipv4':
                    address = ai['@addr']

        cpe[address] = {}
        cve[address] = {}

        if 'ports' in i and 'port' in i['ports']:
            for pobj in i['ports']['port']:
                if type(pobj) is dict:
                    p = pobj
                else:
                    p = i['ports']['port']

                if lastportid == p['@portid']:
                    continue
                else:
                    lastportid = p['@portid']

                if 'service' in p:
                    if 'cpe' in p['service']:
                        if type(p['service']['cpe']) is list:
                            for cpei in p['service']['cpe']:
                                cpe[address][cpei] = cpei
                        else:
                            cpe[address][p['service']['cpe']] = p['service']['cpe']

                if 'script' in p:
                    if type(p['script']) is list:
                        for scripti in p['script']:
                            if 'elem' in scripti:
                                if type(scripti['elem']) is list:
                                    for elmi in scripti['elem']:
                                        if elmi['@key'] == 'cve':
                                            cve[address][elmi['#text']] = elmi['#text']

        # this fix single host report
        if type(ik) is not dict:
            break

    res = {'cpe': cpe, 'cve': cve}
    return res


def getcve(xmlfile):
    scanfilemd5 = hashlib.md5(str(xmlfile).encode('utf-8')).hexdigest()
    cpecve = getcpe(xmlfile)
    cvejson = {}

    for i in cpecve['cpe']:
        # extract ip addresses with cpes from cpecve and add empty values to dict
        if i not in cvejson:
            cvejson[i] = []

        for cpestr in cpecve['cpe'][i]:
            cpe23str = _get_cpe_23_str(cpestr)
            if re.search('^cpe:/([^:]+):([^:]+):([^:]+)(?::([^:]+))?$', cpestr):
                # r = requests.get('http://cve.circl.lu/api/cvefor/' + cpestr)
                r = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe23str}')

                try:
                    response = r.json()
                except:
                    response = None

                if response is not None:
                    cves = extract_cve_ids(response)
                    cvejson[i].append(cves)

    cvejson = merge_and_flatten(cvejson)
    cvejson_full = {key: [] for key in cvejson.keys()}

    for i in cpecve['cve']:
        if i not in cvejson:
            cvejson[i] = []

        if i not in cvejson_full:
            cvejson_full[i] = []

        for cvestr in cvejson[i]:
            r = requests.get('http://cve.circl.lu/api/cve/' + cvestr)
            if r.json() is not None:
                if r.json() is dict:
                    cvejson_full[i].append(r.json())
                else:
                    cvejson_full[i].append([r.json()])

    print(cvejson_full)
    
    for i in cvejson_full:
        hostmd5 = hashlib.md5(str(i).encode('utf-8')).hexdigest()

        if type(cvejson_full[i]) is list and len(cvejson_full[i]) > 0:
            print(f"Writing file to /opt/notes/{scanfilemd5}_{hostmd5}.cve")
            with open('/opt/notes/' + scanfilemd5 + '_' + hostmd5 + '.cve', 'w') as f:
                f.write(json.dumps(cvejson_full[i], indent=4))


getcve(sys.argv[1])
