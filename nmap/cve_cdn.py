import hashlib
import json
import re
import requests
import sys
import xmltodict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_IP = "192.168.178.38"
_PORT = "5000"

def getcpe(xmlfile):
    cpe, cve = {}, {}

    oo = xmltodict.parse(open('/opt/xml/' + xmlfile, 'r').read())
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

        addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
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

        if i not in cvejson:
            cvejson[i] = []

        for cpestr in cpecve['cpe'][i]:
            if re.search('^cpe:[^:]+:[^:]+:[^:]+:.+$', cpestr):
                print(cpestr)
                r = requests.get(f'https://{_IP}:{_PORT}/api/cvefor/' + cpestr, verify=False)
                if r.json() is not None:
                    if r.json() is dict:
                        cvejson[i].append(r.json())
                    else:
                        cvejson[i].append(r.json())

    for i in cpecve['cve']:

        if i not in cvejson:
            cvejson[i] = []

        for cvestr in cpecve['cve'][i]:
            r = requests.get(f'https://{_IP}:{_PORT}/api/cve/' + cvestr, verify=False)
            if r.json() is not None:
                if r.json() is dict:
                    cvejson[i].append(r.json())
                else:
                    cvejson[i].append([r.json()])

    for i in cvejson:
        hostmd5 = hashlib.md5(str(i).encode('utf-8')).hexdigest()

        if type(cvejson[i]) is list and len(cvejson[i]) > 0:
            f = open('/opt/notes/' + scanfilemd5 + '_' + hostmd5 + '.cve', 'w')
            f.write(json.dumps(cvejson[i], indent=4))
            f.close()


getcve(sys.argv[1])
