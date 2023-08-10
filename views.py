import base64
import subprocess
import xmltodict
import json
import hashlib
import re
import os
import logging
import colorlog
import urllib.parse
from collections import OrderedDict
from datetime import datetime
import urllib.parse

from django.http import HttpResponse
from django.shortcuts import render

from proteciotnet_dev.functions import _get_cwe_description
from proteciotnet_dev.functions import *

V2_PATTERN = "AV:([L|A|N])/AC:(H|M|L)/Au:([M|S|N])/C:([N|P|C])/I:([N|P|C])/A:([N|P|C])"


logging_level = logging.DEBUG
main_logger = logging.getLogger()
main_logger.setLevel(logging_level)

# Set up a stream handler to log to the console
stream_handler = colorlog.StreamHandler()
stream_handler.setFormatter(colorlog.ColoredFormatter("%(asctime)s - %(name)s - %(log_color)s%(levelname)s - %(message)s"))

# Add handler to logger
main_logger.addHandler(stream_handler)

# logger.debug("This is a debug message")
# logger.info("This is an info message")
# logger.warning("This is a warning message")
# logger.error("This is an error message")
# logger.critical("This is a critical message")


class Cvss3vector:
    def __init__(self, vector_string):
        self.vector_string = vector_string
        self.fields = self.parse_vector()
        self.version = 0
        self.attack_vector = ""
        self.att_complexity = ""
        self.priv_req = ""
        self.user_interaction = ""
        self.scope = ""
        self.confidentiality = ""
        self.integrity = ""
        self.availability = ""
        self.mapping = {
            "AV": {
                "N": "Network",
                "A": "Adjacent Network",
                "L": "Local",
                "P": "Physical"
            },
            "AC": {
                "H": "High",
                "L": "Low"
            },
            "PR": {
                "N": "None",
                "L": "Low",
                "H": "High"
            },
            "UI": {
                "N": "None",
                "R": "Required"
            },
            "S": {
                "U": "Unchanged",
                "C": "Changed"
            },
            "C": {
                "N": "None",
                "L": "Low",
                "H": "High"
            },
            "I": {
                "N": "None",
                "L": "Low",
                "H": "High"
            },
            "A": {
                "N": "None",
                "L": "Low",
                "H": "High"
            }
        }
        self.get_text()

    def parse_vector(self):
        fields = {}
        parts = self.vector_string.split("/")
        for part in parts:
            field, value = part.split(":")
            fields[field] = value
        return fields

    def get_text(self):
        for key in self.fields.keys():
            if key == "CVSS":
                self.version = self.fields['CVSS']
            elif key == "AV":
                self.attack_vector = self.mapping.get('AV', '').get(self.fields['AV'], '')
            elif key == "AC":
                self.att_complexity = self.mapping.get('AC', '').get(self.fields['AC'], '')
            elif key == "PR":
                self.priv_req = self.mapping.get('PR', '').get(self.fields['PR'], '')
            elif key == "UI":
                self.user_interaction = self.mapping.get('UI', '').get(self.fields['UI'], '')
            elif key == "S":
                self.scope = self.mapping.get('S', '').get(self.fields['S'], '')
            elif key == "C":
                self.confidentiality = self.mapping.get('C', '').get(self.fields['C'], '')
            elif key == "I":
                self.integrity = self.mapping.get('I', '').get(self.fields['I'], '')
            elif key == "A":
                self.availability = self.mapping.get('A', '').get(self.fields['A'], '')

    def __str__(self):
        td_style = 'style="padding:0; margin:0; border: none;"'
        tr_style = 'style="border: none;"'

        overview = f'<table style="border-collapse: collapse;">' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>CVSS Version</td>' \
            f'<td {td_style}>{self.version}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Attack Vector (AV)</td>' \
            f'<td {td_style}>{self.attack_vector}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Attack Complexity (AC)</td>' \
            f'<td {td_style}>{self.att_complexity}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Privileges Required (PR)</td>' \
            f'<td {td_style}>{self.priv_req}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>User Interaction (UI)</td>' \
            f'<td {td_style}>{self.user_interaction}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Scope (S)</td>' \
            f'<td {td_style}>{self.scope}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Confidentiality Impact (C)</td>' \
            f'<td {td_style}>{self.confidentiality}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Integrity Impact (I)</td>' \
            f'<td {td_style}>{self.integrity}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Availability Impact (A)</td>' \
            f'<td {td_style}>{self.availability}</td>' \
            f'</tr>'\
            f'</table>'

        return overview


class CvssVector:
    def __init__(self, cvss_vec, cve_id):
        try:
            matches = re.findall(V2_PATTERN, cvss_vec)
        except IndexError:
            matches = [('-', '-', '-', '-', '-', '-')]

        if not matches:
            matches = [('-', '-', '-', '-', '-', '-')]

        self.cve_id = cve_id
        self.access_vector = matches[0][0]
        self.access_complexity = matches[0][1]
        self.authentication = matches[0][2]
        self.confidentiality_impact = matches[0][3]
        self.integrity_impact = matches[0][4]
        self.availability_impact = matches[0][5]

        self.access_vector_text = self._get_full_access_vector(self.access_vector)
        self.access_complexity_text = self._get_full_access_complexity(self.access_complexity)
        self.authentication_text = self._get_full_authentication(self.authentication)
        self.confidentiality_impact_text = self._get_full_con_impact(self.confidentiality_impact)
        self.integrity_impact_text = self._get_full_con_impact(self.integrity_impact)
        self.availability_impact_text = self._get_full_con_impact(self.availability_impact)

    # TODO make like v3 version
    def __str__(self):

        td_style = 'style="padding:0; margin:0; border: none;"'
        tr_style = 'style="border: none;"'

        x = f'<table style="border-collapse: collapse;">' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Access Vector (AV)</td>' \
            f'<td {td_style}>{self.access_vector_text}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Access Complexity (AC)</td>' \
            f'<td {td_style}>{self.access_complexity_text}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Authentication (Au)</td>' \
            f'<td {td_style}>{self.authentication_text}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Confidentiality Impact (C)</td>' \
            f'<td {td_style}>{self.confidentiality_impact_text}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Integrity Impact (I)</td>' \
            f'<td {td_style}>{self.integrity_impact_text}</td>' \
            f'</tr>' \
            f'<tr {tr_style}>' \
            f'<td {td_style}>Availability Impact (A)</td>' \
            f'<td {td_style}>{self.availability_impact_text}</td>' \
            f'</tr>' \
            f'</table>'

        return x

    def __repr__(self):
        return f"CVSS_vector(cvss_vec='{self.access_vector}/{self.access_complexity}/" \
               f"{self.authentication}/{self.confidentiality_impact}/" \
               f"{self.integrity_impact}/{self.availability_impact}')"

    def _get_full_access_vector(self, av):
        if av == "L":
            return "Local"
        elif av == "A":
            return "Adjacent Network"
        elif av == "N":
            return "Network"
        else:
            return "NaN"

    def _get_full_access_complexity(self, ac):
        if ac == "H":
            return "High"
        elif ac == "M":
            return "Medium"
        elif ac == "L":
            return "Low"
        else:
            return "NaN"

    def _get_full_authentication(self, a):
        if a == "M":
            return "Multiple"
        elif a == "S":
            return "Single"
        elif a == "N":
            return "None"
        else:
            return "NaN"

    def _get_full_con_impact(self, ci):
        if ci == "N":
            return "None"
        elif ci == "P":
            return "Partial"
        elif ci == "C":
            return "Complete"
        else:
            return "NaN"


def login(request):
    r = {}

    if request.method == "POST":
        return HttpResponse(json.dumps(r), content_type="application/json")

    return render(request, 'proteciotnet_dev/main.html', r)


def setscanfile(request, scanfile):
    xmlfiles = os.listdir('/opt/xml')

    for i in xmlfiles:
        if i == scanfile:
            request.session['scanfile'] = i
            break

    if scanfile == 'unset':
        if 'scanfile' in request.session:
            del (request.session['scanfile'])

    return render(request, 'proteciotnet_dev/nmap_device_overview.html',
                  {'js': '<script> location.href="/"; </script>'})


def port(request, port):
    return render(request, 'proteciotnet_dev/main.html',
                  {'out': '', 'table': '', 'scaninfo': '', 'scandetails': '', 'trhost': ''})


def details(request, address):
    r = {'auth': True}

    oo = xmltodict.parse(open('/opt/xml/' + request.session['scanfile'], 'r').read())
    r['out2'] = json.dumps(oo['nmaprun'], indent=4)
    o = json.loads(r['out2'])

    r['trhost'] = ''
    pc, po, pf = 0, 0, 0

    scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

    # collect all labels in labelhost dict
    labelhost = {}
    labelfiles = os.listdir('/opt/notes')
    for lf in labelfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.host\.label$', lf)
        if m is not None:
            if m.group(1) not in labelhost:
                labelhost[m.group(1)] = {}
            labelhost[m.group(1)][m.group(2)] = open('/opt/notes/' + lf, 'r').read()

    # collect all notes in noteshost dict
    noteshost = {}
    notesfiles = os.listdir('/opt/notes')
    for nf in notesfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.notes$', nf)
        if m is not None:
            if m.group(1) not in noteshost:
                noteshost[m.group(1)] = {}
            noteshost[m.group(1)][m.group(2)] = open('/opt/notes/' + nf, 'r').read()

    # collect all cve in cvehost dict
    cvehost = get_cve(scanmd5)

    r[
        'trhead'] = '<tr><th>Port</th><th style="width:300px;">Product / Version</th><th>Extra Info</th><th>&nbsp;</th></tr>'
    for ik in o['host']:
        pel = 0
        # this fix single host report
        if type(ik) is dict:
            i = ik
        else:
            i = o['host']

        if 'ports' not in i:
            continue

        if '@addr' in i['address']:
            saddress = i['address']['@addr']
        elif type(i['address']) is list:
            for ai in i['address']:
                if ai['@addrtype'] == 'ipv4':
                    saddress = ai['@addr']

        if str(saddress) == address:
            hostname = ''
            if 'hostnames' in i and type(i['hostnames']) is dict:
                # hostname = json.dumps(i['hostnames'])
                if 'hostname' in i['hostnames']:
                    hostname += '<br>'
                    if type(i['hostnames']['hostname']) is list:
                        for hi in i['hostnames']['hostname']:
                            hostname += '<span class="small grey-text"><b>' + hi['@type'] + ':</b> ' + hi[
                                '@name'] + '</span><br>'
                    else:
                        hostname += '<span class="small grey-text"><b>' + i['hostnames']['hostname'][
                            '@type'] + ':</b> ' + i['hostnames']['hostname']['@name'] + '</span><br>'

            r['address'] = html.escape(str(saddress))
            r['hostname'] = hostname

            scantitle = request.session['scanfile'].replace('.xml', '').replace('_', ' ')
            if re.search('^webmapsched\_[0-9\.]+', request.session['scanfile']):
                m = re.search('^webmapsched\_[0-9\.]+\_(.+)', request.session['scanfile'])
                scantitle = m.group(1).replace('.xml', '').replace('_', ' ')
            r['scanfile'] = scantitle

            labelout = '<span id="hostlabel"></span>'
            if scanmd5 in labelhost:
                if addressmd5 in labelhost[scanmd5]:
                    labelcolor = labelToColor(labelhost[scanmd5][addressmd5])
                    _ = labelToMargin(labelhost[scanmd5][addressmd5])
                    _ = '<span id="hostlabel" style="margin-left:60px;margin-top:-24px;" class="rightlabel ' \
                        + labelcolor + '">' + html.escape(labelhost[scanmd5][addressmd5]) + '</span>'

                    r['label'] = html.escape(labelhost[scanmd5][addressmd5])
                    r['labelcolor'] = labelcolor

            rmdupl = {}
            r['tr'] = {}
            for pobj in i['ports']['port']:
                if type(pobj) is dict:
                    p = pobj
                else:
                    p = i['ports']['port']

                if p['@portid'] in rmdupl:
                    continue

                rmdupl[p['@portid']] = 1

                if p['state']['@state'] == 'closed':
                    pc = (pc + 1)
                elif p['state']['@state'] == 'open':
                    po = (po + 1)
                elif p['state']['@state'] == 'filtered':
                    pf = (pf + 1)

                pel = (pel + 1)
                oshtml = ''
                if 'service' in p:
                    if '@ostype' in p['service']:
                        oshtml = '<div style="font-family:monospace;padding:6px;margin:6px;border-left:solid #666 1px;"><sup style="border-bottom:solid #ccc 1px;">Operating System</sup><br>' + html.escape(
                            p['service']['@ostype']) + '</div>'

                so = ''
                if 'script' in p:
                    if '@id' in p['script']:
                        if p['script']['@id'] != 'fingerprint-strings':
                            so += '<div style="word-wrap: break-word;word-break: break-all;padding:6px;margin-left:6px;border-left:solid #666 1px;max-width:300px;font-size:12px;color:#ccc;font-family:monospace;"><sup style="color:#999;border-bottom:solid #999 1px;">script output</sup><br><b>' + html.escape(
                                p['script']['@id']) + '</b> ' + html.escape(p['script']['@output']) + '</div>'
                    else:
                        for sosc in p['script']:
                            if '@id' in sosc:
                                if sosc['@id'] != 'fingerprint-strings':
                                    so += '<div style="word-wrap: break-word;word-break: break-all;padding:6px;margin:6px;border-left:solid #666 1px;max-width:300px;font-size:12px;color:#ccc;font-family:monospace;"><sup style="color:#999;border-bottom:solid #999 1px;">script output</sup><br><b>' + html.escape(
                                        sosc['@id']) + '</b> ' + html.escape(sosc['@output']) + '</div>'

                v, z, e = '', '', '<i class="grey-text">N/A</i>'
                if p['state']['@state'] == 'open':
                    if 'service' in p:
                        if '@version' in p['service']:
                            v = p['service']['@version']
                        else:
                            v = '<i class="grey-text">No Version</i>'

                        if '@product' in p['service']:
                            z = p['service']['@product']
                        else:
                            z = '<i class="grey-text">No Product</i>'

                        if '@extrainfo' in p['service']:
                            e = p['service']['@extrainfo']

                        cpe = ''
                        if 'cpe' in p['service']:
                            if type(p['service']['cpe']) is list:
                                for cpei in p['service']['cpe']:
                                    cpe += '<div class="grey-text" style="font-family:monospace;font-size:12px;">' + html.escape(
                                        cpei) + '</div>'
                            else:
                                cpe = '<div class="grey-text" style="font-family:monospace;font-size:12px;">' + html.escape(
                                    p['service']['cpe']) + '</div>'

                        servicename = p['service']['@name']
                    else:
                        servicename = ''

                    r['tr'][p['@portid']] = {
                        'service': servicename,
                        'protocol': p['@protocol'],
                        'portid': p['@portid'],
                        'product': z,
                        'version': v,
                        'cpe': cpe,
                        'state': p['state']['@state'],
                        'reason': p['state']['@reason'],
                        'extrainfo': e,
                        'pel': str(pel)
                    }

                    r['trhost'] += '<tr><td style="vertical-align:top;">' + \
                                   '<span style="color:#999;font-size:12px;">' + servicename + '</span><br>' + \
                                   '<span class="new badge blue" data-badge-caption="">' + p['@protocol'] + ' / ' + p[
                                       '@portid'] + '</span>' + \
                                   '</td>' + \
                                   '<td>' + z + ' / ' + v + '<br><span style="font-size:12px;color:#999;">State: ' + \
                                   p['state']['@state'] + '<br>Reason: ' + p['state']['@reason'] + '</span></td>' + \
                                   '<td style="vertical-align:top">' + e + '<br>' + cpe + '</td>' + \
                                   '<td><ul id="dropdown' + str(
                        pel) + '" class="dropdown-content" style="min-width:300px;">' + \
                                   '	<li><a href="#!" class="btncpy" data-clipboard-text="curl -v -A \'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1\' -k \'http://' + html.escape(
                        address) + ':' + html.escape(p['@portid']) + '\'">Copy as curl command</a></li>' + \
                                   '	<li><a href="#!" class="btncpy" data-clipboard-text="nikto -host \'http://' + html.escape(
                        address) + ':' + html.escape(p['@portid']) + '\'">Copy as nikto command</a></li>' + \
                                   '	<li><a href="#!" class="btncpy" data-clipboard-text="telnet ' + html.escape(
                        address) + ' ' + html.escape(p['@portid']) + '">Copy as telnet command</a></li>' + \
                                   '</ul><a class="dropdown-trigger btn blue right" href="#!" data-target="dropdown' + str(
                        pel) + '"><i class="material-icons">arrow_drop_down</i></a> ' + \
                                   '<button onclick="javascript:apiPortDetails(\'' + html.escape(
                        address) + '\',\'' + html.escape(p[
                                                             '@portid']) + '\');" class="btn blue right"><i class="material-icons">receipt</i></button></td>' + \
                                   '</tr>'
                elif p['state']['@state'] == 'filtered':
                    if 'service' in p:
                        servicename = p['service']['@name']
                    else:
                        servicename = ''

                    r['tr'][p['@portid']] = {
                        'service': servicename,
                        'protocol': p['@protocol'],
                        'portid': p['@portid'],
                        'state': p['state']['@state'],
                        'reason': p['state']['@reason'],
                        'pel': str(pel)
                    }
                    r['trhost'] += '<tr><td><span class="new badge grey" data-badge-caption="">' + p[
                        '@protocol'] + ' / ' + p['@portid'] + '</span><br>' + \
                                   '<span style="color:#999;font-size:12px;">' + servicename + '</span></td>' + \
                                   '<td colspan="2" style="color:#999;font-size:12px;">State: filtered<br>Reason: ' + \
                                   p['state']['@reason'] + '</td>' + \
                                   '<td><button onclick="javascript:apiPortDetails(\'' + html.escape(
                        address) + '\',\'' + html.escape(p[
                                                             '@portid']) + '\');" class="btn blue right"><i class="material-icons">receipt</i></button></td></tr>'
                else:
                    if 'service' in p:
                        servicename = p['service']['@name']
                    else:
                        servicename = ''

                    r['tr'][p['@portid']] = {
                        'service': servicename,
                        'protocol': p['@protocol'],
                        'portid': p['@portid'],
                        'state': p['state']['@state'],
                        'reason': p['state']['@reason'],
                        'pel': str(pel)
                    }
                    r['trhost'] += '<tr><td><span class="new badge grey" data-badge-caption="">' + p[
                        '@protocol'] + ' / ' + p['@portid'] + '</span><br>' + \
                                   '<span style="color:#999;font-size:12px;">' + servicename + '</span></td>' + \
                                   '<td colspan="2" style="color:#999;font-size:12px;">State: ' + p['state'][
                                       '@state'] + '<br>Reason: ' + p['state']['@reason'] + '</td>' + \
                                   '<td><button onclick="javascript:apiPortDetails(\'' + html.escape(
                        address) + '\',\'' + html.escape(p[
                                                             '@portid']) + '\');" class="btn blue right"><i class="material-icons">receipt</i></button></td></tr>'

        # this fix single host report
        if type(ik) is not dict:
            break

    r['table'] = ''
    if scanmd5 in noteshost:
        if addressmd5 in noteshost[scanmd5]:
            notesb64 = noteshost[scanmd5][addressmd5]
            r['table'] += '<div class="card" style="background-color:#3e3e3e;">' + \
                          '	<div class="card-content"><h5>Notes</h5>' + \
                          '		' + base64.b64decode(urllib.parse.unquote(notesb64)).decode('ascii') + \
                          '	</div>' + \
                          '</div>'
            r['notes'] = base64.b64decode(urllib.parse.unquote(notesb64)).decode('ascii')

    cveout = ''
    if scanmd5 in cvehost:
        if addressmd5 in cvehost[scanmd5]:
            cvejson = json.loads(cvehost[scanmd5][addressmd5])
            cveids = {}

            for i in cvejson:
                if type(i) is list:
                    listcve = i
                elif type(i) is dict:
                    listcve = [i]

                for cveobj in listcve:
                    try:
                        if 'message' in cveobj.keys():
                            if cveobj['message'] == 'No cves found':
                                continue
                    except KeyError:
                        continue

                    cverefout = ''
                    for cveref in cveobj['references']:
                        cverefout += '<a href="' + cveref + '">' + cveref + '</a><br>'

                    cveexdbout = ''
                    if 'exploit-db' in cveobj:
                        cveexdbout = '<br><div class="small" style="line-height:20px;"><b>Exploit DB:</b><br>'
                        for cveexdb in cveobj['exploit-db']:
                            if 'title' in cveexdb:
                                cveexdbout += '<a href="' + cveexdb['source'] + '">' + html.escape(
                                    cveexdb['title']) + '</a><br>'
                        cveexdbout += '</div>'

                    cvss_score = cveobj.get('cvss', '')
                    cvss3_score = cveobj.get('cvss3', '')
                    cvss3_vector = cveobj.get('cvss3-vector', '')

                    if cvss3_score:
                        label3_color, font3_color = get_cvss_color(cvss3_score, 3)

                    label_color, font_color = get_cvss_color(cvss_score, 2)

                    #cwe_string = f'<span class="label grey">' + html.escape(cveobj['cwe']) + '</span>'

                    if "Other" not in cveobj["cwe"] and "noinfo" not in cveobj["cwe"]:
                        cwe_tooltip = f'<div class="tt2" style="color:white"><a href="https://cwe.mitre.org/data/definitions/{cveobj["cwe"][4:]}.html" target="_BLANK" style="color:white">{cveobj["cwe"]}</a><span class="ttt2">{_get_cwe_description(cveobj["cwe"])}</span></div>'
                        #cwe_tooltip = f'<a href="https://cwe.mitre.org/data/definitions/{cveobj["cwe"][4:]}.html" data-toggle="tooltip" data-placement="top" title="{_get_cwe_description(cveobj["cwe"])}" style="color:white">{cwe_string}</a>'
                    else:
                        #cwe_tooltip = f'<a href="#" data-toggle="tooltip" data-placement="top" title="{_get_cwe_description(cveobj["cwe"])}" style="color:white">{html.escape(cveobj["cwe"])}</a>'
                        cwe_tooltip = f'<div class="tt2" style="color:white">{cveobj["cwe"]}<span class="ttt2">{_get_cwe_description(cveobj["cwe"])}</span></div>'

                    cwe_string = f'<span class="label grey">' + cwe_tooltip + '</span>'

                    try:
                        cvss_vector = cveobj["cvss-vector"]
                        cvss_vec_obj = CvssVector(cvss_vector, cveobj["id"])
                    except KeyError:
                        cvss_vector = "AV:-/AC:-/Au:-/C:-/I:-/A:-"
                        cvss_vec_obj = CvssVector(cvss_vector, cveobj["id"])

                    #cvss_vector_html = f'<a href="#" data-toggle="tooltip" data-placement="top" title="{cvss_vec_obj.__str__()}" style="color:white">{html.escape(cvss_vector)}</a>'
                    cvss_vector_html = f'<div class="tooltip" style="color:white">{html.escape(cvss_vector)}<span class="tooltiptext">{cvss_vec_obj.__str__()}</span></div>'

                    if cvss3_vector:
                        cvss3_vec_obj = Cvss3vector(cvss3_vector)
                        #cvss3_vector_html = f'<a href="#" data-toggle="tooltip" data-placement="top" title="{cvss3_vec_obj.__str__()}" style="color:white">{html.escape(cvss3_vector)}</a>'
                        cvss3_vector_html = f'<div class="tooltip" style="color:white">{html.escape(cvss3_vector)}<span class="tooltiptext">{cvss3_vec_obj.__str__()}</span></div>'

                    cveout += f'<div id="' + html.escape(cveobj['id']) + '" style="line-height:28px;padding:10px;border-bottom:solid #666 1px;margin-top:10px;">'
                    cveout += f'<a href=https://nvd.nist.gov/vuln/detail/{html.escape(cveobj["id"])} style="color:white" target="_BLANK"> <span class="label blue" style="box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);">' + html.escape(cveobj['id']) + '</span></a> '
                    cveout += '&nbsp; - &nbsp;'
                    cveout += f'<span class="label {label_color}" style="color:{font_color}">' + html.escape(f"CVSS 2.0 score: {str(cveobj['cvss'])}") + '</span> '
                    cveout += f'<span class="label grey">' + cvss_vector_html + '</span>' + " "

                    if cvss3_score and cvss3_vector:
                        cveout += '&nbsp; - &nbsp;'
                        cveout += f'<span class="label {label3_color}" style="color:{font3_color}">' + html.escape(f"CVSS {cvss3_vec_obj.version} score: {str(cvss3_score)}") + '</span> '
                        cveout += f'<span class="label grey">' + cvss3_vector_html + '</span>' + " "
                        cveout += '&nbsp; - &nbsp;'

                    cveout += cwe_string
                    cveout += '<br><br>'
                    cveout += html.escape(cveobj['summary'])
                    cveout += '<br><br>'
                    cveout += f'<div class="small" style="line-height:20px;"><b>References:</b><br>' + cverefout + '</div>' + cveexdbout + '</div>'

                    cveids[cveobj['id']] = cveobj['id']

            r['cveids'] = cveids
            r['cvelist'] = cveout

    r['js'] = '<script> ' + \
              '$(document).ready(function() { ' + \
              '	$("#scantitle").html("' + html.escape(request.session['scanfile']) + '");' + \
              '	var clipboard = new ClipboardJS(".btncpy"); ' + \
              '	clipboard.on("success", function(e) { ' + \
              '		M.toast({html: "Copied to clipboard"}); ' + \
              '	}); ' + \
              '	$(".dropdown-trigger").dropdown(); ' + \
              '	$("#detailspo").html(\'<center><h4><i class="fas fa-lock-open green-text"></i> ' + str(
        po) + '</h4><span class="small grey-text">OPEN PORTS</span></center>\');' + \
              '	$("#detailspc").html(\'<center><h4><i class="fas fa-lock red-text"></i> ' + str(
        pc) + '</h4><span class="small grey-text">CLOSED PORTS</span></center>\');' + \
              '	$("#detailspf").html(\'<center><h4><i class="fas fa-filter grey-text"></i> ' + str(
        pf) + '</h4><span class="small grey-text">FILTERED PORTS</span></center>\');' + \
              '}); ' + \
              '</script>'

    return render(request, 'proteciotnet_dev/nmap_device_details.html', r)


def index(request, filterservice="", filterportid=""):
    r = {'auth': True}

    gitcmd = subprocess.check_output('cd /opt/proteciotnet/proteciotnet_dev && git describe --long --abbrev=10 --tag',
                                     shell=True, text=True).strip()
    r['webmapver'] = gitcmd

    if 'scanfile' in request.session:
        oo = xmltodict.parse(open('/opt/xml/' + request.session['scanfile'], 'r').read())
        r['out2'] = json.dumps(oo['nmaprun'], indent=4)
        o = json.loads(r['out2'])
    else:
        # no file selected
        xmlfiles = os.listdir('/opt/xml')

        r['tr'] = {}
        r['stats'] = {'po': 0, 'pc': 0, 'pf': 0}

        xmlfilescount = 0
        for i in xmlfiles:
            if re.search('\.xml$', i) is None:
                continue

            # portstats = {}
            xmlfilescount = (xmlfilescount + 1)

            try:
                oo = xmltodict.parse(open('/opt/xml/' + i, 'r').read())
            except:
                r['tr'][i] = {'filename': html.escape(i), 'start': 0, 'startstr': 'Incomplete / Invalid', 'hostnum': 0,
                              'href': '#!', 'portstats': {'po': 0, 'pc': 0, 'pf': 0}}
                continue

            r['out2'] = json.dumps(oo['nmaprun'], indent=4)
            o = json.loads(r['out2'])

            if 'host' in o:
                if type(o['host']) is not dict:
                    hostnum = str(len(o['host']))
                else:
                    hostnum = '1'
            else:
                hostnum = '0'

            if hostnum != '0':
                viewhref = '/setscanfile/' + html.escape(i)
            else:
                viewhref = '#!'

            filename = i
            if re.search('^webmapsched\_[0-9\.]+', i):
                m = re.search('^webmapsched\_([0-9\.]+)\_(.+)', i)
                filename = '<i class="fas fa-calendar-alt grey-text"></i> ' + html.escape(m.group(2))

            portstats = nmap_ports_stats(i)

            r['stats']['po'] = (r['stats']['po'] + portstats['po'])
            r['stats']['pc'] = (r['stats']['pc'] + portstats['pc'])
            r['stats']['pf'] = (r['stats']['pf'] + portstats['pf'])

            r['tr'][o['@start']] = {
                'filename': filename,
                'start': o['@start'],
                'startstr': html.escape(datetime.fromtimestamp(int(o['@start'])).strftime('%A, %d. %B %Y - %H:%M:%S')),
                # html.escape(o['@startstr']),
                'hostnum': hostnum,
                'href': viewhref,
                'portstats': portstats
            }

        r['tr'] = OrderedDict(sorted(r['tr'].items()))
        r['stats']['xmlcount'] = xmlfilescount

        return render(request, 'proteciotnet_dev/nmap_file_overview.html', r)

    scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    r['scanfile'] = html.escape(str(request.session['scanfile']))
    r['scanmd5'] = scanmd5

    # collect all labels in labelhost dict
    labelhost = {}
    labelfiles = os.listdir('/opt/notes')
    for lf in labelfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.host\.label$', lf)
        if m is not None:
            if m.group(1) not in labelhost:
                labelhost[m.group(1)] = {}
            labelhost[m.group(1)][m.group(2)] = open('/opt/notes/' + lf, 'r').read()

    # collect all notes in noteshost dict
    noteshost = {}
    notesfiles = os.listdir('/opt/notes')
    for nf in notesfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.notes$', nf)
        if m is not None:
            if m.group(1) not in noteshost:
                noteshost[m.group(1)] = {}
            noteshost[m.group(1)][m.group(2)] = open('/opt/notes/' + nf, 'r').read()

    # collect all cve in cvehost dict
    cvehost = get_cve(scanmd5)

    hostsup = 0
    hostindex = 1
    ports = {'open': 0, 'closed': 0, 'filtered': 0}
    allostypelist, sscount, picount, cpe = {}, {}, {}, {}

    r['tr'] = {}
    r['stats'] = {}

    for ik in o['host']:

        # this fix single host report
        if type(ik) is dict:
            i = ik
        else:
            i = o['host']

        hostname = ''
        info_hostnames = '<sup style="font-size: 70%; position: relative; top: 0.2em; left: -0.3em;"> <span class="material-icons" style="font-size: inherit;">question_mark</span></sup>'
        if 'hostnames' in i and type(i['hostnames']) is dict:
            if 'hostname' in i['hostnames']:
                if type(i['hostnames']['hostname']) is list:
                    for hi in i['hostnames']['hostname']:
                        hostname += '<div class="small grey-text"><b><span title="DNS pointer record">' + hi[
                            '@type'] + info_hostnames + '&#8594; </span></b> ' + hi['@name'] + '</div>'
                else:
                    hostname += '<div class="small grey-text"><b><span title="DNS pointer record">' + \
                                i['hostnames']['hostname']['@type'] + info_hostnames + '&#8594; </span></b>' + \
                                i['hostnames']['hostname']['@name'] + '</div>'

        po, pc, pf = 0, 0, 0
        ss, pp, ost = {}, {}, {}
        lastportid = 0

        if '@addr' in i['address']:
            address = i['address']['@addr']
        elif type(i['address']) is list:
            for ai in i['address']:
                if ai['@addrtype'] == 'ipv4':
                    address = ai['@addr']

        vendor = ""
        mac_address = ""
        if '@vendor' in i['address']:
            try:
                vendor = i['address']['@vendor']
            except KeyError:
                pass
            mac_address = i['address']['@addr']
        elif type(i['address']) is list:
            for ai in i['address']:
                if ai['@addrtype'] == 'mac':
                    try:
                        vendor = ai['@vendor']
                    except KeyError:
                        pass
                    mac_address = ai['@addr']

        if vendor == "" and mac_address == "":
            vendor = 'unknown'

        if vendor == "":
            vendor = f'<a href="https://maclookup.app/search/result?mac={urllib.parse.quote(mac_address)}" style="color: #9e9e9e; text-decoration: none;">{mac_address}<sup style="font-size: 70%; position: relative; top: -0.9em;"><span class="material-icons" style="font-size: 12px; vertical-align: middle;">info</span></sup></a>'

        addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

        if i['status']['@state'] == 'up':
            if address not in cpe:
                hostsup = (hostsup + 1)

                r['tr'][address] = {
                    'hostindex': '',
                    'hostname': hostname,
                    'po': 0,
                    'pc': 0,
                    'pf': 0,
                    'totports': str(0),
                    'addressmd5': addressmd5
                }

        cpe[address] = {}

        striggered = False
        e = ''
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
                    if filterservice != "" and p['service']['@name'] == filterservice:
                        striggered = True

                    if filterportid != "" and p['@portid'] == filterportid:
                        striggered = True

                pp[p['@portid']] = p['@portid']

                if 'service' in p:
                    ss[p['service']['@name']] = p['service']['@name']

                    if '@extrainfo' in p['service']:
                        e = p['service']['@extrainfo']

                    # cpehtml = ''
                    if 'cpe' in p['service']:
                        if type(p['service']['cpe']) is list:
                            for cpei in p['service']['cpe']:
                                cpe[address][cpei] = cpei
                        else:
                            cpe[address][p['service']['cpe']] = p['service']['cpe']

                    if '@ostype' in p['service']:
                        if p['service']['@ostype'] in allostypelist:
                            allostypelist[p['service']['@ostype']] = (allostypelist[p['service']['@ostype']] + 1)
                        else:
                            allostypelist[p['service']['@ostype']] = 1;

                        ost[p['service']['@ostype']] = p['service']['@ostype']

                    if p['service']['@name'] in sscount:
                        sscount[p['service']['@name']] = (sscount[p['service']['@name']] + 1)
                    else:
                        sscount[p['service']['@name']] = 1

                if p['@portid'] in picount:
                    picount[p['@portid']] = (picount[p['@portid']] + 1)
                else:
                    picount[p['@portid']] = 1

                if p['state']['@state'] == 'closed':
                    ports['closed'] = (ports['closed'] + 1)
                    pc = (pc + 1)
                elif p['state']['@state'] == 'open':
                    ports['open'] = (ports['open'] + 1)
                    po = (po + 1)
                elif p['state']['@state'] == 'filtered':
                    ports['filtered'] = (ports['filtered'] + 1)
                    pf = (pf + 1)

            services = ''
            service_counter = 0
            for s in ss:
                if filterservice != ss[s]:
                    services += '<a href="/report/service/' + ss[s] + '/">' + ss[s] + '</a>, '
                else:
                    services += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">' + ss[
                        s] + '</span>, '
                service_counter += 1

            ostype = ''
            for oty in ost:
                ostype += '<i class="' + fromOSTypeToFontAwesome(
                    html.escape(ost[oty])) + '"></i> <span class="grey-text small">' + ost[oty].lower() + '</span> '

            tdports = ''
            for kp in pp:
                if filterportid != pp[kp]:
                    tdports += '<a href="/report/portid/' + pp[kp] + '/">' + pp[kp] + '</a>, '
                else:
                    tdports += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">' + pp[
                        kp] + '</span>, '

            poclass = ''
            if po == 0:
                poclass = 'zeroportopen'

            labelout = '<span id="hostlabel' + str(hostindex) + '"></span>'
            newlabelout = '<div id="hostlabel' + str(hostindex) + '"></div><div id="hostlabelbb' + str(
                hostindex) + '"></div>'
            if scanmd5 in labelhost:
                if addressmd5 in labelhost[scanmd5]:
                    labelcolor = labelToColor(labelhost[scanmd5][addressmd5])
                    labelmargin = labelToMargin(labelhost[scanmd5][addressmd5])
                    labelout = '<span id="hostlabel' + str(
                        hostindex) + '" style="margin-left:' + labelmargin + '" class="rightlabel ' + labelcolor + '">' + html.escape(
                        labelhost[scanmd5][addressmd5]) + '</span>'
                    newlabelout = '<div id="hostlabel' + str(
                        hostindex) + '" style="z-index:99;transform: rotate(-8deg);margin-top:-14px;margin-left:-40px;" class="leftlabel ' + labelcolor + '">' + html.escape(
                        labelhost[scanmd5][addressmd5]) + '</div>' + \
                                  '<div id="hostlabelbb' + str(
                        hostindex) + '" class="' + labelcolor + '" style="border-radius:0px 4px 0px 4px;z-index:98;position:absolute;width:18px;height:10px;margin-left:-54px;margin-top:-3px;"></div>'

            notesout, notesb64, removenotes = '', '', ''
            if scanmd5 in noteshost:
                if addressmd5 in noteshost[scanmd5]:
                    notesb64 = noteshost[scanmd5][addressmd5]
                    notesout = '<a id="noteshost' + str(hostindex) + '" class="grey-text" href="#!" onclick="javascript:openNotes(\'' + hashlib.md5(
                        str(address).encode('utf-8')).hexdigest() + '\', \'' + notesb64 + '\');"><i class="fas fa-comment"></i> contains notes</a>'
                    removenotes = '<li><a href="#!" class="grey-text" onclick="javascript:removeNotes(\'' + addressmd5 + '\', \'' + str(
                        hostindex) + '\');">Remove notes</a></li>'

            cveout = ''
            cvecount = 0
            if scanmd5 in cvehost:
                if addressmd5 in cvehost[scanmd5]:
                    cvejson = json.loads(cvehost[scanmd5][addressmd5])
                    for ic in cvejson:
                        if type(ic) is list:
                            listcve = ic
                        elif type(ic) is dict:
                            listcve = [ic]

                        for cvei in listcve:
                            if 'id' in cvei:
                                cvecount = (cvecount + 1)

                    if cvecount > 0:
                        cveout = '<a href="/report/' + address + '" class="grey-text"><i class="fas fa-bug"></i> ' + str(
                            cvecount) + ' CVE found</a>'

            service_action = ''
            if service_counter > 0:
                device_services = list(ss.keys())
                # any(specified_string in item for item in string_list)
                if any("ssh" in item for item in device_services):
                    service_action += '<a href="/report/' + address + '" class="grey-text"><i class="material-icons">call_to_action</i> Bruteforce SSH</a>'
                if any("http" in item for item in device_services):
                    service_action += '<a href="/report/' + address + '" class="grey-text"><i class="material-icons">web</i> Bruteforce Web-Server</a>'


            if (filterservice != "" and striggered is True) or (filterportid != "" and striggered is True) or (
                    filterservice == "" and filterportid == ""):
                portstateout = '<div style="overflow:none;background-color:#444;" class="tooltipped" data-position="top" data-tooltip="' + str(
                    po) + ' open, ' + str(pc) + ' closed, ' + str(pf) + ' filtered">' + \
                               '		<div class="perco" data-po="' + str(
                    po) + '" style="padding-left:16px;padding-right:20px;"><b>' + str(po) + '</b></div>' + \
                               ' </div>'

                if (filterservice != "" and striggered is True):
                    portstateout = '<div style="overflow:none;background-color:#444;" class="tooltipped" data-position="top" data-tooltip="' + str(
                        po) + ' open, ' + str(pc) + ' closed, ' + str(pf) + ' filtered">' + \
                                   '		<div class="perco" data-po="' + str(po) + '" data-pt="' + str(
                        (po + pf + pc)) + '" style="padding-left:16px;padding-right:20px;"><b>' + str(
                        po) + '</b></div>' + \
                                   '	</div>'

                tags = []
                extrainfosplit = e.split(' ')
                for eis in extrainfosplit:
                    if re.search('[a-zA-Z0-9\_]+\/[0-9\.]+', eis) is not None:
                        robj = re.search('([a-zA-Z0-9\_]+)\/([0-9\.]+)', eis)
                        tags.append(robj.group(1) + ' ' + robj.group(2))

                r['tr'][address] = {
                    'hostindex': str(hostindex),
                    'hostname': hostname,
                    'ostype': ostype,
                    'notes': notesout,
                    'cve': cveout,
                    'portstate': portstateout,
                    'po': po,
                    'pc': pc,
                    'pf': pf,
                    'tags': tags,
                    'totports': str((po + pf + pc)),
                    'services': str(services[0:-2]),
                    'ports': str(tdports[0:-2]),
                    'addressmd5': addressmd5,
                    'removenotes': removenotes,
                    'labelout': labelout,
                    'newlabelout': newlabelout,
                    'notesb64': notesb64,
                    'notesout': notesout,
                    'cveout': cveout,
                    'cvecount': cvecount,
                    'serviceaction': service_action,
                    'vendor': vendor
                }


                hostindex = (hostindex + 1)

                # this fix single host report
                if type(ik) is not dict:
                    break
            else:
                if address in r['tr']:
                    del r['tr'][address]
        else:
            if address in r['tr']:
                del r['tr'][address]

    totports = (ports['open'] + ports['closed'] + ports['filtered'])
    if filterservice == "" and filterportid == "":
        scaninfobox2 = '<canvas id="chart1"></canvas>'
        scaninfobox3 = '<canvas id="chart3" height="150"></canvas>'
    else:
        scaninfobox2 = '<div class="small">' + \
                       '	<b class="orange-text">Filter port / service:</b> <b>' + html.escape(
            filterportid + filterservice) + '</b> <a href="/"><i class="fas fa-trash-alt"></i></a><br>' + \
                       '	<b class="orange-text">Total Ports:</b> ' + str(totports) + '<br>' + \
                       '	<b class="orange-text">Open Ports:</b> ' + str(ports['open']) + '<br>' + \
                       '	<b class="orange-text">Closed Ports:</b> ' + str(ports['closed']) + '<br>' + \
                       '	<b class="orange-text">Filtered Ports:</b> ' + str(ports['filtered']) + '</div>'
        scaninfobox3 = '<div id="detailstopports"></div>'

    scantype = ''
    if 'scaninfo' in o and '@type' in o['scaninfo']:
        scantype = o['scaninfo']['@type']

    if 'scaninfo' in o and type(o['scaninfo']) is list:
        for sinfo in o['scaninfo']:
            scantype += sinfo['@type'] + ', '
        scantype = scantype[0:-2]

    protocol = ''
    if 'scaninfo' in o and '@protocol' in o['scaninfo']:
        protocol = o['scaninfo']['@protocol']

    if 'scaninfo' in o and type(o['scaninfo']) is list:
        for sinfo in o['scaninfo']:
            protocol += sinfo['@protocol'] + ', '
        protocol = protocol[0:-2]

    numservices = ''
    if 'scaninfo' in o and '@numservices' in o['scaninfo']:
        numservices = o['scaninfo']['@numservices']

    verbose, debugging = '', ''
    if 'verbose' in o and '@level' in o['verbose']:
        verbose = o['verbose']['@level']

    if 'debugging' in o and '@level' in o['debugging']:
        debugging = o['debugging']['@level']

    r['stats'] = {
        'filename': r['scanfile'],
        'startstr': html.escape(datetime.fromtimestamp(int(o['@start'])).strftime('%A, %d. %B %Y - %H:%M:%S')),
        # o['@startstr'],
        'scantype': scantype,
        'protocol': protocol,
        'verbose': verbose,
        'debugging': debugging,
        'numservices': numservices,
        'nmapver': o['@version'],
        'nmapargs': insert_linebreaks(o['@args']), # o['@args'],
        'xmlver': o['@xmloutputversion'],
        'hostsup': str(hostsup),
        'popen': ports['open'],
        'pclosed': ports['closed'],
        'pfiltered': ports['filtered']
    }

    allss = ''
    allsslabels = ''
    allssdata = ''
    allssc = 0
    for i in sorted(sscount, key=sscount.__getitem__, reverse=True):
        if allssc <= 30:
            if filterservice != i:
                allss += '<a href="/report/service/' + html.escape(i) + '/">' + html.escape(i) + '(' + str(
                    sscount[i]) + ')</a>, '
            else:
                allss += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">' + html.escape(
                    i) + '</span>, '

            allsslabels += '"' + html.escape(i) + '", '
            allssdata += '' + str(sscount[i]) + ','
            allssc = (allssc + 1)

    allpilabels = ''
    allpidata = ''
    allpilinks = ''
    allpic = 1
    for i in sorted(picount, key=picount.__getitem__, reverse=True):
        if allpic <= 5:
            allpilinks += '<a href="/report/portid/' + str(i) + '/">' + str(i) + '</a>, '
            allpilabels += '"' + html.escape(i) + '", '
            allpidata += '' + str(picount[i]) + ','
            allpic = (allpic + 1)
        elif allpic > 5 and allpic <= 10:
            allpilinks += '<a href="/report/portid/' + str(i) + '/">' + str(i) + '</a>, '
            allpic = (allpic + 1)

    allostypelinks = ''
    for i in sorted(allostypelist, key=allostypelist.__getitem__, reverse=True):
        allostypelinks += '<a href="">' + str(i) + '</a>, '

    r['stats']['services'] = allss[0:-2]
    r['stats']['portids'] = allpilinks[0:-2]
    r['stats']['ostypes'] = allostypelinks[0:-2]

    r['pretable'] = ''
    r['js'] = ''
    if filterservice == "" and filterportid == "":
        r['js'] += '<script>' + \
                   '	$(document).ready(function() {' + \
                   '		var ctx = document.getElementById("chart1").getContext("2d");' + \
                   '		var myChart = new Chart(ctx, {' + \
                   '			type: "doughnut", data: {labels:["Open", "Filtered", "Closed"], datasets: [{ data: [' + str(
            ports['open']) + ',' + str(ports['filtered']) + ',' + str(ports[
                                                                          'closed']) + '], backgroundColor:["rgba(0,150,0,0.8)","rgba(255,200,0,0.8)","rgba(255,0,0,0.8)"], borderColor:"#ccc", borderWidth:0 }]}, options: {legend: { position: "right", labels: { fontColor: "#ccc" }  }}' + \
                   '		});' + \
                   '		var ctx = document.getElementById("chart3").getContext("2d");' + \
                   '		var myChart = new Chart(ctx, {' + \
                   '			type: "doughnut", data: {labels:[' + allpilabels[
                                                                     0:-2] + '], datasets: [{ data: [' + allpidata[
                                                                                                         0:-1] + '], borderColor: "#fff", borderWidth:0,  backgroundColor:["#e6194b", "#3cb44b", "#ffe119", "#4363d8", "#f58231", "#911eb4", "#46f0f0", "#f032e6", "#bcf60c", "#fabebe", "#008080", "#e6beff", "#9a6324", "#fffac8", "#800000", "#aaffc3", "#808000", "#ffd8b1", "#000075", "#808080", "#ffffff", "#000000"] }]}, options: {legend: { position: "right", labels: { fontColor: "#ccc" }}}' + \
                   '		});' + \
                   '		var ctx = document.getElementById("chart2").getContext("2d");' + \
                   '		var myChart = new Chart(ctx, {' + \
                   '			type: "horizontalBar", data: { labels:[' + allsslabels[
                                                                           0:-2] + '], datasets: [{ data: [' + allssdata[
                                                                                                               0:-1] + '], backgroundColor: "rgba(0,140,220,0.8)" }]}, options: {legend: { display: false }, scales: { xAxes: [{ ticks: { beginAtZero: true, fontColor: "#666" } }], yAxes: [{ ticks: { fontColor: "#666" } }] }  }' + \
                   '		});' + \
                   '	});' + \
                   '</script>'
    else:
        r['pretablestyle'] = 'display:none;'

    r['js'] += '<script>' + \
               '	$(document).ready(function() {' + \
               '		/* $("#scantitle").html("' + html.escape(request.session['scanfile']) + '"); */ ' + \
               '		$(".dropdown-trigger").dropdown();' + \
               '		$(".tooltipped").tooltip();' + \
               '		$(".perco").each(function() { ' + \
               '			var pwidth = ( (($(this).attr("data-po") * 100) / ' + str(totports) + ') ); ' + \
               '			/* console.log(pwidth); */ ' + \
               '			$(this).css("width", pwidth+"%" ); ' + \
               '			if($(this).attr("data-po") < 1) { $(this).html("&nbsp;"); $(this).css("background-color","#666") } ' + \
               '		});' + \
               '	$("#detailstopports").html(\'<span class="small">' + str(allss[0:-2]) + '</span>\');' + \
               '	});' + \
               '</script>'

    cpedict = {}
    # r['cpestring'] = ''
    for cpeaddr in cpe:
        for cpei in cpe[cpeaddr]:
            if re.search('^cpe:.+:.+:.+:.+$', cpei) is not None:
                # r['cpestring'] += cpei+'<br>'
                if cpei not in cpedict:
                    cpedict[cpei] = {}
                if cpeaddr not in cpedict[cpei]:
                    cpedict[cpei][cpeaddr] = 1

    r['cpestring'] = ' <input type="hidden" id="cpestring" value="' + urllib.parse.quote_plus(
        base64.b64encode(json.dumps(cpedict).encode())) + '" /> '

    return render(request, 'proteciotnet_dev/nmap_device_overview.html', r)


def about(request):
    r = {'auth': True}
    return render(request, 'proteciotnet_dev/nmap_about.html', r)
