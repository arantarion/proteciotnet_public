import hashlib
import json
import os
import re
import time
import subprocess

from django.conf import settings
from django.http import HttpResponse

PROTECIOTNET_BASE_DIR = '/opt/proteciotnet/proteciotnet_dev/'
NSE_SCRIPT_DIR = f"{PROTECIOTNET_BASE_DIR}nmap/nse"


def nmap_newscan(request):
    """
    Initiates a new Nmap scan based on parameters from a POST request.

    Parameters:
    - request (HttpRequest): The HTTP request object containing POST data.

    Returns:
    - HttpResponse: A JSON-formatted HTTP response indicating either the POST data or an error message.
    """

    if request.method == "POST":
        if (re.search('^[a-zA-Z0-9\_\-\.]+$', request.POST['filename']) and
                re.search('^[a-zA-Z0-9\-\.\:\/\s]+$', request.POST['target'])):

            res = {'p': request.POST}

            filename = request.POST['filename']
            target = request.POST['target']

            command = ["nmap"]

            args = request.POST.get('args')
            if args:
                args = json.loads(args)
            else:
                args = {}

            flags = [
                ('option-A', '-A'),
                ('option-sV', '-sV'),
                ('option-sC', '-sC'),
                ('option-O', '-O'),
                ('option-Pn', '-Pn'),
                ('option-sS', '-sS'),
                ('option-sT', '-sT'),
                ('option-sA', '-sA'),
                ('option-sW', '-sW'),
                ('option-sM', '-sM'),
                ('option-sU', '-sU'),
                ('option-F', '-F'),
                ('option-open', '--open'),
            ]

            for key, flag in flags:
                if args.get(key, False):
                    command.append(flag)

            value_options = [
                ('option-p', '-p'),
                ('option-e', '-e'),
                ('option-T', '-T'),
                ('option-webxml', '--webxml'),
            ]

            for key, option in value_options:
                value = args.get(key, '').strip()
                if value:
                    command.append(f"{option} {value}")

            if args.get('option-d', ''):
                command.append(f"-d{args.get('option-d')}")

            if args.get('option-v', ''):
                command.append(f"-v{args.get('option-v')}")

            if args.get('option-local-script', '') and args.get('option-script', ''):
                command.append(f"--script {args.get('option-script')},{NSE_SCRIPT_DIR}")
            elif args.get('option-script', ''):
                command.append(f"--script {args.get('option-script')}")
            elif args.get('option-local-script', ''):
                command.append(f"--script {NSE_SCRIPT_DIR}")

            command.append(f"-oX /tmp/{filename}.active")
            command.append(target)

            nmap_command = ' '.join(command)



            # nmap_command = "nmap "
            # nmap_command += request.POST["params"]
            # nmap_command += ' --script=' + settings.BASE_DIR + '/proteciotnet_dev/nmap/nse/ '
            # nmap_command += '-oX /tmp/' + request.POST["filename"] + '.active '
            # nmap_command += request.POST['target'] + ' > /dev/null 2>&1 && '
            nmap_command += ' > /dev/null 2>&1 && '
            nmap_command += 'sleep 10 && '
            nmap_command += 'mv /tmp/' + request.POST['filename'] + '.active /opt/xml/' + request.POST['filename']
            nmap_command += ' &'

            nmap_command = 'nmap -A -sT -F --open -p 30-50 -e wlan0 -T 4 -d1 -v2 --script True -oX /tmp/my_scan.xml.active localhost && sleep 10 && mv /tmp/my_scan.xml.active /opt/xml/my_scan.xml &'

            #os.popen(nmap_command)

            try:
                process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()

                # Check if "QUITTING" is in stdout or stderr
                if "QUITTING" in stdout.decode() or "QUITTING" in stderr.decode():
                    res = {'error2': stdout.decode()}
                    return HttpResponse(json.dumps(res, indent=4), content_type="application/json")

                time.sleep(10)
                # Proceed with the rest of your logic, for example, moving the file
                os.rename('/tmp/my_scan.xml.active', '/opt/xml/my_scan.xml')

            except Exception as e:
                # Handle any exceptions that occur
                res = {'error': str(e)}
                return HttpResponse(json.dumps(res, indent=4), content_type="application/json")

            # os.popen('nmap ' + request.POST[
            #     'params'] + ' --script=' + settings.BASE_DIR + '/proteciotnet_dev/nmap/nse/ -oX /tmp/' + request.POST[
            #              'filename'] + '.active ' + request.POST['target'] + ' > /dev/null 2>&1 && ' +
            #          'sleep 10 && mv /tmp/' + request.POST['filename'] + '.active /opt/xml/' + request.POST[
            #              'filename'] + ' &')

            if args.get('schedule', '') == "true":
                schedobj = {'params': request.POST, 'lastrun': time.time(), 'number': 0}
                filenamemd5 = hashlib.md5(str(request.POST['filename']).encode('utf-8')).hexdigest()
                writefile = f'{settings.BASE_DIR}/proteciotnet_dev/nmap/schedule/{filenamemd5}.json'

                # file = open(writefile, "w")
                # file.write(json.dumps(schedobj, indent=4))

                with open(writefile, "w") as file:
                    file.write(json.dumps(schedobj, indent=4))

            return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
        else:
            res = {'error': 'invalid syntax'}
            return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
