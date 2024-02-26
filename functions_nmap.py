import hashlib
import json
import os
import re
import time
import logging
import subprocess

from django.http import HttpResponse
from configparser import ConfigParser, ExtendedInterpolation

logger = logging.getLogger(__name__)

try:
    config_functions_nmap = ConfigParser(interpolation=ExtendedInterpolation())
    config_functions_nmap.read('proteciotnet.config')
    _BASE_DIRECTORY = config_functions_nmap.get('GENERAL_PATHS', 'base_directory')
    _NSE_SCRIPTS_DIRECTORY = config_functions_nmap.get('WIFI_PATHS', 'nse_scripts_directory')
    _PROTECIOTNET_NMAP_SCHEDULE_DIRECTORY = config_functions_nmap.get('WIFI_PATHS', 'proteciotnet_nmap_schedule_directory')
    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e}")
    exit(-3)

# PROTECIOTNET_BASE_DIR = '/opt/proteciotnet/proteciotnet_dev/'
# NSE_SCRIPT_DIR = f"{PROTECIOTNET_BASE_DIR}nmap/nse"


def nmap_newscan(request) -> HttpResponse:
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

            logger.info("new nmap scan")
            logger.debug(f"filename: {filename}")
            logger.debug(f"target: {target}")

            command = ["nmap"]

            args = request.POST.get('args')
            if args:
                args = json.loads(args)
            else:
                args = {}

            logger.debug(f"args: {args}")

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
                command.append(f"--script {args.get('option-script')},{_NSE_SCRIPTS_DIRECTORY}")
            elif args.get('option-script', ''):
                command.append(f"--script {args.get('option-script')}")
            elif args.get('option-local-script', ''):
                command.append(f"--script {_NSE_SCRIPTS_DIRECTORY}")

            if args.get("option-free", ""):
                command.append(f"{args.get('option-free')}")

            command.append(f"-oX /tmp/{filename}.active")
            command.append(target)

            nmap_command = ' '.join(command)
            nmap_command += ' > /dev/null 2>&1 && '
            nmap_command += 'sleep 10 && '
            nmap_command += 'mv /tmp/' + request.POST['filename'] + '.active /opt/xml/' + request.POST['filename']
            nmap_command += ' &'

            logger.info(f"Running nmap with command: {nmap_command}")

            #os.popen(nmap_command)

            try:
                process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()

                logger.debug(f"stdout: {stdout}")
                logger.debug(f"stderr: {stderr}")

                # Check if "QUITTING" is in stdout or stderr
                if "QUITTING" in stdout.decode() or "QUITTING" in stderr.decode():
                    logger.error("nmap command did not run, because of incompatible options or bad command")
                    res = {'error2': stdout.decode()}
                    return HttpResponse(json.dumps(res, indent=4), content_type="application/json")

                time.sleep(10)
                # Proceed with the rest of your logic, for example, moving the file
                os.rename('/tmp/my_scan.xml.active', '/opt/xml/my_scan.xml')

                logger.info(f"nmap successfully ran")

            except Exception as e:
                logger.error(f"There was an error running nmap with command: {nmap_command}\n\nException: {e}")
                res = {'error': str(e)}
                return HttpResponse(json.dumps(res, indent=4), content_type="application/json")

            if args.get('schedule', '') == "true":
                logger.info(f"Scheduled nmap run")
                schedobj = {'params': request.POST, 'lastrun': time.time(), 'number': 0}
                filenamemd5 = hashlib.md5(str(request.POST['filename']).encode('utf-8')).hexdigest()
                writefile = f'{_PROTECIOTNET_NMAP_SCHEDULE_DIRECTORY}/{filenamemd5}.json'

                with open(writefile, "w") as file:
                    file.write(json.dumps(schedobj, indent=4))

                logger.info(f"Scheduled nmap run. Filename: {writefile} ")

            return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
        else:
            logger.error(f"There was an error running nmap. Invalid syntax for request.")
            res = {'error': 'invalid syntax'}
            return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
