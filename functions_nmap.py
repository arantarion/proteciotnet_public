import hashlib
import json
import os
import re
import time

from django.conf import settings
from django.http import HttpResponse


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
                re.search('^[a-zA-Z0-9\-\.\:\=\s,]+$', request.POST['params']) and
                re.search('^[a-zA-Z0-9\-\.\:\/\s]+$', request.POST['target'])):

            res = {'p': request.POST}

            nmap_command = "nmap "
            nmap_command += request.POST["params"]
            nmap_command += ' --script=' + settings.BASE_DIR + '/proteciotnet_dev/nmap/nse/ '
            nmap_command += '-oX /tmp/' + request.POST["filename"] + '.active '
            nmap_command += request.POST['target'] + ' > /dev/null 2>&1 && '
            nmap_command += 'sleep 10 && '
            nmap_command += 'mv /tmp/' + request.POST['filename'] + '.active /opt/xml/' + request.POST['filename']
            nmap_command += ' &'

            os.popen(nmap_command)

            # os.popen('nmap ' + request.POST[
            #     'params'] + ' --script=' + settings.BASE_DIR + '/proteciotnet_dev/nmap/nse/ -oX /tmp/' + request.POST[
            #              'filename'] + '.active ' + request.POST['target'] + ' > /dev/null 2>&1 && ' +
            #          'sleep 10 && mv /tmp/' + request.POST['filename'] + '.active /opt/xml/' + request.POST[
            #              'filename'] + ' &')

            if request.POST['schedule'] == "true":
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
