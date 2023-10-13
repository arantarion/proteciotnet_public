import json
import os.path

_BASE_BLE_DIR = "/opt/ble/"
_BASE_STATIC_BLE_DIR = "/opt/proteciotnet/proteciotnet_dev/static/ble_reports/"


def zigbee(request):
    r = {'auth': True}

    with open(f"{_BASE_BLE_DIR}{request.session['scanfile']}", "r", encoding='utf-8') as f:
        json_input = json.load(f)

    # scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    # addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

    bl_capture_filename = request.session['scanfile']


    r['filename'] = bl_capture_filename
    r['js'] += '<script>' + \
               '	$(document).ready(function() {' + \
               '		/* $("#scantitle").html("' + bl_capture_filename + '"); */ ' + \
               '		$(".dropdown-trigger").dropdown();' + \
               '		$(".tooltipped").tooltip();' + \
               '	});' + \
               '</script>'

    return r
