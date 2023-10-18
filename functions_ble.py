import json

from django.http import HttpResponse


def new_ble_scan(request):
    """
    Initiates a new BLE scan based on parameters from a POST request.

    Parameters:
    - request (HttpRequest): The HTTP request object containing POST data.

    Returns:
    - HttpResponse: A JSON-formatted HTTP response indicating either the POST data or an error message.
    """

    if request.method == "POST":
        filename = request.POST.get("zb_filename", "")
        _ = request.POST.get("zb_interface", "")
        _ = request.POST.get("zb_channel", "")
        _ = request.POST.get("zb_pcap_path", "")

    else:
        return HttpResponse(json.dumps({'error': 'invalid syntax'}, indent=4), content_type="application/json")
