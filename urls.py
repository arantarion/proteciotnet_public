from django.urls import path

from . import views, api, pdf, functions_nmap, functions, view_zigbee, functions_zigbee, functions_ble, view_ble


urlpatterns = [
    path('', views.index, name='index'),

    path('view/login/', views.user_login, name='login'),

    path('setscanfile/<scanfile>', views.setscanfile, name='setscanfile'),
    path('set_online_state', functions.set_state, name='offline_mode'),
    path('about/', views.about, name="about"),
    path('api/v1/delete_file', api.delete_file, name="delete_file"),

    path('api/v1/nmap/scan/new', functions_nmap.nmap_newscan, name='apiv1_scan_new'),
    path('api/v1/bruteforce', api.bruteforce, name="bruteforce"),
    path('api/v1/create_report', pdf.create_report, name='create_report'),
    path('api/setlabel/<objtype>/<label>/<hashstr>/', api.label, name='api_label'),
    path('api/rmlabel/<objtype>/<hashstr>/', api.rmlabel, name='api_rmlabel'),
    path('api/getcve/', api.getCVE, name='getCVE'),
    path('api/savenotes/', api.saveNotes, name='genPDF'),
    path('api/rmnotes/<hashstr>/', api.rmNotes, name='api_rmnotes'),
    path('api/<address>/<portid>/', api.port_details, name='api_port'),
    path('api/v1/scan/<scanfile>/<faddress>', api.apiv1_hostdetails, name='apiv1_hostdetails'),
    path('api/v1/scan/<scanfile>', api.apiv1_hostdetails, name='apiv1_hostdetails'),
    path('api/v1/scan', api.apiv1_scan, name='apiv1_scan'),
    path('<address>/', views.details, name='details'),
    path('<address>/<sorting>', views.details, name='details2'),
    path('port/<port>/', views.port, name='port'),
    path('service/<filterservice>/', views.index, name='service'),
    path('portid/<filterportid>/', views.index, name='portid'),

    path('api/v1/zigbee/scan/new', functions_zigbee.new_zigbee_scan, name='apiv1_scan_zigbee_new'),
    path('zigbee/', view_zigbee.zigbee, name="zigbee"),
    path('api/v1/create_zigbee_report', pdf.create_zigbee_report, name="zigbee_report"),

    path('api/v1/ble/scan/new', functions_ble.new_ble_scan, name='apiv1_scan_ble_new'),
    path('ble_report/<address>', view_ble.ble_details, name="ble_details"),
]

# path('api/v1/nmap/scan/active', functions_nmap.nmap_scaninfo, name='apiv1_scan_active'),
# path('api/pdf/', api.genPDF, name='genPDF'),
# path('view/login/', views.login, name='login'),
# path('view/pdf/', pdf.report_pdf_view, name='reportPDFView'),
