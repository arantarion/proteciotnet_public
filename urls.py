from django.urls import path

from . import views, api, pdf, functions_nmap, functions, view_zigbee


urlpatterns = [
    path('', views.index, name='index'),
    path('setscanfile/<scanfile>', views.setscanfile, name='setscanfile'),
    path('<address>/', views.details, name='details'),
    path('<address>/<sorting>', views.details, name='details2'),
    path('port/<port>/', views.port, name='port'),
    path('service/<filterservice>/', views.index, name='service'),
    path('portid/<filterportid>/', views.index, name='portid'),
    path('api/v1/scan/<scanfile>/<faddress>', api.apiv1_hostdetails, name='apiv1_hostdetails'),
    path('api/v1/scan/<scanfile>', api.apiv1_hostdetails, name='apiv1_hostdetails'),
    path('api/v1/scan', api.apiv1_scan, name='apiv1_scan'),
    # path('api/v1/nmap/scan/active', functions_nmap.nmap_scaninfo, name='apiv1_scan_active'),
    path('api/v1/nmap/scan/new', functions_nmap.nmap_newscan, name='apiv1_scan_new'),
    path('set_online_state', functions.set_state, name='offline_mode'),
    path('api/setlabel/<objtype>/<label>/<hashstr>/', api.label, name='api_label'),
    path('api/rmlabel/<objtype>/<hashstr>/', api.rmlabel, name='api_rmlabel'),
    # path('api/pdf/', api.genPDF, name='genPDF'),
    path('api/getcve/', api.getCVE, name='getCVE'),
    path('api/savenotes/', api.saveNotes, name='genPDF'),
    path('api/rmnotes/<hashstr>/', api.rmNotes, name='api_rmnotes'),
    path('api/<address>/<portid>/', api.port_details, name='api_port'),
    # path('view/login/', views.login, name='login'),
    # path('view/pdf/', pdf.report_pdf_view, name='reportPDFView'),
    path('api/v1/create_report', pdf.create_report, name='create_report'),
    path('api/v1/delete_file', api.delete_file, name="delete_file"),
    path('api/v1/bruteforce', api.bruteforce, name="bruteforce"),
    path('about/', views.about, name="about"),
    path('zigbee/', view_zigbee.zigbee, name="zigbee"),
]
