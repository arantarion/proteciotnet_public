//var active_scan_timer;
var wmover = false;
var wmopen = false;
var navbarvisible = false;
$(document).ready(function () {
    // doc ready

    $(document).scroll(function () {
        // console.log($(this).scrollTop());
        if ($(this).scrollTop() > 10) {
            if (!navbarvisible) {
                navbarvisible = true;
                $('#topnavbar').css('background-color', 'rgba(10,10,10,0.9)');
                $('#topnavbar').css('box-shadow', '4px 4px 6px #000');
            }
        }

        if ($(this).scrollTop() <= 10) {
            if (navbarvisible) {
                navbarvisible = false;
                $('#topnavbar').css('background-color', 'rgba(10,10,10,0.2)');
                $('#topnavbar').css('box-shadow', 'none');
            }
        }
    });

    //active_scan_timer = setInterval(function() { checkActiveScan(); }, 2000);
    //$('select').formSelect();

    var wminterval = setInterval(function () {
        if (!wmover) {
            $('.wm_menu').animate({
                width: '44px'
            }, {
                queue: false,
                start: function () {
                    $('.wm_menu > ul > li > a').each(function () {
                        $(this).css('display', 'none');
                    });
                    $('.wm_menu > ul > section > li > a').each(function () {
                        $(this).css('display', 'none');
                    });
                },
                done: function () {
                    wmopen = false;
                    $('.wm_menu').scrollTop(0);
                    $('.wm_menu').css('overflow-y', 'hidden');
                }
            });
        }
    }, 2000);

    $('.wm_menu').css('height', ($(window).height() - 120) + 'px');

    $('.wm_menu').click(function () {
        wmover = true;
        wmopen = true;

        $(this).animate({
            width: '240px'
        }, {
            queue: false,
            done: function () {
                $('.wm_menu > ul > li > a').each(function () {
                    $(this).stop().show();
                });
                $('.wm_menu > ul > section > li > a').each(function () {
                    $(this).stop().show();
                });
                $('.wm_menu').css('overflow-y', 'scroll');
            }
        });
    });

    $('.wm_menu').mouseover(function () {
        wmover = true;
        if (!wmopen) {
            $(this).stop().animate({width: '60px'}, {duration: 50});
        }
    });

    $('.wm_menu').mouseout(function () {
        if (wmover) {
            wmover = false;
        }
        if (!wmopen) {
            $(this).stop().animate({width: '44px'}, {duration: 200});
        }
    });

});

function checkActiveScan() {
    $.get('/api/v1/nmap/scan/active').done(function (d) {
        // console.log(d);
        $('#activescan_info').html('');
        var c = 0;
        for (i in d['scans']) {
            c = (c + 1);
            if (d['scans'][i]['status'] == 'active') {

                $('#activescan_line').css('display', 'block');
                $('#activescan_info').css('display', 'block');
                $('#activescan_progress').css('display', 'block');
                $('#activescan_info').append('<li>' +
                    '<i class="fas fa-info-circle"></i> ' +
                    '<a href="#!">' + i + '</a>' +
                    '</li>' +
                    '<li>' +
                    '<i class="material-icons">keyboard_arrow_right</i> ' +
                    '<a href="#!">' + d['scans'][i]['startstr'] + '</a>' +
                    '</li>' +
                    '<li>' +
                    '<i class="material-icons">keyboard_arrow_right</i> ' +
                    '<a href="#!">' + d['scans'][i]['type'] + ' ' + d['scans'][i]['protocol'] + '</a>' +
                    '</li>');

                if (wmover && wmopen) {
                    $('.wm_menu > ul > li > a').each(function () {
                        $(this).stop().show();
                    });
                    $('.wm_menu > ul > section > li > a').each(function () {
                        $(this).stop().show();
                    });
                }
            } else {

                $('#activescan_line').css('display', 'block');
                $('#activescan_info').css('display', 'block');
                $('#activescan_info').append('<li>' +
                    '<i class="fas fa-info-circle"></i> ' +
                    '<a href="#!">' + i + '</a>' +
                    '</li>' +
                    '<li>' +
                    '<i class="material-icons">keyboard_arrow_right</i> ' +
                    '<a href="#!">' + d['scans'][i]['startstr'] + '</a>' +
                    '</li>' +
                    '<li>' +
                    '<i class="material-icons">keyboard_arrow_right</i> ' +
                    '<a href="#!">' + d['scans'][i]['type'] + ' ' + d['scans'][i]['protocol'] + '</a>' +
                    '</li>');
                $('#activescan_progress').css('display', 'none');

                if (wmover && wmopen) {
                    $('.wm_menu > ul > li > a').each(function () {
                        $(this).stop().show();
                    });
                    $('.wm_menu > ul > section > li > a').each(function () {
                        $(this).stop().show();
                    });
                }

                swal("Done!", "Your Nmap scan is done. reload this page...", "success");
                setTimeout(function () {
                    location.reload();
                }, 5000);
            }
        }

        if (c <= 0) {
            $('#activescancard').css('display', 'none');
        }
    });
}

function newscan() {
    $('#modaltitle').html('<i class="material-icons">wifi_tethering</i> New Nmap Scan');
    $('#modalbody').html(
        '' +
        '<div class="input-field">' +
        '	<div class="small">' +
        '		<div style="padding:20px;">' +
        '<p style="font-size: medium;">' +
        '    Nmap, short for Network Mapper, is an open-source tool used to identify available hosts, the services they offer, their operating systems, and even the type of firewalls in use.' +
        '</p>' +
         '<br>' +
        '<h5>1. Filename:</h5>' +
        '<p style="font-size: medium;">' +
        '    The filename refers to the output file where the scan results will be saved. All scans will be saved as a XML file for further analysis. Please provide a fitting name (you can omit the <code class="language-markup">.xml</code> in the filename if you want).' +
        '</p>' +
         '<br>' +
        '<h5>2. Target:</h5>' +
        '<p style="font-size: medium;">' +
        '    The target specifies the host or network to be scanned. A single IP address, a hostname, or a subnet can be specified.' +
        '</p>' +
        '<p style="font-size: medium;">Examples:<br></p>' +

        '<table style="border-collapse: collapse; width: 30%; font-size: 13px; border: none;">' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>192.168.1.1</code></td>' +
        '<td style="padding: 10px; border: none;">to scan a single host</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>example.com</code></td>' +
        '<td style="padding: 10px; border: none;">to scan a single domain</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>192.168.1.0/24</code></td>' +
        '<td style="padding: 10px; border: none;">to scan a whole subnet</td>' +
    '</tr>' +
'</table>' +
 '<br>' +
        '<h5>3. Parameters:</h5>' +
        '<p style="font-size: medium;">' +
        '    Parameters in Nmap are utilized to customize the scan. Here are some common and useful parameters:' +
        '</p>' +

        '<table style="border-collapse: collapse; width: 50%; font-size: 13px; border: none;">' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>-p</code></td>' +
        '<td style="padding: 10px; border: none;">Specify the port range (e.g., <code>-p 20-1024</code>).</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>-T4</code></td>' +
        '<td style="padding: 10px; border: none;">Set the timing template to "aggressive" (speeds up the scan).</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>-A</code></td>' +
        '<td style="padding: 10px; border: none;">Enable OS detection, version detection, script scanning, and traceroute.</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>-sV</code></td>' +
        '<td style="padding: 10px; border: none;">Probe open ports to determine service/version info</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>-sC</code></td>' +
        '<td style="padding: 10px; border: none;">equivalent to --script=default.</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>-O</code></td>' +
        '<td style="padding: 10px; border: none;">Enable OS detection.</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>-Pn</code></td>' +
        '<td style="padding: 10px; border: none;">Skip host discovery and scan anyway.</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>-sS/sT/sA/sW/sM</code></td>' +
        '<td style="padding: 10px; border: none;">TCP SYN/Connect()/ACK/Window/Maimon scans.</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>-sU</code></td>' +
        '<td style="padding: 10px; border: none;">Perform a UDP scan.</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>-F</code></td>' +
        '<td style="padding: 10px; border: none;">Fast mode - Scan fewer ports than the default scan</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>--open</code></td>' +
        '<td style="padding: 10px; border: none;">Only show open ports.</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>--script</code></td>' +
        '<td style="padding: 10px; border: none;">Specify custom NSE scripts to run (e.g., <code>--script=vuln</code>).</td>' +
    '</tr>' +
    '<tr>' +
        '<td style="padding: 10px; border: none;"><code>--script-args</code></td>' +
        '<td style="padding: 10px; border: none;">Provide arguments to NSE scripts (e.g., <code>--script-args=user=foo,pass=bar</code>).</td>' +
    '</tr>' +
'</table>' +

        '<p style="font-size: medium;">more information at <a href="https://nmap.org/book/man-briefoptions.html">https://nmap.org/book/man-briefoptions.html</a></p>' +

        '		<div>' +
        '	</div>' +
        '<br>' +

        '<hr>' +
        '<table style=" border-collapse: collapse; width: 60%; max-width: 800px;">' +
        '    <tr style="border: none;">' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><label class="params_label" for="xmlfilename">XML Filename:</label></td>' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><input placeholder="e.g., my_scan.xml (you can omit the .xml)" id="xmlfilename" type="text" class="validate"></td>' +
        '    </tr>' +
        '    <tr style="border: none;">' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><label class="params_label" for="targethost">Target IP or Hostname:</label></td>' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><input placeholder="e.g., 192.168.1.0/24" id="targethost" type="text" class="validate"></td>' +
        '    </tr>' +
        '    <tr style="border: none;">' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><label class="params_label" for="params">Nmap Parameters:</label></td>' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><input placeholder="e.g., -sT -A -T4" id="params" type="text" class="validate"></td>' +
        '    </tr>' +
        '</table>' +

        '	<br><br>' +
        '	<div class="row">' +
        '		<div class="col s4 black-text darken-5"><h6>Schedule:</h6></div>' +
        '		<div class="col s8 black-text" style="padding:10px;"><div class="switch"><label>Off<input id="schedule" name="schedule" type="checkbox"><span class="lever"></span>On</label></div></div>' +
        '		<div class="col s12" style="border-bottom:solid 1px #ccc;margin-bottom:20px;">&nbsp;</div>' +
        '		<div class="col s4 black-text darken-3"><h6>Frequency:</h6></div>' +
        '		<div class="col s6" style="width: 200px;"><select id="frequency" name="frequency">' +
        '			<option value="1h">Hourly</option>' +
        '			<option value="1d">Daily</option>' +
        '			<option value="1w">Weekly</option>' +
        '			<option value="1m">Monthly</option>' +
        '		</select></div>' +
        '	</div>' +
        '</div>' +
        ''
    );
    $('#modalfooter').html('<button onclick="startscan();" class="btn green">Start</button>');
    $('#modal1').modal('open');
    $('select').formSelect();
}

function startscan() {
    $('#modal1').modal('close');
    csrftoken = $('input[name="csrfmiddlewaretoken"]').val();

    let xmlFilename = $('#xmlfilename').val();
    if (!xmlFilename.endsWith('.xml')) {
        xmlFilename += '.xml';
    }

    $.post('/api/v1/nmap/scan/new', {
        'csrfmiddlewaretoken': csrftoken,
        'filename': xmlFilename,
        'target': $('#targethost').val(),
        'params': $('#params').val(),
        'schedule': $('#schedule').prop('checked'),
        'frequency': $('#frequency').val(),
    }).done(function (d) {
        if (typeof (d['error']) != 'undefined') {
            swal("Error", "Invalid syntax or disallowed characters", "error");
        } else {
            swal("Started", "Your new Nmap scan is running.This can take quite some time.Make yourself a tea and relax.", "success");
        }
    });
}


function checkCVE() {
    if ($('#cpestring').length <= 0) {
        M.toast({html: 'Please, select a scan report first'});
        return 0;
    }

    cpe = JSON.parse(atob(decodeURIComponent($('#cpestring').val())));
    csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
    console.log(cpe);

    $('#modaltitle').html('Looking for CVE and Exploits');
    $('#modalbody').html(
        'This process could take a while, please wait...' +
        '<div class="progress"><div class="indeterminate"></div></div>'
    );
    $('#modalfooter').html('');
    $('#modal1').modal('open');

    $.post('/report/api/getcve/', {
        'cpe': $('#cpestring').val(),
        'csrfmiddlewaretoken': csrftoken
    }).done(function (d) {
        if (typeof (d['error']) != 'undefined') {
            $('#modalbody').html('Error. Could not connect to local CVE database. Is the IP and Port correctly set?');
            $('#modalfooter').html('<button class="modal-close waves-effect waves-red btn red">Close</button>');
        } else {
            $('#modalbody').html('Done. Please, reload this page by clicking on Reload button.');
            $('#modalfooter').html('<button class="btn blue" onclick="location.reload();">Reload</button>');
        }
    });
    return 0;
}


function createReport(filename, filetype) {
    $('#modal1').modal('close');
    csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
    $.post('api/v1/create_report', {
        'csrfmiddlewaretoken': csrftoken,
        'report_type': filetype,
        'filename': filename
    }).done(function (d) {
        let new_filename;
        if (typeof (d['error']) != 'undefined') {
            swal("Error", "Something went wrong. The requests was not a POST", "error");
        } else {
            swal("Started", "Your report is being generated and should open automatically. (Reload the page to see the file selector)", "success");

            new_filename = filename.split('.').slice(0, -1).join('.');

            var checkFileInterval = setInterval(function () {
                $.get('/static/reports/' + new_filename + '.' + filetype)
                    .done(function () {
                        console.log("File created")
                        clearInterval(checkFileInterval); // Stop polling
                        window.open(`/static/reports/${new_filename}.${filetype}`, '_blank');
                    });
            }, 3000);
        }
    });
}

function openReport(filename, filetype) {
    let new_filename = filename.split('.').slice(0, -1).join('.');

    if (filetype === "dot") {
        filetype = "png";
    }
    window.open(`/static/reports/${new_filename}.${filetype}`, '_blank');

}


function genPDF(md5scan) {
    if (/^[a-f0-9]{32,32}$/.test(md5scan)) {
        $.get('/report/api/pdf/').done(function (data) {
            console.log(data);
            $('#modaltitle').html('Generating Report');

            $('#modalbody').html('Please wait a few seconds...<br>' +
                '<div class="progress"><div class="indeterminate"></div></div>' +
                '<br><br>You\'ll be redirected to the report:<br>')
            $('#modal1').modal('open');
        });

        var pdfcheck = setInterval(function () {
            $.get('/static/' + md5scan + '.pdf')
                .done(function () {
                    $('#modalbody').append('PDF ready! Please wait...<br>');
                    setTimeout(function () {
                        location.href = '/static/' + md5scan + '.pdf'
                    }, 3000);
                })
                .fail(function () {
                    $('#modalbody').append('<i>PDF not ready yet...</i><br>');
                });
        }, 2000);
    }
}

function removeNotes(hashstr, i) {
    $.get('/report/api/rmnotes/' + hashstr + '/').done(function (data) {
        if (data['ok'] === 'notes removed') {
            $('#noteshost' + i).remove();
        }
    });
}

function saveNotes() {
    nb64 = encodeURIComponent(btoa($('#notes').val()));
    csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
    hashstr = $('#hashstr').val();
    console.log(hashstr);
    $.post('/report/api/savenotes/', {
        'notes': nb64,
        'csrfmiddlewaretoken': csrftoken,
        'hashstr': hashstr
    }).done(function (d) {
        console.log(d);
        if (typeof (d['ok']) !== 'undefined' && d['ok'] == 'notes saved') {
            $('#modalbody').html('<span class="green-text">Notes successfully saved!</span><br> The page needs to be reloaded. Please, click on the &quot;Reload&quot; button.');
            $('#modalfooter').html('<button class="btn blue" onclick="javascript:location.reload();">Reload</button>');
        }
    });
}

function openNotes(hashstr, notesb64) {
    if (/^[a-f0-9]{32,32}$/.test(hashstr)) {
        if (notesb64 != '') {
            savednotes = atob(decodeURIComponent(notesb64));
        } else {
            savednotes = ''
        }

        $('#modaltitle').html('Save Notes');
        $('#modalbody').html(
            'Here you can write all the notes you want. The notes you wrote will be displayed on the devices page. ' +
            'Your input is <b class="blue-text">not sanitized</b>, so you can use HTML and JavaScript.<br></br>Don\'t forget to use <b class="blue-text">&lt;br&gt;</b> to make linebreaks. <br>' +
            'For a template idea please click <a class="blue-text" href="https://gist.githubusercontent.com/arantarion/28ea49a46552dcf6537dfdb056fe7dd6/raw/9866e3a1af7b7236465dd9412e131f5ea8b5465a/notes_template.html">here</a>. <br><br>' +
            '<textarea id="notes" style="min-height:160px;border-radius:4px;border:solid #ccc 1px;padding:10px;font-family:monospace;">' + $('<span/>').text(savednotes).html() + '</textarea>' +
            '<input type="hidden" id="hashstr" value="' + hashstr + '" /><br><br>' +
            '<b>Tips:</b><br>' +
            '<code class="grey-text">&lt;b&gt;bold text&lt;/b&gt;</code> = <b>bold text</b><br>' +
            '<code class="grey-text">&lt;i&gt;italic text&lt;/i&gt;</code> = <i>italic text</i><br>' +
            '<code class="grey-text">&lt;span class="label red"&gt;A red label&lt;/span&gt;</code> = <span class="label red">A red label</span><br>' +
            '<code class="grey-text">&lt;code&gt;monospace font&lt;/code&gt;</code> = <code>monospace font</code><br>' +
            '<code class="grey-text">&lt;button onclick="alert(\'Hello, World!\')"&gt;Click me&lt;/button&gt;</code> = <button onclick="alert(\'Hello, World!\')">Click me</button><br>' +
            '<code class="grey-text">&lt;img src="https://example.com/image.jpg" alt="Example Image" width="100"&gt;</code> = <img src="https://example.com/image.jpg" alt="Example Image" width="100"><br>' +
            '<code class="grey-text">&lt;a href="https://example.com" target="_blank"&gt;Visit Example.com&lt;/a&gt;</code> = <a href="https://example.com" target="_blank">Visit Example.com</a><br>' +
            '<code class="grey-text">&lt;blockquote&gt;A blockquote for highlighting text.&lt;/blockquote&gt;</code> = <blockquote>A blockquote for highlighting text.</blockquote><br>' +
            '<code class="grey-text">&lt;ol&gt;&lt;li&gt;Step 1&lt;/li&gt;&lt;li&gt;Step 2&lt;/li&gt;&lt;/ol&gt;</code> = <ol><li>Step 1</li><li>Step 2</li></ol><br>' +
            '<code class="grey-text">&lt;table border="1"&gt;&lt;tr&gt;&lt;th&gt;Header 1&lt;/th&gt;&lt;th&gt;Header 2&lt;/th&gt;&lt;/tr&gt;&lt;tr&gt;&lt;td&gt;Data 1&lt;/td&gt;&lt;td&gt;Data 2&lt;/td&gt;&lt;/tr&gt;&lt;/table&gt;</code> = <table border="1"><tr><th>Header 1</th><th>Header 2</th></tr><tr><td>Data 1</td><td>Data 2</td></tr></table><br>'
        );
        $('#modalfooter').html('<button class="modal-close waves-effect waves-green btn grey">Close</button> <button onclick="saveNotes();" class="waves-effect waves-green btn green white-text">Save</button>');
        $('#modal1').modal('open');
    }
}

function apiPortDetails(address, portid) {
    $.get('/report/api/' + address + '/' + portid + '/').done(function (data) {
        // console.log(data);

        $('#modaltitle').html('Port Details: <span class="blue-text">' + $('<span/>').text(data['@protocol']).html().toUpperCase() + ' / ' + $('<span/>').text(data['@portid']).html() + '</span>');

        tbody = ''
        ingorescriptid = {
            'fingerprint-strings': true
        }

        // console.log(typeof(data['script']));
        if (typeof (data['script']) !== 'undefined') {
            if (typeof (data['script']) === 'object' && typeof (data['script']['@id']) === 'undefined') {
                for (sid in data['script']) {
                    if (typeof (ingorescriptid[data['script'][sid]['@id']]) !== 'undefined') {
                        continue;
                    }
                    tbody += '<tr><td class="black-text">' + $('<span/>').text(data['script'][sid]['@id']).html() + '</td><td style="font-family:monospace;font-size:12px;">' + $('<span/>').text(data['script'][sid]['@output']).html() + '</td></tr>'
                }
            } else {
                if (typeof (ingorescriptid[data['script']['@id']]) === 'undefined') {
                    tbody += '<tr><td class="black-text">' + $('<span/>').text(data['script']['@id']).html() + '</td><td style="font-family:monospace;font-size:12px;">' + $('<span/>').text(data['script']['@output']).html() + '</td></tr>'
                }
            }
        } else {
            tbody += '<tr><td><i>none</i></td><td><i>none</i></td></tr>'
        }


        $('#modalbody').html('<table class="table"><thead><th style="min-width:200px;">Script ID</th><th>Output</th></thead><tbody>' + tbody + '</tbody></table>');
        $('#modalbody').append('<br><b>Raw Output:</b><br><pre>' + $('<span/>').text(JSON.stringify(data, null, 4)).html() + '</pre>');
        $('#modal1').modal('open');
    });
}

function removeLabel(type, hashstr, i) {
    $.get('/report/api/rmlabel/' + type + '/' + hashstr + '/').done(function (data) {
        if (data['ok'] === 'label removed') {
            $('#hostlabel' + i).attr("class", "")
            $('#hostlabel' + i).html("");
            $('#hostlabelbb' + i).attr("class", "")
            $('#hostlabelbb' + i).css("background-color", "")
        }
    });
}

function setLabel(type, label, hashstr, i) {

    $.get('/report/api/setlabel/' + type + '/' + label + '/' + hashstr + '/').done(function (data) {

        var res = data;
        var color = 'grey';
        var margin = '10px';

        if (res['ok'] === 'label set') {

            switch (res['label']) {
                case 'Vulnerable':
                    color = '#F44336';
                    margin = '10px';
                    break;
                // case 'Critical': color = 'black'; margin = '22px'; break;
                case 'Warning':
                    color = 'orange';
                    margin = '28px';
                    break;
                case 'Checked':
                    color = '#0c7bbb';
                    margin = '28px';
                    break;
            }

            // displayed label
            // z-index:99;transform: rotate(-8deg);margin-top:-14px;margin-left:-40px;
            $('#hostlabel' + i).css("margin-left", '-40px')
            $('#hostlabel' + i).css("z-index", '99')
            $('#hostlabel' + i).css("transform", 'rotate(-8deg)')
            $('#hostlabel' + i).css("margin-top", '-14px')
            $('#hostlabel' + i).css("background-color", color);
            $('#hostlabel' + i).attr("class", "")
            $('#hostlabel' + i).addClass('leftlabel');
            // $('#hostlabel'+i).addClass(color);
            $('#hostlabel' + i).html(res['label']);

            //little corner bit
            // border-radius:0px 4px 0px 4px;z-index:98;position:absolute;width:18px;height:10px;margin-left:-48px;margin-top:-3px;
            $('#hostlabelbb' + i).css("border-radius", '1px 4px 1px 4px')
            $('#hostlabelbb' + i).css("z-index", '98')
            $('#hostlabelbb' + i).css("position", 'absolute')
            $('#hostlabelbb' + i).css("width", '18px')
            $('#hostlabelbb' + i).css("height", '10px')
            $('#hostlabelbb' + i).css("margin-left", '-54px')
            $('#hostlabelbb' + i).css("margin-top", '-3px')
            $('#hostlabelbb' + i).css("background-color", color);
            $('#hostlabelbb' + i).attr("class", "")
            //$('#hostlabelbb'+i).addClass(color);
        }
    });
}

function delete_file(filename) {
    csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
    $.post('api/v1/delete_file', {
        'csrfmiddlewaretoken': csrftoken,
        'file_to_delete': filename
    }).done(function (d) {
        if (typeof (d['error']) != 'undefined') {
            swal("Error", "Could not delete the file", "error");
        } else {
            swal("Deletion", "File successfully deleted. This page will reload automatically in 3 seconds", "success");

            setTimeout(function () {
                location.href = "/setscanfile/unset"
            }, 4000);
        }
    });
}

function start_bruteforcer_real(filename, host) {
    csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
    $.post('api/v1/bruteforce', {
        'csrfmiddlewaretoken': csrftoken,
        'filename': filename,
        'specified_host': host
    });
    swal("Start", "Trying to guess the password and username for " + host + ". This will take some time", "success");

}

function start_bruteforcer(filename, host) {

    $('#modaltitle').html('CAUTION - Before you proceed');
    $('#modalbody').html(
        '<p>You are about to bruteforce one or multiple devices. Please make sure that you have the necessary permissions to do so. <br><br>' +
        'If you are in germany here are some related links:<br>' +
        '<a href="https://www.gesetze-im-internet.de/stgb/__202a.html">- StGB $202a Auspähen von Daten</a> <br>' +
        '<a href="https://www.gesetze-im-internet.de/stgb/__202b.html">- StGB $202b Abfangen von Daten</a> <br>' +
        '<a href="https://www.gesetze-im-internet.de/stgb/__202c.html">- StGB $202c Vorbereiten des Ausspähens und Abfangens von Daten</a> ' +
        '</p>'
    );

    $('#modalfooter').html('<button class="modal-close waves-effect waves-green btn grey">Close</button> <button onclick="start_bruteforcer_real(\'' + filename + '\', \'' + host + '\'); $(\'#modal1\').modal(\'close\');" class="waves-effect waves-red btn red white-text">Start Process</button>');
    $('#modal1').modal('open');
}


function cve_info() {
    $('#modaltitle').html('What are CVEs and why you should care');
    $('#modalbody').html(
        '<p style="text-align: justify;">' +
        '"Common Vulnerabilities and Exposures (CVE)"  is a standardized list of entries, each denoting ' +
        'a specific security vulnerability or exposure in a software. Each entry is identified with a ' +
        'unique CVE Identifier (CVE ID), facilitating the sharing of data across separate vulnerability capabilities ' +
        '(tools, databases, and services).<br>' +
        'CVE dates back to 1999 when it was launched by the MITRE Corporation, a not-for-profit ' +
        'organization that operates federally funded research and development centers. The primary objective was to ' +
        'standardize the way vulnerabilities and exposures are identified, thus promoting a universal standard for ' +
        'vulnerability management, security tools, and services.<br>' +
        'The anatomy of a CVE entry encompasses a unique identifier, a description of the vulnerability or exposure, ' +
        'and references, i.e., pointers to related resources where one can learn more information about the vulnerability. ' +
        'The CVE list does not encompass metrics or information regarding the risks, impacts, fixes, or other related ' +
        'nuances. However, it serves as a baseline for the National Vulnerability Database (NVD) that provides such details.<br>' +
        'Over the years, the CVE system has evolved, embracing new structures to encapsulate more information and adapt ' +
        'to the complexity of cybersecurity landscapes. The initial flat structure has morphed into a more ' +
        'hierarchical model, allowing for better organization and identification of vulnerabilities.<br>' +
        'Now, why should you concern yourself with CVEs? The answer lies in the adoption ' +
        'of smart home devices and IoT (Internet of Things) technologies. Today\'s home networks are no longer confined ' +
        'to computers and smartphones. They now encompass a lot of devices ranging from smart thermostats, ' +
        'security cameras, smart TVs, to intelligent refrigerators. Each of these devices, being a node on the network, ' +
        'presents a potential entry point for malicious actors if they harbor vulnerabilities.<br>' +
        'The relevance of CVEs in home network security is can be summarized into:<br>' +
        '<ol>' +
        '<li><b>Awareness:</b> By perusing CVE databases, you can become aware of the known vulnerabilities in ' +
        'the devices you own or intend to purchase. This awareness is the first step towards a secure home network.</li>' +
        '<li><b>Mitigation:</b> Once aware of the vulnerabilities, you can take steps to mitigate the risks. ' +
        'This could range from applying patches, changing configurations, or even replacing highly vulnerable devices.</li>' +
        '<li><b>Vendor Accountability:</b> CVEs also serve as a mechanism to hold vendors accountable. A vendor with ' +
        'a long list of CVEs may not be following best security practices in their product development.</li>' +
        '<li><b>Community Support:</b> The CVE system fosters a community where individuals and organizations share ' +
        'information about vulnerabilities in a standardized manner, promoting collective security improvement.</li>' +
        '<li><b>Informed Purchasing Decisions:</b> Before adding a new device to you network, you can check ' +
        'the CVE database to understand the security risks of the device, thus making informed purchasing decisions.</li>' +
        '</ol>' +
        'The process of keeping up to date with CVEs has been simplified with the advent of automated tools and platforms ' +
        'that provide real-time updates and even mitigation strategies for known vulnerabilities. Moreover, some ' +
        'platforms offer user-friendly interfaces and are tailored for individuals with no advanced technical knowledge, ' +
        'thus demystifying the notion that CVEs are the reserve of cybersecurity professionals. (some are listed below)<br>' +

        'In conclusion, the CVE system is an invaluable resource in the quest for enhanced cybersecurity in home ' +
        'networks. As smart homes become the norm rather than the exception, embracing a proactive approach towards ' +
        'understanding and mitigating vulnerabilities is imperative for safeguarding personal data and ensuring a ' +
        'secure and resilient network.' +
        '</p>' +
        '<br><br>' +
        '<h4>External Resources:</h4>' +
        '<p style="text-align: justify;">' +
        '<b>General Information:</b><br>' +
        '<a href="https://www.cve.org/About/Overview" target="_blank">https://www.cve.org/About/Overview</a><br>' +
        '<a href="https://nvd.nist.gov/general/cve-process" target="_blank">https://nvd.nist.gov/general/cve-process</a><br>' +
        '<a href="https://nvd.nist.gov/general/cna-counting" target="_blank">https://nvd.nist.gov/general/cna-counting</a><br>' +
        '<a href="https://www.redhat.com/en/topics/security/what-is-cve" target="_blank">https://www.redhat.com/en/topics/security/what-is-cve</a><br>' +
        '<a href="https://snyk.io/de/learn/what-is-cve-vulnerablity/" target="_blank">https://snyk.io/de/learn/what-is-cve-vulnerablity/</a><br>' +
        '<a href="https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures" target="_blank">https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures</a><br>' +
        '<br><b>Specifications:</b><br>' +
        '<a href="https://www.first.org/cvss/v2/guide" target="_blank">https://www.first.org/cvss/v2/guide</a><br>' +
        '<a href="https://www.first.org/cvss/v3.0/specification-document" target="_blank">https://www.first.org/cvss/v3.0/specification-document</a><br>' +
        '<a href="https://www.first.org/cvss/v3.1/specification-document" target="_blank">https://www.first.org/cvss/v3.1/specification-document</a><br>' +
        '<a href="https://www.first.org/cvss/v4.0/specification-document" target="_blank">https://www.first.org/cvss/v4.0/specification-document</a><br>' +
        '<a href="https://cpe.mitre.org/specification/" target="_blank">https://cpe.mitre.org/specification/</a><br>' +
        '<br><b>CVE Databases:</b><br>' +
        '<a href="https://nvd.nist.gov/vuln/search" target="_blank">https://nvd.nist.gov/vuln/search</a><br>' +
        '<a href="https://www.cve.org/" target="_blank">https://www.cve.org/</a><br>' +
        '<a href="https://www.cvedetails.com/" target="_blank">https://www.cvedetails.com/</a><br>' +
        '<a href="https://www.opencve.io/welcome" target="_blank">https://www.opencve.io/welcome</a><br>' +
        '<a href="https://vuldb.com/" target="_blank">https://vuldb.com/</a><br>' +
        '<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank">https://www.cisa.gov/known-exploited-vulnerabilities-catalog</a><br> ' +
        '</p>'
    );
    $('#modalfooter').html('<button class="modal-close waves-effect waves-green btn grey">Close</button>');
    $('#modal1').modal('open');

}