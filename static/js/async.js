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
        'Run a new Nmap scan by setting the following 3 parameters:' +
        '<div class="input-field">' +
        '	<div class="small">' +
        '		<div style="padding:20px;">' +
        '		<b>Filename:</b><br>Name of the Nmap XML file. This name must has the <code class="language-markup">.xml</code> extension.<br>Allowed chars: <code>[a-zA-Z0-9], _, - and .</code><br><br>' +
        '		<b>Target:</b><br>This could be the target IP address or hostname (e.g. 192.168.1.0/24)<br><br>' +
        '		<b>Parameters:</b><br>NMAP parameters, more information at <a href="https://nmap.org/book/man-briefoptions.html">https://nmap.org/book/man-briefoptions.html</a>' +
        '		<div>' +
        '	</div>' +
        '<br>' +
        '	<input placeholder="XML Filename (ex. my_scan.xml)" id="xmlfilename" type="text" class="validate">' +
        '	<input placeholder="Target IP or hostname (ex. 192.168.1.0/24)" id="targethost" type="text" class="validate">' +
        '	<input placeholder="Nmap Parameters (ex. -sT -A -T4)" id="params" type="text" class="validate">' +
        '	<br><br>' +
        '	<div class="row">' +
        '		<div class="col s4 grey-text darken-3"><h6>Schedule:</h6></div>' +
        '		<div class="col s8" style="padding:10px;"><div class="switch"><label>Off<input id="schedule" name="schedule" type="checkbox"><span class="lever"></span>On</label></div></div>' +
        '		<div class="col s12" style="border-bottom:solid 1px #ccc;margin-bottom:20px;">&nbsp;</div>' +
        '		<div class="col s4 grey-text darken-3"><h6>Frequency:</h6></div>' +
        '		<div class="col s8"><select id="frequency" name="frequency">' +
        '			<option value="1h">Hourly</option>' +
        '			<option value="1d">Daily</option>' +
        '			<option value="1w">Weekly</option>' +
        '			<option value="1m">Monthly</option>' +
        '		</select></div>' +
        '	</div>' +
        '</div>' +
        ''
    );
    $('#modalfooter').html('<button onclick="javascript:startscan();" class="btn green">Start</button>');
    $('#modal1').modal('open');
    $('select').formSelect();
}

function startscan() {
    $('#modal1').modal('close');
    csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
    $.post('/api/v1/nmap/scan/new', {
        'csrfmiddlewaretoken': csrftoken,
        'filename': $('#xmlfilename').val(),
        'target': $('#targethost').val(),
        'params': $('#params').val(),
        'schedule': $('#schedule').prop('checked'),
        'frequency': $('#frequency').val(),
    }).done(function (d) {
        if (typeof (d['error']) != 'undefined') {
            swal("Error", "Invalid syntax or disallowed characters", "error");
        } else {
            swal("Started", "Your new Nmap scan is running.\nThis can take quite some time.\nMake yourself a tea and relax.", "success");
        }
    });
}

var cpetot = 0;
var cpetimer;

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
        console.log(d);
        $('#modalbody').html('Done. Please, reload this page by clicking on Reload button.');
        $('#modalfooter').html('<button class="btn blue" onclick="javascript:location.reload();">Reload</button>');
    });

    return 0;

    cpetot = Object.keys(cpe).length;
    console.log(cpetot);

    for (host in cpe) {
        for (port in cpe[host]) {
            for (cpestr in cpe[host][port]) {
                if (/^cpe:.+:.+:.+:.*$/.test(cpestr)) {
                    console.log(cpestr);
                    $.post('/report/api/getcve/', {
                        'cpe': cpestr,
                        'host': host,
                        'port': port,
                        'csrfmiddlewaretoken': csrftoken
                    }).done(function (d) {
                        console.log(d);
                        for (rhost in d) {
                            for (rport in d[rhost]) {
                                $('#modalbody').append('<div class="small"><i>Received: ' + d[rhost][rport]['id'] + ' host:' + rhost + ' port:' + rport + '</i></div>');
                            }
                        }
                    }).always(function () {
                        cpetot = (cpetot - 1);
                    });
                } else {
                    cpetot = (cpetot - 1);
                }

                console.log(cpetot);
            }
        }
    }

    cpetimer = setInterval(function () {
        if (checkCPETOT()) {
            console.log('END');
            window.clearInterval(cpetimer);
            $('#modalbody').html('Done. Please, reload this page by clicking on Reload button.');
            $('#modalfooter').html('<button class="btn blue" onclick="javascript:location.reload();">Reload</button>');
        }
    }, 2000);
}

function checkCPETOT() {
    return cpetot <= 0;
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
            swal("Error", "Something went wrong :C", "error");
        } else {
            swal("Started", "Your report is being generated!\n(Reload the page to see the file selector)", "success");

            new_filename = filename.split('.').slice(0, -1).join('.');

            if (filetype === "dot") {
                filetype = "png";
            }

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
        // $('#modal1').css('background-color','#3e3e3e');
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

function start_bruteforcer(filename, host) {
    csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
    $.post('api/v1/bruteforce', {
        'csrfmiddlewaretoken': csrftoken,
        'filename': filename,
        'specified_host': host
    });
    swal("Start", "Trying to guess the password and username for " + host + ". This will take some time", "success");

}