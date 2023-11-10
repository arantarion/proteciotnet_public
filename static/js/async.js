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

function new_bl_scan() {
    $('#modaltitle').html('<i class="material-icons">bluetooth</i> New Bluetooth Scan');
    $('#modalbody').html(`
    <div class="input-field">
        <div class="small">
            <p style="font-size: medium;">
                Bluetooth is a widely adopted wireless communication standard designed for short-range data exchange 
                between devices. Initially developed for replacing wired connections, it supports a broad range of 
                applications, from audio streaming to file transfers. Bluetooth Low Energy (BLE), introduced as part 
                of the Bluetooth 4.0 specification, is a power-optimized variant that is particularly suitable for 
                applications requiring minimal energy consumption and periodic short bursts of data transmission. 
                The usage of BLE includes fitness trackers measuring your heart rate, smart home sensors, and 
                location-based beacon systems, all operating with extended battery life.
            </p>
            <br>
            <hr>
            <h5>Scan Options</h5>
            <table style="border-collapse: collapse; width: 75%; max-width: 850px;">
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_filename">Output Filename:<sup>*</sup></label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <input placeholder="e.g. my_ble_scan (without file extension)" 
                                id="ble_filename" 
                                type="text" 
                                class="validate" 
                                required 
                                title="Please provide a fitting filename without a file extension">
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_scan_time">Time (in seconds) or continuous<sup>*</sup></label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <input placeholder="e.g. 60 / 99999 (for long)" 
                                id="ble_scan_time" 
                                type="number" 
                                class="validate" 
                                min="1" 
                                title="Please provide the length of time you want to scan for devices (min. 1)">
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <div class="switch">
                            <label>Off<input id="ble_continuous_switch" name="ble_continuous_mode" type="checkbox"><span class="lever"></span>On</label>
                        </div>
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_list_only_text">Only list devices:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <div class="switch">
                            <label>Off<input id="ble_list_only_switch" name="ble_listmode" type="checkbox"><span class="lever"></span>On</label>
                        </div>
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_connectable_only_text">Connectable only:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <div class="switch">
                            <label>Off<input id="ble_connectable_only_switch" name="ble_connectable_mode" type="checkbox"><span class="lever"></span>On</label>
                        </div>
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_beacons_only_text">Beacons (e.g. AirTags) only:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <div class="switch">
                            <label>Off<input id="ble_beacons_only_switch" name="ble_beacons_mode" type="checkbox"><span class="lever"></span>On</label>
                        </div>
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_bonding_test_text">Test Bonding Modes:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <div class="switch">
                            <label>Off<input id="ble_bonding_test_switch" name="ble_bonding_test_mode" type="checkbox"><span class="lever"></span>On</label>
                        </div>
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_schedule">Schedule:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <div class="switch">
                            <label>Off<input id="ble_schedule" name="ble_schedule" type="checkbox"><span class="lever"></span>On</label>
                        </div>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_scan_frequency">Frequency:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <select id="ble_scan_frequency" name="ble_frequency">
                            <option value="none">-</option>
                            <option value="10min">10 Minutes</option>
                            <option value="1h">Hourly</option>
                            <option value="1d">Daily</option>
                            <option value="1w">Weekly</option>
                            <option value="1m">Monthly</option>
                        </select>
                    </td>
                </tr>
            </table>
            <h6>Advanced Options</h6>
            <table style="border-collapse: collapse; width: 72%; max-width: 820px;">
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_interface_nr">(opt.) Interface Nr.</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <input placeholder="e.g. 0 (for hci0) / 1 (hci1)" id="ble_interface_nr" type="number" class="validate" min="0" title="Enter an ID for an HCI interface. 0 for HCI0, 1 for HCI1 etc.">
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_specific_device">(opt.) Device Address</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <input placeholder="e.g. 7E:B5:C1:97:E4:C9" id="ble_specific_device" type="text" class="validate" title="Please enter a valid MAC address (e.g., 7E:B5:C1:97:E4:C9)">
                    </td>
                </tr>
            </table>
            <br><br>
            <hr>
            <h5>Sniffing Options</h5>
            <table style="border-collapse: collapse; width: 70%; max-width: 800px;">
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_sniff_filename">Output Filename:<sup>*</sup></label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <input placeholder="e.g. my_ble_sniff (please omit the file extension)" id="ble_sniff_filename" type="text" class="validate" required title="Please provide a fitting filename without a file exptension">
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_sniff_timeout">Sniffing Timeout:<sup>*</sup></label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <input placeholder="timeout for sniffing" id="ble_sniff_timeout" type="text" class="validate" required title="Please provide a timeout for the sniffing operation">
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_ltk">(opt.) LTK:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <input placeholder="e.g. 0164310ef9525180aaff9fc1460636a7" id="ble_ltk" type="text" class="validate" minlength="32" maxlength="32" title="Please enter a valid LTK for the decryption. They can be obtained via the tool Crackle">
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_decrypt_packages">Decrypt traffic:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <div class="switch">
                            <label>Off<input id="ble_decrypt_packages_switch" name="ble_decrypt_packages_mode" type="checkbox"><span class="lever"></span>On</label>
                        </div>
                    </td>
                </tr>
            </table>
            <br><br>
            <hr>
            <h5>Send Command / Subscribe to Characteristic</h5>
            <table style="border-collapse: collapse; width: 70%; max-width: 800px;">
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_send_dev_addr">Device Address:<sup>*</sup></label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <input placeholder="e.g. 7E:B5:C1:97:E4:C9" id="ble_send_dev_addr" type="text" class="validate" required title="Please enter a valid device address (e.g., 7E:B5:C1:97:E4:C9)">
                    </td>
                </tr>
                <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_chara">Characteristic:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <input placeholder="e.g. 0000fff3-0000-1000-8000-00805f9b34fb (or fff3)" id="ble_chara" type="text" class="validate" minlength="4" title="Please provide either the short or long address for the characteristic">
                    </td>
                </tr>
               <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_value">Value:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <input placeholder="e.g. use-case specific" id="ble_value" type="text" class="validate" title="Please provide the value that you want to send to the characteristic">
                    </td>
                </tr>
               <tr style="border: none;">
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <label class="params_label" for="ble_subscribe_chara">Subscribe:</label>
                    </td>
                    <td style="padding: 10px; vertical-align: middle; border: none;">
                        <div class="switch">
                            <label>Off<input id="ble_subscribe_chara_switch" name="ble_subscribe_chara_mode" type="checkbox"><span class="lever"></span>On</label>
                        </div>
                    </td>
                </tr>
            </table>
        </div>
    </div>
    `);

    $('#ble_beacons_only_switch').change(function () {
        if ($(this).is(':checked')) {
            $('#ble_list_only_switch').prop('checked', true);
            $('#ble_bonding_test_switch').prop('checked', false);
            $('#ble_connectable_only_switch').prop('checked', false);
        }
    });

    $('#ble_connectable_only_switch').change(function () {
        if ($(this).is(':checked')) {
            $('#ble_beacons_only_switch').prop('checked', false);
        }
    });

    $('#ble_continuous_switch').change(function () {
        if ($(this).is(':checked')) {
            $('#ble_scan_time').prop('disabled', true);
        } else {
            $('#ble_scan_time').prop('disabled', false);
        }
    });

    $('#ble_bonding_test_switch').change(function () {
        if ($(this).is(':checked')) {
            $('#ble_beacons_only_switch').prop('checked', false);
        }
    });

    $('#ble_filename').on('input', function () {
        if ($(this).val().trim() !== "") {
            $('#ble_sniff_filename, #ble_sniff_timeout, #ble_ltk, #ble_decrypt_packages_switch, #ble_send_dev_addr, #ble_chara, #ble_value, #ble_subscribe_chara_switch').prop('disabled', true);
            $('#ble_sniff_filename, #ble_sniff_timeout, #ble_ltk, #ble_send_dev_addr, #ble_chara, #ble_value').val("")
            $('#ble_decrypt_packages_switch, #ble_subscribe_chara_switch').prop("checked", false)
        } else {
            $('#ble_sniff_filename, #ble_sniff_timeout, #ble_ltk, #ble_decrypt_packages_switch, #ble_send_dev_addr, #ble_chara, #ble_value, #ble_subscribe_chara_switch').prop('disabled', false);
        }
    });

    $('#ble_sniff_filename').on('input', function () {
        if ($(this).val().trim() !== "") {
            $('#ble_filename, #ble_scan_time, #ble_continuous_switch, #ble_list_only_switch, #ble_connectable_only_switch, #ble_beacons_only_switch, #ble_bonding_test_switch, #ble_schedule, #ble_scan_frequency, #ble_interface_nr, #ble_specific_device, #ble_send_dev_addr, #ble_chara, #ble_value, #ble_subscribe_chara_switch').prop('disabled', true);
            $('#ble_filename, #ble_scan_time, #ble_interface_nr, #ble_specific_device, #ble_send_dev_addr, #ble_chara, #ble_value').val('');
            $('#ble_continuous_switch, #ble_list_only_switch, #ble_connectable_only_switch, #ble_beacons_only_switch, #ble_bonding_test_switch, #ble_schedule, #ble_subscribe_chara_switch').prop("checked", false)
        } else {
            $('#ble_filename, #ble_scan_time, #ble_continuous_switch, #ble_list_only_switch, #ble_connectable_only_switch, #ble_beacons_only_switch, #ble_bonding_test_switch, #ble_schedule, #ble_scan_frequency, #ble_interface_nr, #ble_specific_device, #ble_send_dev_addr, #ble_chara, #ble_value, #ble_subscribe_chara_switch').prop('disabled', false);
        }
    });

    $('#ble_send_dev_addr').on('input', function () {
        if ($(this).val().trim() !== "") {
            $('#ble_filename, #ble_scan_time, #ble_continuous_switch, #ble_list_only_switch, #ble_connectable_only_switch, #ble_beacons_only_switch, #ble_bonding_test_switch, #ble_schedule, #ble_scan_frequency, #ble_interface_nr, #ble_specific_device, #ble_sniff_filename, #ble_sniff_timeout, #ble_ltk, #ble_decrypt_packages_switch').prop('disabled', true);
            $('#ble_filename, #ble_scan_time, #ble_interface_nr, #ble_specific_device, #ble_sniff_filename, #ble_sniff_timeout, #ble_ltk').val('');
            $('#ble_continuous_switch, #ble_list_only_switch, #ble_connectable_only_switch, #ble_beacons_only_switch, #ble_bonding_test_switch, #ble_schedule').prop("checked", false)
        } else {
            $('#ble_filename, #ble_scan_time, #ble_continuous_switch, #ble_list_only_switch, #ble_connectable_only_switch, #ble_beacons_only_switch, #ble_bonding_test_switch, #ble_schedule, #ble_scan_frequency, #ble_interface_nr, #ble_specific_device, #ble_sniff_filename, #ble_sniff_timeout, #ble_ltk, #ble_decrypt_packages_switch').prop('disabled', false);
        }
    });


    $('#modalfooter').html('<button id="ble_start_button" onclick="start_ble_scan()" class="btn green">Start</button>');
    $('#modal1').modal('open');
    $('select').formSelect();
}

function start_ble_scan() {
    $('#modal1').modal('close');
    const csrftoken = $('input[name="csrfmiddlewaretoken"]').val();

    // Extract Scan Options
    const bleFilename = $('#ble_filename').val();
    const bleScanTime = $('#ble_scan_time').val();
    const bleContScan = $('#ble_continuous_switch').is(':checked');
    const bleListOnly = $('#ble_list_only_switch').is(':checked');
    const bleConnectableOnly = $('#ble_connectable_only_switch').is(':checked');
    const bleBeaconsOnly = $('#ble_beacons_only_switch').is(':checked');
    const bleBondingTest = $('#ble_bonding_test_switch').is(':checked');
    const bleSchedule = $('#ble_schedule').is(':checked');
    const frequency = $('#ble_scan_frequency').val();

    // Extract advanced options
    const bleInterfaceNr = $('#ble_interface_nr').val();
    const bleSpecificDevice = $('#ble_specific_device').val();

    // Extract Sniffing Options
    const bleSniffFilename = $('#ble_sniff_filename').val();
    const bleSniffTimeout = $('#ble_sniff_timeout').val();
    const bleLTK = $('#ble_ltk').val();
    const bleDecryptPackages = $('#ble_decrypt_packages_switch').is(':checked');

    // Extract Send Command / Subscribe to Characteristics Parameters
    const bleSendDevAddr = $('#ble_send_dev_addr').val();
    const bleChara = $('#ble_chara').val();
    const bleValue = $('#ble_value').val();
    const bleSubscribeChara = $('#ble_subscribe_chara_switch').is(':checked');

    const postData = {
        'csrfmiddlewaretoken': csrftoken,
        'ble_filename': bleFilename,
        'ble_scan_time': bleScanTime,
        'ble_cont_scan': bleContScan,
        'ble_list_only': bleListOnly,
        'ble_connectable_only': bleConnectableOnly,
        'ble_beaconsOnly': bleBeaconsOnly,
        'ble_bondingTest': bleBondingTest,
        'ble_schedule': bleSchedule,
        'ble_frequency': frequency,
        'ble_interface_nr': bleInterfaceNr,
        'ble_specific_device': bleSpecificDevice,
        'ble_sniff_filename': bleSniffFilename,
        'ble_sniff_timeout': bleSniffTimeout,
        'ble_ltk': bleLTK,
        'ble_decrypt_packages': bleDecryptPackages,
        'ble_send_dev_addr': bleSendDevAddr,
        'ble_chara': bleChara,
        'ble_value': bleValue,
        'ble_subscribe_chara': bleSubscribeChara,
    };

    if (!bleFilename && !bleSniffFilename && !bleSendDevAddr) {
        swal("Error", "Please supply a filename at least...", "error");
        $('#modal1').modal('open');
    }

    $.post('/api/v1/ble/scan/new', postData).done(function (d) {
        if ((typeof (d['error']) != 'undefined') && (d['error'] === "incomplete parameters")) {
            swal("Error", "Please provide a valid filename.", "error");
        } else if (typeof (d['error']) != 'undefined') {
            swal("Error", "Invalid syntax or something else went wrong!", "error");
        } else {
            swal("Started", "Your Bluetooth Low Energy scan is running. This can take some time.", "success");
        }
    });
}

function new_zigbee_scan() {
    $('#modaltitle').html('<i class="material-icons">sensors</i> New ZigBee Scan');
    $('#modalbody').html('' +
        '<div class="input-field">' +
        '	<div class="small">' +
        '		<div style="padding:20px;">' +
        '<p style="font-size: medium;">' +
        'Zigbee is a robust, low-power wireless communication protocol tailored for short-range connectivity among ' +
        'smart home devices, using a mesh network topology. This protocol ' +
        'offers energy efficiency, security, and interoperability, positioning it as a solution for ' +
        'home automation systems. In a home environment, Zigbee facilitates seamless integration, enabling ' +
        'functionalities such as automated lighting, adaptive thermostats, security systems, and ' +
        'synchronized smart appliances.' +
        '</p>' +
        '<br>' +
        '<h5>1. Filename:</h5>' +
        '<p style="font-size: medium;">' +
        'The filename refers to the output file where the scan results will be saved. All scans will be saved ' +
        'as a JSON file for further analysis. Please provide a fitting name (you can ' +
        'omit the <code class="language-markup">.json</code> in the filename if you want).' +
        '</p>' +
        '<br>' +
        '<h5>2. Interface Name / ID (optional):</h5>' +
        '<p style="font-size: medium;">' +
        '    <b>[Neccessary if you are not using a CC2531 USB Dongle]</b> The name of the hardware and its current USB ' +
        'Bus and correspondig device identifier or the "/dev/tty" path to you device. ' +
        '</p>' +
        '<br>' +
        '<h5>3. Channel (optional):</h5>' +
        '<p style="font-size: medium;">' +
        '   <b> [If you already know the channel]</b> The ZigBee channel number. Most commonly channels between 11 ' +
        'and 26 are used. Channel 0 is sometimes used in Europe, while channels 1 to 10 ' +
        'are likely used in America and Asia.' + '<br>' +
        'Depending on your devices you may find the channel in the manual or documentation of your ZigBee hub.' +
        '</p>' +
        '<br>' +
        '<h5>4. PCAP Path (optional):</h5>' +
        '<p style="font-size: medium;">' +
        '    <b>[If you scanned you network yourself]</b> If you already conducted a scan of your ZigBee network you ' +
        'can provide the path to a local PCAP file and the file will be processed to be displayed by ProtecIoTnet. ' +
        'The other parameters (except filename) will be ignored.' +
        '</p>' +
        '		<div>' +
        '	</div>' +
        '<br>' +
        '<hr>' +
        '<table style=" border-collapse: collapse; width: 70%; max-width: 800px;">' +
        '    <tr style="border: none;">' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><label class="params_label" for="jsonfilename">JSON Filename:</label></td>' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><input placeholder="e.g. my_scan.json (you can omit the .json)" id="jsonfilename" type="text" class="validate" required></td>' +
        '    </tr>' +
        '    <tr style="border: none;">' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><label class="params_label" for="zb_interface">(opt.) Device path / Bus ID:</label></td>' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><input placeholder="e.g. /dev/tty0 or \'1:8\' " id="zb_interface" type="text" class="validate"></td>' +
        '    </tr>' +
        '    <tr style="border: none;">' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><label class="params_label" for="zb_channel">(opt.) Channel:</label></td>' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><input placeholder="e.g. 20" id="zb_channel" type="number" min="0" max="26" class="validate"></td>' +
        '<span class="helper-text" data-error="Channel must be between 0 and 26."></span>' +
        '    </tr>' +
        '    <tr style="border: none;">' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><label class="params_label" for="zb_pcap_path">(opt.) .pcap Path:</label></td>' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><input placeholder="e.g. /path/to/your/zigbee_file.pcap" id="zb_pcap_path" type="text" class="validate" pattern="^(\\/[^\\/]+)+\\.pcap$"></td>' +
        '    </tr>' +
        '</table>' +

        '	<br><br>' +
        '</div>' +
        ''
    );
    $('#modalfooter').html('<button  id="startButton" onclick="start_zigbee_scan();" class="btn green">Start</button>');

    $('#modal1').modal('open');
    $('select').formSelect();
}

function start_zigbee_scan() {
    $('#modal1').modal('close');
    csrftoken = $('input[name="csrfmiddlewaretoken"]').val();

    let zigbeeFilename = $('#jsonfilename').val();
    if (!zigbeeFilename.endsWith('.json')) {
        zigbeeFilename += '.json';
    }

    $.post('/api/v1/zigbee/scan/new', {
        'csrfmiddlewaretoken': csrftoken,
        'zb_filename': zigbeeFilename,
        'zb_interface': $('#zb_interface').val(),
        'zb_channel': $('#zb_channel').val(),
        'zb_pcap_path': $('#zb_pcap_path').val(),
    }).done(function (d) {
        if ((typeof (d['error']) != 'undefined') && (d['error'] === "incomplete parameters")) {
            swal("Error", "Please provide a valid filename.", "error");
        } else if (typeof (d['error']) != 'undefined') {
            swal("Error", "Invalid syntax or something else went wrong!", "error");
        } else {
            swal("Started", "Your ZigBee scan is running.This can take quite some time. Make yourself a tea and relax.", "success");
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
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><input placeholder="e.g. my_scan.xml (you can omit the .xml)" id="xmlfilename" type="text" class="validate"></td>' +
        '    </tr>' +
        '    <tr style="border: none;">' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><label class="params_label" for="targethost">Target IP or Hostname:</label></td>' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><input placeholder="e.g. 192.168.1.0/24" id="targethost" type="text" class="validate"></td>' +
        '    </tr>' +
        '    <tr style="border: none;">' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><label class="params_label" for="params">Nmap Parameters:</label></td>' +
        '        <td style="padding: 10px; vertical-align: middle; border: none;"><input placeholder="e.g. -sT -A -T4" id="params" type="text" class="validate"></td>' +
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
            swal("Started", "Your new Nmap scan is running.This can take quite some time. Make yourself a tea and relax.", "success");
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

function createZigBeeReport(filename, filetype) {
    console.log(filename, filetype);
    $('#modal1').modal('close');
    csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
    let currentURL = window.location.href;
    let baseURL = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
    $.post(baseURL + '/api/v1/create_zigbee_report', {
        'csrfmiddlewaretoken': csrftoken,
        'report_type': filetype,
        'filename': filename
    }).done(function (d) {
        let new_filename;
        if (typeof (d['error']) != 'undefined') {
            swal("Error", "Something went wrong. The requests was not a POST", "error");
        } else {
            swal("Started", "Your report/file is being generated and should open automatically. (Reload the page to see the file selector)", "success");

            new_filename = filename.split('.').slice(0, -1).join('.');
            if (filetype === "plain") {
                filetype = "txt";
            }
            if (filetype === "ps") {
                filetype = "pdf";
            }

            var checkFileInterval = setInterval(function () {
                $.get('/static/zigbee_reports/' + new_filename + '.' + filetype)
                    .done(function () {
                        console.log("File created")
                        clearInterval(checkFileInterval); // Stop polling
                        window.open(`/static/zigbee_reports/${new_filename}.${filetype}`, '_blank');
                    });
            }, 3000);
        }
    });
}

function open_zigbee_report(filename, filetype) {
    let new_filename = filename.split('.').slice(0, -1).join('.');
    window.open(`/static/zigbee_reports/${new_filename}.${filetype}`, '_blank');
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
                    color = '#1565C0';
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
            // $('#hostlabelbb'+i).addClass(color);
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

function ble_info() {
    $('#modaltitle').html('Bluetooth Low Energy (BLE) information and security considerations');
    $('#modalbody').html(`
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; }
        h1, h2 { color: #1565C0; font-size: 18pt; }
        h3 { color: #1565C0; font-size: 16pt; }
        p { text-align: justify; }
        a { color: #1565C0; }
        ul { list-style-type: square; }
        .toc { background-color: #f9f9f9; border: 1px solid #ccc; padding: 10px 10px 10px 30px; max-width: 400px; margin-left: 40px;}
        img { max-width: 100%; height: auto; text-align: center; display:block;}
        table, th, td {
            border: 0;
            border-collapse: collapse;
            padding: 0;
            margin: 0; 
        .tg  {border:none;border-collapse:collapse;border-spacing:0; padding: 5px;}
        .tg td{background-color:#fff;border-color:#ccc;border-style:solid;border-width:0px;color:#333;
          font-family:Arial, sans-serif;font-size:14px;overflow:hidden;padding:10px 5px;word-break:normal; padding: 5px;}
        .tg th{background-color:#f0f0f0;border-color:#ccc;border-style:solid;border-width:0px;color:#333;
          font-family:Arial, sans-serif;font-size:14px;font-weight:normal;overflow:hidden;padding:10px 5px;word-break:normal; padding: 5px;}
        .tg .tg-lboi{border-color:inherit;text-align:left;vertical-align:middle}
        .tg .tg-72fj{border-color:inherit;font-size:16px;font-weight:bold;text-align:center;vertical-align:middle}
        .tg .tg-uzvj{border-color:inherit;font-weight:bold;text-align:center;vertical-align:middle}
    </style>  
      
    <div class="toc">
        <h2>Table of Contents</h2>
        <ul>
            <li><a style="color: #1565C0;" href="#introduction">Introduction to BLE</a></li>
            <li><a style="color: #1565C0;" href="#features">Key Features and Advantages</a></li>
            <li><a style="color: #1565C0;" href="#gatt">Generic Attribute Profile (GATT)</a></li>
            <li><a style="color: #1565C0;" href="#gap">Generic Access Profile (GAP)</a></li>
            <li><a style="color: #1565C0;" href="#security">Security in BLE</a></li>
            <li><a style="color: #1565C0;" href="#security-issues">Security Issues and Considerations</a></li>
            <li><a style="color: #1565C0;" href="#things_to_look_for">Things to look out for</a></li>
        </ul>
    </div>
     <br>
        
    <h2 id="introduction">Introduction to BLE</h2>
    Bluetooth Low Energy (BLE), also known as Bluetooth LE or Bluetooth Smart, is a wireless personal area 
    network technology designed for applications in healthcare, fitness, beacon technology, security, and home 
    entertainment. It is <b>independent of classic Bluetooth</b> and was integrated into Bluetooth 4.0 in December 2009 
    as Bluetooth Low Energy.<br>
    <center><img class="center" style="width: 30%;" src="/static/img/ble_info/ble_vs_bl_classic.png" alt="Supported devices and platforms for BLE"></center>
    
    <br><br>
        
    <h2 id="features">Key Features and Advantages</h2>
    BLE uses the 2.4 GHz radio frequency band, similar to classic Bluetooth. However, it employs a simpler 
    modulation system, making it different from the classic version. This enables dual-mode devices to share 
    a single radio antenna. The BLE 4.0 specification allows devices to support either or both of the LE and BR/EDR 
    systems. BLE devices are broadly categorized into 'Bluetooth Smart Ready' - indicating dual-mode compatibility, 
    and 'Bluetooth Smart' - indicating LE-only devices.<br>
    BLE is natively supported by various mobile operating systems including iOS, Android, Windows Phone, 
    as well as desktop operating systems like macOS, Linux, and different versions of Windows. 
    This wide support contributes to its popularity across different device types and platforms.
    While Bluetooth Classic specifies a full stack with its applications, such as phone book access or file transfer,
    BLE only employs a basic stack with a set of defined profiles (see. image 1).
    <img src="" alt="Supported devices and platforms for BLE">
    
    <br><br>
    
    <h2 id="gatt">Generic Attribute Profile (GATT)</h2>
    GATT defines the way that two Bluetooth Low Energy devices transfer data back and forth using concepts called 
    Services and Characteristics. It makes use of a generic data protocol called the Attribute Protocol (ATT), 
    which is used to store Services, Characteristics and related data in a simple lookup table using 16-bit IDs 
    for each entry in the table. GATT comes into play after a dedicated connection is established between devices (see.
    chapter on GAP).<br>
    A peripheral (e.g. a sensor) is called the GATT server and it holds the ATT lookup data as well as service and 
    characteristic definitions. A central device (e.g. a phone) on the other hand is the GATT client and sends requests 
    to a GATT server.
    <center><img class="center" style="width: 30%;" src="/static/img/ble_info/gatt_topo.png" alt="BLE Connected Topology"></center>
    
    <h3>Attributes, Services and Characteristics</h3>
    GATT transactions in BLE are based on high-level, nested objects called Profiles, Services and Characteristics.
    An attribute consists of a Handle, a Type, Permission and a Value, while Services group conceptually related 
    attributes.
    Profiles do not exist on the BLE peripheral, it just predefines a collection of Services. The list for all GATT-
    based profiles can be seen <a href="https://www.bluetooth.com/specifications/specs/">here</a>.
    Characteristics are the lowest level concepts in GATT. They represent a container for user data. Like services
    characteristics have predefined 16-bit or 128-bit UUIDs. There are also predifined standard characteristics which 
    ensure interoperability across BLE-hardware and software. Further, there are multiple permissions for characteristics:
    <br><br>
    <table style="margin-left: 20px; max-width: fit-content;">
            <tr>
            <td><strong>Read</strong></td>
            <td>Allows the characteristic to be read.</td>
            </tr>
            <tr>
            <td><strong>Write</strong></td>
            <td>Permits writing to the characteristic.</td>
            </tr>
            <tr>
            <td><strong>Write Without Response &nbsp&nbsp&nbsp&nbsp</strong></td>
            <td> Enables writing to the characteristic without requiring a response from the receiver.</td>
            </tr>
            <tr>
            <td><strong>Signed Write</strong></td>
            <td>Allows writing to the characteristic with an authenticated signature.</td>
            </tr>
            <tr>
            <td><strong>Notify</strong></td>
            <td>Permits the characteristic to notify a connected device when its value changes.</td>
            </tr>
            <tr>
            <td><strong>Indicate</strong></td>
            <td>Enables the characteristic to indicate to a connected device when its value changes requiring an acknowledgment.</td>
            </tr>
            <tr>
            <td><strong>Authenticated Read</strong></td>
            <td>Allows reading the characteristic with authentication.</td>
            </tr>
            <tr>
            <td><strong>Authenticated Write</strong></td>
            <td>Permits writing to the characteristic with authentication.</td>
            </tr>
            <tr>
            <td><strong>Extended Properties</strong></td>
            <td>Defines additional properties of the characteristic.</td>
            </tr>
            <tr>
            <td><strong>Broadcast</strong></td>
            <td>Enables broadcasting of the characteristic’s value.</td>
            </tr>
    </table>
    
    <br><br>
    
    <h2 id="gap">Generic Access Profile (GAP)</h2>
    The Generic Acces Profile (GAP) is used for device discovery, broadcasting data, establishing connections as well
    as name discovery, connection parameter updates etc. Also GAP specifies four roles for devices: Broadcaster,
    Observer, Central and Peripheral. <br>
    To announce oneself devices use advertising packets. Connectable, non-connectable, scannable, non-scannable, 
    directed and undirected are esablished as advertising properties. Furthermore, non-discoverable, limited 
    discoverable and general discoverable are possible discoverable modes.
    <br><br>
    <center><img class="center" style="width: 50%;" src="/static/img/ble_info/ble_addr_types.png" alt="BLE address types"></center>
    <br>
    <center><img class="center" style="width: 40%;" src="/static/img/ble_info/ble_addr_types_2.png" alt="BLE address types - how do differentiate"></center>
    
    <br><br>
    
    <h2 id="security">Security in BLE</h2>
    BLE employs 4 security levels in Security Mode 1: No security, unauthenticated encryption, authenticated encryption and 
    authenticated encryption with Secure Connections pairing. In Security Mode 2 there is Unauthenticated data signing
    and Authenticated data signing.
    BLE incorporates robust security features designed to protect against various cyber threats. It achieves 
    this through secure pairing methods, encryption, and privacy features. Despite these mechanisms, 
    vulnerabilities exist, particularly during the pairing process and in legacy BLE connections.<br>
    BLE faces two common types of cyberattacks: passive eavesdropping and man-in-the-middle attacks. Passive 
    eavesdropping involves unauthorized access to data transmission, while man-in-the-middle attacks involve 
    intercepting and possibly altering data between devices. BLE Secure connections are inherently protected 
    against passive eavesdropping but require careful implementation of pairing methods to safeguard against 
    man-in-the-middle attacks.<br>
    The pairing process in BLE is crucial for establishing secure connections. It involves several phases where 
    devices exchange keys and authentication data. Supported pairing methods are just works, passkey entry, numeric
    comparison and out of band. The pairing methods depend on device capabilities however. The bonding process, 
    which is optional, stores this authentication data for future secure reconnections. However, vulnerabilities exist, 
    particularly during the initial phases where data exchange is not encrypted.<br>
    <br>
<table class="tg">
<thead>
  <tr>
    <th class="tg-lboi"></th>
    <th class="tg-72fj" colspan="5">Initiator&nbsp;&nbsp;</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-uzvj">Responder</td>
    <td class="tg-uzvj">DisplayOnly</td>
    <td class="tg-uzvj">Display YesNo</td>
    <td class="tg-uzvj">Keyboard Only</td>
    <td class="tg-uzvj">NoInput NoOutput</td>
    <td class="tg-uzvj">Keyboard Display</td>
  </tr>
  <tr>
    <td class="tg-uzvj">Display Only</td>
    <td class="tg-lboi">Just Works <br>Unauthenticated</td>
    <td class="tg-lboi">Just Works<br>Unauthenticated</td>
    <td class="tg-lboi">Passkey Entry: responder displays, initiator inputs <br>Authenticated</td>
    <td class="tg-lboi">Just Works <br>Unauthenticated</td>
    <td class="tg-lboi">Passkey Entry: responder displays, initiator inputs <br>Authenticated</td>
  </tr>
  <tr>
    <td class="tg-uzvj" rowspan="2">Display YesNo</td>
    <td class="tg-lboi" rowspan="2">Just Works <br>Unauthenticated</td>
    <td class="tg-lboi">Just Works (For LE Legacy Pairing) <br>Unauthenticated</td>
    <td class="tg-lboi" rowspan="2">Passkey Entry: responder displays, initiator inputs<br>Authenticated<br></td>
    <td class="tg-lboi" rowspan="2">Just Works<br>Unauthenticated</td>
    <td class="tg-lboi">Passkey Entry (For LE Legacy Pairing): responder displays, initiator inputs <br>Authenticated</td>
  </tr>
  <tr>
    <td class="tg-lboi">Numeric Comparison (For LE Secure Connections) <br>Authenticated</td>
    <td class="tg-lboi">Numeric Comparison (For LE Secure Connections)<br>Authenticated</td>
  </tr>
  <tr>
    <td class="tg-uzvj">Keyboard Only</td>
    <td class="tg-lboi">Passkey Entry: initiator displays, responder inputs <br>Authenticated</td>
    <td class="tg-lboi">Passkey Entry: initiator displays, responder inputs <br>Authenticated</td>
    <td class="tg-lboi">Passkey Entry: initiator and responder inputs <br>Authenticated</td>
    <td class="tg-lboi">Just Works<br>Unauthenticated</td>
    <td class="tg-lboi">Passkey Entry: initiator displays, responder inputs<br>Authenticated</td>
  </tr>
  <tr>
    <td class="tg-uzvj">Noinput NoOutput</td>
    <td class="tg-lboi">Just Works<br>Unauthenticated</td>
    <td class="tg-lboi">Just Works<br>Unauthenticated</td>
    <td class="tg-lboi">Just Works<br>Unauthenticated</td>
    <td class="tg-lboi">Just Works<br>Unauthenticated</td>
    <td class="tg-lboi">Just Works<br>Unauthenticated</td>
  </tr>
  <tr>
    <td class="tg-uzvj" rowspan="2">Keyboard Display</td>
    <td class="tg-lboi" rowspan="2">Passkey Entry: initiator displays, responder inputs<br>Authenticated<br></td>
    <td class="tg-lboi">Passkey Entry (For LE Legacy Pairing): initiator displays, responder inputs <br>Authenticated</td>
    <td class="tg-lboi" rowspan="2">Passkey Entry: responder displays, initiator inputs<br>Authenticated</td>
    <td class="tg-lboi" rowspan="2">Just Works<br>Unauthenticated</td>
    <td class="tg-lboi">Passkey Entry (For LE Legacy Pairing): initiator displays, responder inputs <br>Authenticated</td>
  </tr>
  <tr>
    <td class="tg-lboi">Numeric Comparison (For LE Secure Connections)<br>Authenticated</td>
    <td class="tg-lboi">Numeric Comparison (For LE Secure Connections) <br>Authenticated</td>
  </tr>
</tbody>
</table>
    <br>
    BLE security is anchored on three types of keys: the Long Term Key (LTK) for encryption, the Connection 
    Signature Resolving Key (CSRK) for data signing, and the Identity Resolving Key (IRK) for device privacy. 
    These keys play critical roles in ensuring the confidentiality, integrity, and privacy of the BLE communication.
    Furthermore, there is also the Short Term Key (STK). BLE uses AES with 128-bit keys for encryption. Data signing with the CSRK 
    ensures data integrity and authenticity. Additionally, BLE employs Resolvable Private Addresses (RPAs), 
    generated using the IRK, to protect device privacy and prevent unauthorized tracking.
    
        <br><br>
    
    <h2 id="security-issues">Security Issues and Considerations</h2>
    Users should be aware of the potential vulnerabilities in BLE, especially during pairing and in devices with 
    outdated BLE versions. These vulnerabilities can expose users to risks like eavesdropping and data manipulation.
    It is essential to use secure pairing methods and keep BLE devices updated. Understanding the types of keys 
    and their roles in BLE security can also help users in making informed decisions about their devices.
    Users are advised to use devices with the latest BLE versions for enhanced security. They should also be 
    cautious with the types of devices they connect to and ensure secure settings are enabled, especially in 
    environments where sensitive data is transmitted.<br>
   
        <br><br>
    
    <h2 id="things_to_look_for">Things to look out for</h2>
    <ul>
        <li>- Is the device discoverable/connectable? Should it be? And when?</li>
        <li>- Is the device trackable (address type)?</li>
        <li>- What capabilities are present and which flags are set (paring methods, Secure Connections)?</li>
        <li>- What security mode is used by the connection?</li>
        <li>- Are critical attributes accessible without proper security level?</li>
        <li>- Do the keys (TK, STK, LTK, etc.) change?</li>
        <li>- Is data written to attributes parsed correctly?</li>
        <li>- What use cases are there? Is there a potential vulnerable application layer protocol?</li>
        <li>- Should other applications be able to interact with the bonded device?</li>
        <li>- Is the power relevant? Are power draining attacks possible? (connection parameters, advertising intervals, 
        TX power, timeouts, etc.)</li>
    </ul>
        `
    );
    $('#modalfooter').html('<button class="modal-close waves-effect waves-green btn grey">Close</button>');
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
        'nuances. However, it serves as a baseline for the National Vulnerability Database (NVD) that provides such details.' +
        'Over the years, the CVE system has evolved, embracing new structures to encapsulate more information and adapt ' +
        'to the complexity of cybersecurity landscapes. The initial flat structure has morphed into a more ' +
        'hierarchical model, allowing for better organization and identification of vulnerabilities.<br>' +
        'Now, why should you concern yourself with CVEs? The answer lies in the adoption ' +
        'of smart home devices and IoT (Internet of Things) technologies. Today\'s home networks are no longer confined ' +
        'to computers and smartphones. They now encompass a lot of devices ranging from smart thermostats, ' +
        'security cameras, smart TVs, to intelligent refrigerators. Each of these devices, being a node on the network, ' +
        'presents a potential entry point for malicious actors if they harbor vulnerabilities.<br><br>' +
        'The relevance of CVEs can be summarized into:<br>' +
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