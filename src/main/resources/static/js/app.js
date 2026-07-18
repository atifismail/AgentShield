function readCookie(name) {
    var match = document.cookie.match('(?:^|; )' + name + '=([^;]*)');
    return match ? decodeURIComponent(match[1]) : null;
}

/** Reads the signed-in username from the navbar (see layout/fragments.html #currentUserName). */
function currentUser() {
    var text = $('#currentUserName').text();
    return text ? text.trim() : 'system';
}

function showAlert(message, type) {
    $('#alertHost').html('<div class="alert alert-' + type + ' alert-dismissible fade show" role="alert">' +
        message + '<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>');
}

$(function () {
    var csrfToken = readCookie('XSRF-TOKEN');
    if (csrfToken) {
        $.ajaxSetup({
            beforeSend: function (xhr, settings) {
                var method = (settings.type || 'GET').toUpperCase();
                if (!/^(GET|HEAD|OPTIONS|TRACE)$/.test(method)) {
                    xhr.setRequestHeader('X-XSRF-TOKEN', csrfToken);
                }
            }
        });
    }

    $('.data-table').each(function () {
        $(this).DataTable({
            pageLength: 25,
            order: []
        });
    });

    $('[data-confirm]').on('click', function (e) {
        var message = $(this).data('confirm');
        if (!window.confirm(message)) {
            e.preventDefault();
        }
    });

    initDashboardChart();
    initAuditIntegrityCheck();
});

// Reads the inert JSON data island (see dashboard/index.html) rather than an inline <script>
// block, which the strict CSP (script-src 'self', no unsafe-inline) would silently block.
function initDashboardChart() {
    var ctx = document.getElementById('requestVolumeChart');
    var dataEl = document.getElementById('dashboard-chart-data');
    if (!ctx || !dataEl || !window.Chart) {
        return;
    }
    var series;
    try {
        series = JSON.parse(dataEl.textContent || '{}');
    } catch (e) {
        series = {labels: [], allow: [], deny: [], approval: []};
    }
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: series.labels || [],
            datasets: [
                {label: 'Allow', data: series.allow || [], backgroundColor: '#198754'},
                {label: 'Deny', data: series.deny || [], backgroundColor: '#dc3545'},
                {label: 'Approval required', data: series.approval || [], backgroundColor: '#ffc107'}
            ]
        },
        options: {responsive: true, scales: {x: {stacked: true}, y: {stacked: true, beginAtZero: true}}}
    });
}

function initAuditIntegrityCheck() {
    var $button = $('#verifyIntegrityBtn');
    if ($button.length === 0) {
        return;
    }
    $button.on('click', function () {
        var $result = $('#integrityResult');
        $.get('/api/audit/verify-integrity').done(function (data) {
            if (data.valid) {
                $result.removeClass('d-none alert-danger').addClass('alert-success')
                    .text('Audit chain verified: ' + data.eventsChecked + ' event(s) checked, no tampering detected.');
            } else {
                $result.removeClass('d-none alert-success').addClass('alert-danger')
                    .text('Audit chain verification FAILED at event #' + data.firstBrokenEventId + ': ' + data.reason);
            }
        }).fail(function () {
            $result.removeClass('d-none alert-success').addClass('alert-danger').text('Could not run integrity check.');
        });
    });
}
