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
    initDlpCharts();
    initCodeTrustChart();
    initSiemCoverageChart();
    initSocValidationChart();
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

// Reads the inert JSON data island (see dlp/index.html) rather than an inline <script> block,
// same CSP-safe convention as initDashboardChart().
function initDlpCharts() {
    var dataEl = document.getElementById('dlp-chart-data');
    if (!dataEl || !window.Chart) {
        return;
    }
    var series;
    try {
        series = JSON.parse(dataEl.textContent || '{}');
    } catch (e) {
        series = {labels: [], counts: [], categoryLabels: [], categoryCounts: []};
    }
    var trendCtx = document.getElementById('dlpFindingsChart');
    if (trendCtx) {
        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: series.labels || [],
                datasets: [{label: 'Findings', data: series.counts || [], borderColor: '#0d6efd', tension: 0.2}]
            },
            options: {responsive: true, scales: {y: {beginAtZero: true}}}
        });
    }
    var categoryCtx = document.getElementById('dlpCategoryChart');
    if (categoryCtx) {
        new Chart(categoryCtx, {
            type: 'doughnut',
            data: {
                labels: series.categoryLabels || [],
                datasets: [{
                    data: series.categoryCounts || [],
                    backgroundColor: ['#0d6efd', '#dc3545', '#ffc107', '#198754', '#6610f2', '#20c997', '#fd7e14', '#6f42c1', '#d63384', '#0dcaf0', '#adb5bd', '#212529']
                }]
            },
            options: {responsive: true}
        });
    }
}

function initCodeTrustChart() {
    var dataEl = document.getElementById('codetrust-chart-data');
    var ctx = document.getElementById('codeTrustChart');
    if (!dataEl || !ctx || !window.Chart) {
        return;
    }
    var series;
    try {
        series = JSON.parse(dataEl.textContent || '{}');
    } catch (e) {
        series = {labels: [], passed: [], blocked: []};
    }
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: series.labels || [],
            datasets: [
                {label: 'Passed', data: series.passed || [], backgroundColor: '#198754'},
                {label: 'Blocked', data: series.blocked || [], backgroundColor: '#dc3545'}
            ]
        },
        options: {responsive: true, scales: {x: {stacked: true}, y: {stacked: true, beginAtZero: true}}}
    });
}

// Reads the inert JSON data island (see siem/coverage.html) rather than an inline <script> block,
// same CSP-safe convention as initDashboardChart().
function initSiemCoverageChart() {
    var dataEl = document.getElementById('siem-coverage-chart-data');
    var ctx = document.getElementById('siemCoverageChart');
    if (!dataEl || !ctx || !window.Chart) {
        return;
    }
    var series;
    try {
        series = JSON.parse(dataEl.textContent || '{}');
    } catch (e) {
        series = {sourceLabels: [], sourceCounts: []};
    }
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: series.sourceLabels || [],
            datasets: [{
                data: series.sourceCounts || [],
                backgroundColor: ['#0d6efd', '#dc3545', '#198754', '#ffc107', '#6610f2']
            }]
        },
        options: {responsive: true}
    });
}

// Reads the inert JSON data island (see siem/validation.html) rather than an inline <script>
// block, same CSP-safe convention as initDashboardChart().
function initSocValidationChart() {
    var dataEl = document.getElementById('soc-validation-chart-data');
    var ctx = document.getElementById('socValidationChart');
    if (!dataEl || !ctx || !window.Chart) {
        return;
    }
    var series;
    try {
        series = JSON.parse(dataEl.textContent || '{}');
    } catch (e) {
        series = {labels: [], counts: []};
    }
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: series.labels || [],
            datasets: [{
                label: 'Alert import result',
                data: series.counts || [],
                backgroundColor: ['#198754', '#dc3545', '#ffc107']
            }]
        },
        options: {responsive: true, scales: {y: {beginAtZero: true}}}
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
