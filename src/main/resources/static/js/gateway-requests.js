$(function () {
    var $button = $('#simulateBtn');
    if ($button.length === 0) {
        return;
    }
    var requestId = $button.closest('[data-gateway-request-id]').data('gateway-request-id');

    $button.on('click', function () {
        var $result = $('#simulateResult');
        $.get('/api/policies/replay/' + requestId).done(function (data) {
            var badgeClass = data.decisionChanged ? 'alert-warning' : 'alert-secondary';
            var html = '<div class="alert ' + badgeClass + ' mb-0">' +
                '<p class="mb-1"><strong>Original decision:</strong> ' + (data.originalDecision || '(none recorded)') +
                (data.originalReason ? ' — ' + data.originalReason : '') + '</p>' +
                '<p class="mb-0"><strong>Simulated decision (now):</strong> ' + data.simulatedDecision +
                ' [' + data.simulatedRuleId + '] — ' + data.simulatedReason + '</p>' +
                (data.decisionChanged ? '<p class="mb-0 mt-1"><em>The decision would be different under the current policy.</em></p>' : '') +
                '</div>';
            $result.removeClass('d-none').html(html);
        }).fail(function (xhr) {
            $result.removeClass('d-none').html('<div class="alert alert-danger mb-0">Simulation failed: ' +
                (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText) + '</div>');
        });
    });
});
