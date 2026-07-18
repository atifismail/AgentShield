$(function () {
    $('table').on('click', '.btn-toggle, .btn-toggle-off', function () {
        var id = $(this).closest('tr').data('policy-id');
        var enable = $(this).hasClass('btn-toggle');
        $.post('/api/policies/' + id + '/' + (enable ? 'enable' : 'disable')).done(function () {
            location.reload();
        }).fail(function (xhr) { showAlert('Action failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    $('#dryRunForm').on('submit', function (e) {
        e.preventDefault();
        var payload = {
            agentId: Number($(this).find('[name=agentId]').val()),
            toolId: Number($(this).find('[name=toolId]').val()),
            actionCategory: $(this).find('[name=actionCategory]').val(),
            targetEnvironment: $(this).find('[name=targetEnvironment]').val(),
            payloadSizeBytes: Number($(this).find('[name=payloadSizeBytes]').val())
        };
        $.ajax({url: '/api/policies/dry-run', method: 'POST', contentType: 'application/json', data: JSON.stringify(payload)})
            .done(function (data) {
                $('#dryRunResult').html('<div class="alert alert-info"><strong>' + data.decision + '</strong> (' + data.ruleId + ')<br/>' + (data.reason || '') + '</div>');
            })
            .fail(function (xhr) {
                showAlert('Dry-run failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger');
            });
    });

    $('#createOverrideForm').on('submit', function (e) {
        e.preventDefault();
        var $form = $(this);
        var blankToNull = function (name) {
            var v = $form.find('[name=' + name + ']').val();
            return v ? v : null;
        };
        var payload = {
            actionCategory: blankToNull('actionCategory'),
            targetEnvironment: blankToNull('targetEnvironment'),
            toolGroup: blankToNull('toolGroup'),
            agentName: blankToNull('agentName'),
            decision: $form.find('[name=decision]').val(),
            reason: $form.find('[name=reason]').val(),
            priority: Number($form.find('[name=priority]').val())
        };
        $.ajax({url: '/api/policy-overrides', method: 'POST', contentType: 'application/json', data: JSON.stringify(payload)})
            .done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Failed to add override: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    $('#overridesTable').on('click', '.btn-override-toggle, .btn-override-toggle-off', function () {
        var id = $(this).closest('tr').data('override-id');
        var enable = $(this).hasClass('btn-override-toggle');
        $.post('/api/policy-overrides/' + id + '/' + (enable ? 'enable' : 'disable')).done(function () {
            location.reload();
        }).fail(function (xhr) { showAlert('Action failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    $('#overridesTable').on('click', '.btn-override-delete', function () {
        if (!window.confirm('Delete this policy override?')) {
            return;
        }
        var id = $(this).closest('tr').data('override-id');
        $.ajax({url: '/api/policy-overrides/' + id, method: 'DELETE'}).done(function () {
            location.reload();
        }).fail(function (xhr) { showAlert('Delete failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });
});
