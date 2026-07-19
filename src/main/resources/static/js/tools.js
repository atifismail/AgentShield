$(function () {
    $('#registerToolForm').on('submit', function (e) {
        e.preventDefault();
        var payload = {
            name: $(this).find('[name=name]').val(),
            type: $(this).find('[name=type]').val(),
            toolGroup: $(this).find('[name=toolGroup]').val(),
            endpointUrl: $(this).find('[name=endpointUrl]').val(),
            description: $(this).find('[name=description]').val(),
            schemaJson: $(this).find('[name=schemaJson]').val()
        };
        $.ajax({url: '/api/tools', method: 'POST', contentType: 'application/json', data: JSON.stringify(payload)})
            .done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Failed to register tool: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    $('#toolsTable').on('click', '.btn-approve, .btn-reject', function () {
        var id = $(this).closest('tr').data('tool-id');
        var action = $(this).hasClass('btn-approve') ? 'approve' : 'reject';
        $.ajax({
            url: '/api/tools/' + id + '/' + action, method: 'POST', contentType: 'application/json',
            data: JSON.stringify({decidedBy: currentUser()})
        }).done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Action failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    $('#verifySignatureForm').on('submit', function (e) {
        e.preventDefault();
        var $form = $(this);
        var id = $form.data('tool-id');
        var payload = {
            bundleJson: $form.find('[name=bundleJson]').val(),
            expectedIdentity: $form.find('[name=expectedIdentity]').val() || null,
            expectedIssuer: $form.find('[name=expectedIssuer]').val() || null
        };
        $.ajax({url: '/api/tools/' + id + '/provenance/verify', method: 'POST', contentType: 'application/json', data: JSON.stringify(payload)})
            .done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Verification failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    $('.btn-provenance-revoke').on('click', function () {
        var reason = window.prompt('Reason for revoking this tool\'s provenance:');
        if (!reason) {
            return;
        }
        var id = $(this).data('tool-id');
        $.ajax({url: '/api/tools/' + id + '/provenance/revoke', method: 'POST', contentType: 'application/json', data: JSON.stringify({reason: reason})})
            .done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Revoke failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });
});
