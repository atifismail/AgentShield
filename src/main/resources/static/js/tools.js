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
});
