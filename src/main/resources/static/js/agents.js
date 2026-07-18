$(function () {
    $('#createAgentForm').on('submit', function (e) {
        e.preventDefault();
        var groups = $(this).find('[name=allowedToolGroups]').val();
        var payload = {
            name: $(this).find('[name=name]').val(),
            description: $(this).find('[name=description]').val(),
            owner: $(this).find('[name=owner]').val(),
            environment: $(this).find('[name=environment]').val(),
            allowedToolGroups: groups ? groups.split(',').map(function (s) { return s.trim(); }).filter(Boolean) : []
        };
        $.ajax({
            url: '/api/agents', method: 'POST', contentType: 'application/json', data: JSON.stringify(payload)
        }).done(function () {
            location.reload();
        }).fail(function (xhr) {
            showAlert('Failed to register agent: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger');
        });
    });

    $('#agentsTable').on('click', '.btn-enable, .btn-disable', function () {
        var id = $(this).closest('tr').data('agent-id');
        var action = $(this).hasClass('btn-enable') ? 'enable' : 'disable';
        $.post('/api/agents/' + id + '/' + action).done(function () {
            location.reload();
        }).fail(function (xhr) {
            showAlert('Action failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger');
        });
    });

    $('#agentsTable').on('click', '.btn-rotate', function () {
        var id = $(this).closest('tr').data('agent-id');
        $.post('/api/agents/' + id + '/rotate-token').done(function (data) {
            $('#tokenValue').text(data.token);
            new bootstrap.Modal('#tokenModal').show();
        }).fail(function (xhr) {
            showAlert('Rotate failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger');
        });
    });
});
