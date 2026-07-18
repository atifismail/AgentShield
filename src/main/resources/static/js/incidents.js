$(function () {
    $('[data-incident-status]').on('click', function () {
        var id = $(this).data('incident-id');
        var status = $(this).data('incident-status');
        $.ajax({
            url: '/api/incidents/' + id + '/status', method: 'PATCH', contentType: 'application/json',
            data: JSON.stringify({status: status})
        }).done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Action failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });
});
