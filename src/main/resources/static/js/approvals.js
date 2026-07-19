$(function () {
    $(document).on('click', '.btn-approve, .btn-reject', function () {
        var id = $(this).closest('[data-approval-id]').data('approval-id');
        var action = $(this).hasClass('btn-approve') ? 'approve' : 'reject';
        $.ajax({
            url: '/api/approvals/' + id + '/' + action, method: 'POST', contentType: 'application/json',
            data: JSON.stringify({decidedBy: currentUser()})
        }).done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Action failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });
});
