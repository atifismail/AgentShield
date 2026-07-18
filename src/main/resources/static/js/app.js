function readCookie(name) {
    var match = document.cookie.match('(?:^|; )' + name + '=([^;]*)');
    return match ? decodeURIComponent(match[1]) : null;
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
});
