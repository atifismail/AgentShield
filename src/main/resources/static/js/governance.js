$(function () {
    function rangeOrAlert() {
        var from = $('#fromInput').val();
        var to = $('#toInput').val();
        if (!from || !to) {
            showAlert('Choose both a "from" and "to" date/time.', 'warning');
            return null;
        }
        return {
            from: new Date(from).toISOString(),
            to: new Date(to).toISOString()
        };
    }

    $('#viewJsonBtn').on('click', function () {
        var range = rangeOrAlert();
        if (!range) {
            return;
        }
        window.open('/api/governance/report?from=' + encodeURIComponent(range.from) + '&to=' + encodeURIComponent(range.to), '_blank');
    });

    $('#downloadMarkdownBtn').on('click', function () {
        var range = rangeOrAlert();
        if (!range) {
            return;
        }
        window.location.href = '/api/governance/report?format=markdown&from=' + encodeURIComponent(range.from) + '&to=' + encodeURIComponent(range.to);
    });
});
