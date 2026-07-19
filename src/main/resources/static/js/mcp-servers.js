$(function () {
    var blankToNull = function ($form, name) {
        var v = $form.find('[name=' + name + ']').val();
        return v ? v : null;
    };

    $('#registerServerForm').on('submit', function (e) {
        e.preventDefault();
        var $form = $(this);
        var payload = {
            name: $form.find('[name=name]').val(),
            transportType: $form.find('[name=transportType]').val(),
            endpointUrl: blankToNull($form, 'endpointUrl'),
            command: blankToNull($form, 'command'),
            args: blankToNull($form, 'args'),
            stdioEnvAllowlist: blankToNull($form, 'stdioEnvAllowlist'),
            owner: blankToNull($form, 'owner'),
            environment: blankToNull($form, 'environment'),
            toolGroup: blankToNull($form, 'toolGroup')
        };
        $.ajax({url: '/api/mcp-servers', method: 'POST', contentType: 'application/json', data: JSON.stringify(payload)})
            .done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Registration failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    $('#serversTable').on('click', '.btn-discover', function () {
        var id = $(this).closest('tr').data('server-id');
        $.post('/api/mcp-servers/' + id + '/discover')
            .done(function (data) {
                showAlert('Discovery complete: ' + data.discoveredOrUpdatedTools.length + ' tool(s) seen, '
                    + data.removedTools.length + ' removed.', 'success');
            })
            .fail(function (xhr) { showAlert('Discovery failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    $('#authForm').on('submit', function (e) {
        e.preventDefault();
        var $form = $(this);
        var id = $form.find('[name=mcpServerId]').val();
        var payload = {
            authMode: $form.find('[name=authMode]').val(),
            oauthIssuer: blankToNull($form, 'oauthIssuer'),
            oauthResource: blankToNull($form, 'oauthResource'),
            oauthClientId: blankToNull($form, 'oauthClientId'),
            oauthClientSecretRef: blankToNull($form, 'oauthClientSecretRef'),
            oauthScopes: blankToNull($form, 'oauthScopes')
        };
        $.ajax({url: '/api/mcp-servers/' + id + '/auth', method: 'PATCH', contentType: 'application/json', data: JSON.stringify(payload)})
            .done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Saving auth config failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    $('#grantConsentForm').on('submit', function (e) {
        e.preventDefault();
        var $form = $(this);
        var expiresAt = $form.find('[name=expiresAt]').val();
        var payload = {
            agentId: Number($form.find('[name=agentId]').val()),
            mcpServerId: Number($form.find('[name=mcpServerId]').val()),
            toolName: blankToNull($form, 'toolName'),
            actionCategory: blankToNull($form, 'actionCategory'),
            expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null
        };
        $.ajax({url: '/api/mcp-consents', method: 'POST', contentType: 'application/json', data: JSON.stringify(payload)})
            .done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Grant failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    $('#consentsTable').on('click', '.btn-consent-revoke', function () {
        if (!window.confirm('Revoke this MCP consent?')) {
            return;
        }
        var id = $(this).closest('tr').data('consent-id');
        $.post('/api/mcp-consents/' + id + '/revoke')
            .done(function () { location.reload(); })
            .fail(function (xhr) { showAlert('Revoke failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });

    function refreshStdioStatus($row) {
        var id = $row.data('server-id');
        var $badge = $row.find('.stdio-status-badge');
        var $detail = $row.find('.stdio-status-detail');
        if ($badge.length === 0) {
            return;
        }
        $.get('/api/mcp-servers/' + id + '/stdio/status')
            .done(function (data) {
                if (data.running) {
                    $badge.removeClass('status-badge-pending status-badge-rejected').addClass('status-badge-approved').text('running');
                    $detail.text('pid ' + data.pid);
                } else {
                    $badge.removeClass('status-badge-pending status-badge-approved').addClass('status-badge-rejected').text('stopped');
                    $detail.text('');
                }
            })
            .fail(function () {
                $badge.text('unknown');
            });
    }

    $('#serversTable tr[data-server-id]').each(function () {
        refreshStdioStatus($(this));
    });

    $('#serversTable').on('click', '.btn-stdio-start, .btn-stdio-stop', function () {
        var $row = $(this).closest('tr');
        var id = $row.data('server-id');
        var action = $(this).hasClass('btn-stdio-start') ? 'start' : 'stop';
        $.post('/api/mcp-servers/' + id + '/stdio/' + action)
            .done(function () { refreshStdioStatus($row); })
            .fail(function (xhr) { showAlert('Stdio ' + action + ' failed: ' + (xhr.responseJSON ? xhr.responseJSON.error : xhr.statusText), 'danger'); });
    });
});
