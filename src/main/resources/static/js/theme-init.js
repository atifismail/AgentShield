(function () {
    var STORAGE_KEY = 'agentshield-theme';
    var theme = 'light';
    try {
        var stored = localStorage.getItem(STORAGE_KEY);
        if (stored === 'light' || stored === 'dark') {
            theme = stored;
        } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            theme = 'dark';
        }
    } catch (e) {
        // localStorage/matchMedia unavailable (e.g. privacy mode) -- fall back to light.
    }
    document.documentElement.setAttribute('data-bs-theme', theme);
})();
