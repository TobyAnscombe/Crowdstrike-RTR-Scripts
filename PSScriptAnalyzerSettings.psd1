@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions'  # RTR scripts run non-interactively
    )
}
