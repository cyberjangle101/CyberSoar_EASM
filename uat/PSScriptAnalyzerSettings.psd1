# PSScriptAnalyzer settings for the UAT scripts (security-scan.yml runs them on every pull request).
# Every Error and Warning rule applies, including all the security rules, apart from three style
# rules that do not fit test scripts. Individual exceptions are suppressed in the code, with a reason.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # The scripts are run by hand or by the Release workflow, and their console output is the report.
        'PSAvoidUsingWriteHost',
        # Start-Agent, Stop-Lab and the like are test helpers, not cmdlets anyone runs with -WhatIf.
        'PSUseShouldProcessForStateChangingFunctions',
        # Empty catch blocks here are deliberate probes ("is an agent already answering on this port?").
        'PSAvoidUsingEmptyCatchBlock'
    )
}
