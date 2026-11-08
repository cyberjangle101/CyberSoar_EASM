# UAT for the v1.9.20 data sources (ip.thc.org, brand watch, archived files) against the initech.test
# part of the lab on 127.0.0.1:18100. Runs on a fresh lab: it does the first-time setup itself.
# Follows the data end to end: Settings form -> scan -> assets -> findings -> evidence -> System health
# -> report exports -> REST API and MCP, as an administrator and as a read-only viewer.
. "$PSScriptRoot\lib.ps1"
$B = 'http://127.0.0.1:18100'
for ($i = 0; $i -lt 180; $i++) { try { if ((Invoke-WebRequest -UseBasicParsing "$B/healthz" -TimeoutSec 2).StatusCode -eq 200) { break } } catch {}; Start-Sleep 1 }
$pw = (New-Secret 20) + '-Dd4'
Set-Content (OutPath 'sources-credentials.txt') -Encoding ascii -Value "lab admin: uatadmin / $pw"
function Flash([string]$html) { ([regex]::Match($html, '(?s)class="flash[^"]*"[^>]*>(.*?)</div>').Groups[1].Value -replace '<[^>]+>', '').Trim() }
function Post($s, [string]$path, [hashtable]$extra = @{}) { $pg = Invoke-Page $s $B '/'; $f = @{ csrf = (Get-Csrf $pg.b) }; foreach ($k in $extra.Keys) { $f[$k] = $extra[$k] }; Invoke-Page $s $B $path $f }
# Table rows only: the text before the first <tr> (filters, the Type list) is not a row.
function Row([string]$html, [string]$needle) { foreach ($row in ($html -split '<tr' | Select-Object -Skip 1)) { if ($row -match [regex]::Escape($needle)) { return $row } } }
function Dec([string]$s) { [Net.WebUtility]::HtmlDecode($s) }

# The main Settings form, read back as a browser would submit it (inputs, ticked boxes, selects, text areas).
function Get-SettingsForm($s) {
    $html = (Invoke-Page $s $B '/settings').b
    $form = [regex]::Match($html, '(?s)<form method="post" action="/settings" class="settings">(.*?)</form>').Groups[1].Value
    $pairs = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches($form, '<input\b[^>]*>')) {
        $t = $m.Value
        $name = [regex]::Match($t, '\bname="([^"]+)"').Groups[1].Value; if (-not $name) { continue }
        $type = [regex]::Match($t, '\btype="([^"]+)"').Groups[1].Value
        $val = Dec ([regex]::Match($t, '\bvalue="([^"]*)"').Groups[1].Value)
        if ($type -in 'checkbox', 'radio') { if ($t -match '\bchecked\b') { $pairs.Add(@($name, $(if ($val) { $val } else { 'on' }))) } ; continue }
        if ($type -in 'submit', 'button', 'file') { continue }
        $pairs.Add(@($name, $val))
    }
    foreach ($m in [regex]::Matches($form, '(?s)<select\b[^>]*name="([^"]+)"[^>]*>(.*?)</select>')) {
        $sel = [regex]::Match($m.Groups[2].Value, '<option[^>]*value="([^"]*)"[^>]*\bselected\b')
        if (-not $sel.Success) { $sel = [regex]::Match($m.Groups[2].Value, '<option[^>]*value="([^"]*)"') }
        $pairs.Add(@($m.Groups[1].Value, (Dec $sel.Groups[1].Value)))
    }
    foreach ($m in [regex]::Matches($form, '(?s)<textarea\b[^>]*name="([^"]+)"[^>]*>(.*?)</textarea>')) { $pairs.Add(@($m.Groups[1].Value, (Dec $m.Groups[2].Value))) }
    return , $pairs
}
function Save-SettingsForm($s, $pairs, [hashtable]$set, [string[]]$tick) {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in $pairs) { if (-not $set.ContainsKey($p[0]) -and $tick -notcontains $p[0]) { $out.Add($p) } }
    foreach ($k in $set.Keys) { $out.Add(@($k, $set[$k])) }
    foreach ($k in $tick) { $out.Add(@($k, 'on')) }
    $body = ($out | ForEach-Object { [uri]::EscapeDataString($_[0]) + '=' + [uri]::EscapeDataString([string]$_[1]) }) -join '&'
    $r = Invoke-WebRequest -UseBasicParsing -WebSession $s -Uri "$B/settings" -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -MaximumRedirection 5
    return $r.Content
}
function Wait-Idle($s) { for ($i = 0; $i -lt 150; $i++) { Start-Sleep 2; $t = (Invoke-Page $s $B '/targets').b; if ($t -notmatch '(?i)>Scanning<|>Queued<') { return $true } }; return $false }

# --- setup: admin and viewer
$a = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$r = Invoke-Page $a $B '/setup'
$null = Invoke-Page $a $B '/setup' @{ csrf = (Get-Csrf $r.b); code = (Get-LabSetupCode); username = 'uatadmin'; password = $pw; confirm = $pw }
$a = Connect-Agent $B 'uatadmin' $pw
$u = Invoke-Page $a $B '/users'
$null = Invoke-Page $a $B '/users' @{ csrf = (Get-Csrf $u.b); username = 'uatviewer'; password = "${pw}vw"; role = 'viewer' }
$vw = Connect-Agent $B 'uatviewer' "${pw}vw"

# --- NS-1: the new settings are on the Settings page, with sensible defaults, and save
$st = (Invoke-Page $a $B '/settings').b
Check 'NS-1.1' 'Settings shows ip.thc.org, brand watch, newly registered feed and archived files' (($st -match 'name="thc_enabled"') -and ($st -match 'name="lookalike_brand_ct"') -and ($st -match 'name="lookalike_brand_words"') -and ($st -match 'name="nrd_feed_url"') -and ($st -match 'name="nrd_feed_key"') -and ($st -match 'name="archive_exposure_enabled"'))
Check 'NS-1.2' 'brand watch ticked by default, archived files off by default' (($st -match '<input[^>]*name="lookalike_brand_ct"[^>]*checked') -and ($st -notmatch '<input[^>]*name="archive_exposure_enabled"[^>]*checked'))
Check 'NS-1.3' 'every new setting has a visible label' ((([regex]::Matches($st, '<label[^>]*>(?:(?!</label>).)*name="(thc_enabled|lookalike_brand_ct|archive_exposure_enabled)"', 'Singleline')).Count -eq 3) -or ($st -match 'for="thc_enabled"'))
$form = Get-SettingsForm $a
$saved = Save-SettingsForm $a $form @{ lookalike_brand_words = 'initrode' } @('thc_enabled', 'lookalike_enabled', 'lookalike_brand_ct', 'archive_exposure_enabled')
$st2 = (Invoke-Page $a $B '/settings').b
Check 'NS-1.4' 'saving ticks ip.thc.org, look-alikes, brand watch and archived files' (($st2 -match '<input[^>]*name="thc_enabled"[^>]*checked') -and ($st2 -match '<input[^>]*name="lookalike_enabled"[^>]*checked') -and ($st2 -match '<input[^>]*name="archive_exposure_enabled"[^>]*checked')) (Flash $saved)
Check 'NS-1.5' 'brand words saved' ($st2 -match 'initrode')
Check 'NS-1.6' 'saving the form kept unrelated settings (SMTP host still the lab mail server)' ($st2 -match 'name="smtp_host"[^>]*value="127\.0\.0\.1"')
$au = (Invoke-Page $a $B '/audit').b
Check 'NS-1.7' 'settings change audited' ($au -match 'settings')
Check 'NS-1.8' 'viewer cannot open Settings' ((Invoke-Page $vw $B '/settings').c -in 302, 303, 403)

# --- NS-2: System health lists the new connectors
$hp = (Invoke-Page $a $B '/health').b
Check 'NS-2.1' 'System health lists ip.thc.org, Brand watch (crt.sh), the feed and archived files' (($hp -match 'ip\.thc\.org') -and ($hp -match 'Brand watch \(crt\.sh\)') -and ($hp -match 'Newly registered domains feed') -and ($hp -match 'Wayback Machine \(archived files\)'))

# --- NS-3: scan initech.test and follow the data
$null = Post $a '/targets' @{ domain = 'initech.test' }
Check 'NS-3.1' 'scan of initech.test finished' (Wait-Idle $a)
$as = (Invoke-Page $a $B '/assets').b
Check 'NS-3.2' 'host known only to ip.thc.org is in the asset inventory' ($as -match 'files\.initech\.test')
Check 'NS-3.3' 'out-of-scope ip.thc.org name is not' ($as -notmatch 'unrelated\.example\.test')
$f = (Invoke-Page $a $B '/findings').b
$ar = Row $f 'Wayback'; if (-not $ar) { $ar = Row $f 'archived' }
Check 'NS-3.4' 'archived secrets on www.initech.test reported' (($f -match 'www\.initech\.test') -and ($f -match '(?i)archived')) ((Dec (($ar -replace '<[^>]+>', ' ') -replace '\s+', ' ')).Trim() | Select-Object -First 1)
$lk = Row $f 'initech-login.test'
Check 'NS-3.5' 'brand look-alike initech-login.test reported (fresh certificate, mail, web)' ([bool]$lk)
$aid = if ($ar -match '/findings/(\d+)/evidence') { $Matches[1] }
$ev = if ($aid) { Invoke-Page $a $B "/findings/$aid/evidence" } else { @{ c = 0; b = '' } }
Check 'NS-3.6' 'archived-file finding has an evidence page linking the Wayback capture' (($ev.c -eq 200) -and ($ev.b -match 'web\.archive\.org')) "finding $aid"
$lid = if ($lk -match '/findings/(\d+)/evidence') { $Matches[1] }
$lev = if ($lid) { Invoke-Page $a $B "/findings/$lid/evidence" } else { @{ c = 0; b = '' } }
Check 'NS-3.7' 'look-alike finding has an evidence page' ($lev.c -eq 200) "finding $lid"
Check 'NS-3.8' 'viewer sees the new findings' (((Invoke-Page $vw $B '/findings').b -match 'initech-login\.test'))
$hp2 = (Invoke-Page $a $B '/health').b
$thcRow = Row $hp2 'ip.thc.org'
Check 'NS-3.9' 'System health records the ip.thc.org call as working' ($thcRow -match '>\s*Connected\s*<') ((Dec (($thcRow -replace '<[^>]+>', ' ') -replace '\s+', ' ')).Trim())

# --- NS-4: reports and exports carry the new findings
$rep = Invoke-Page $a $B '/report?target=initech.test'
Check 'NS-4.1' 'report page includes the look-alike and archived findings' (($rep.c -eq 200) -and ($rep.b -match 'initech-login\.test') -and ($rep.b -match '(?i)archived'))
$csv = (Invoke-WebRequest -UseBasicParsing -WebSession $a "$B/report/findings.csv").Content
Check 'NS-4.2' 'findings.csv has archived-exposure and lookalike-domain rows' (($csv -match 'archived-exposure') -and ($csv -match 'lookalike-domain'))
$inv = (Invoke-WebRequest -UseBasicParsing -WebSession $a "$B/report/inventory.csv").Content
Check 'NS-4.3' 'inventory.csv includes files.initech.test' ($inv -match 'files\.initech\.test')
$pdf = Invoke-WebRequest -UseBasicParsing -WebSession $a "$B/report.pdf?target=initech.test"
Check 'NS-4.4' 'PDF report downloads' (($pdf.StatusCode -eq 200) -and ([Text.Encoding]::ASCII.GetString($pdf.RawContentStream.ToArray()[0..3]) -eq '%PDF'))
$sr = Invoke-WebRequest -UseBasicParsing -WebSession $a "$B/report/findings.sarif"
$sar = [Text.Encoding]::UTF8.GetString($sr.RawContentStream.ToArray()) # application/sarif+json arrives as bytes
Check 'NS-4.5' 'SARIF export includes the new finding types' (($sar -match '"ruleId":"archived-exposure"') -and ($sar -match '"ruleId":"lookalike-domain"'))

# --- NS-5: REST API and MCP (what an AI assistant sees)
$acct = Invoke-Page $a $B '/account'
$null = Invoke-Page $a $B '/account/tokens' @{ csrf = (Get-Csrf $acct.b); name = 'uat-viewer-token'; role = 'viewer' }
$acct2 = (Invoke-Page $a $B '/account').b
$tok = [regex]::Match($acct2, 'easm_[A-Za-z0-9_\-]+').Value
Check 'NS-5.1' 'viewer API token created and shown once' ([bool]$tok)
$hdr = @{ Authorization = "Bearer $tok" }
$fj = Invoke-RestMethod -Uri "$B/api/v1/findings?target=initech.test" -Headers $hdr
$types = @($fj.findings | ForEach-Object { $_.type }) + @($fj | Where-Object { $_.type } | ForEach-Object { $_.type })
Check 'NS-5.2' 'API findings include archived-exposure and lookalike-domain' (($types -contains 'archived-exposure') -and ($types -contains 'lookalike-domain')) (($types | Sort-Object -Unique) -join ',')
$aj = (Invoke-WebRequest -UseBasicParsing -Uri "$B/api/v1/assets?target=initech.test" -Headers $hdr).Content
Check 'NS-5.3' 'API assets include files.initech.test' ($aj -match 'files\.initech\.test')
$mh = @{ Authorization = "Bearer $tok"; Accept = 'application/json, text/event-stream' }
$init = Invoke-RestMethod -Uri "$B/mcp" -Method Post -Headers $mh -ContentType 'application/json' -Body '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"uat","version":"1"}}}'
Check 'NS-5.4' 'MCP initialize answers' ([bool]$init.result.serverInfo.name)
$call = Invoke-RestMethod -Uri "$B/mcp" -Method Post -Headers $mh -ContentType 'application/json' -Body '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_findings","arguments":{"target":"initech.test"}}}'
$mtext = ($call.result.content | ForEach-Object { $_.text }) -join "`n"
Check 'NS-5.5' 'MCP list_findings returns the look-alike and archived findings' (($mtext -match 'initech-login\.test') -and ($mtext -match '(?i)archived'))
$scan = Invoke-RestMethod -Uri "$B/mcp" -Method Post -Headers $mh -ContentType 'application/json' -Body '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"request_scan","arguments":{"target":"initech.test"}}}'
Check 'NS-5.6' 'viewer token cannot start a scan through MCP' ([bool]$scan.error -or [bool]$scan.result.isError)

# --- NS-6: a rescan keeps the findings open (no flapping); switching archived files off closes its findings, says so and audits it
$null = Post $a '/targets/1/scan' @{}
$null = Wait-Idle $a
$f2 = (Invoke-Page $a $B '/findings').b
Check 'NS-6.1' 'rescan: archived and look-alike findings still open' (($f2 -match 'initech-login\.test') -and ($f2 -match '(?i)archived'))
$form = Get-SettingsForm $a
$off = Save-SettingsForm $a ($form | Where-Object { $_[0] -ne 'archive_exposure_enabled' }) @{} @()
Check 'NS-6.2' 'switching archived files off closes its open findings and says so' ((Flash $off) -match 'Closed 2 archived files finding') (Flash $off)
Check 'NS-6.3' 'the closing is audited' ((Invoke-Page $a $B '/audit').b -match 'the archived files check was switched off')
$fj2 = Invoke-RestMethod -Uri "$B/api/v1/findings?target=initech.test&status=open" -Headers $hdr
Check 'NS-6.4' 'look-alike findings stay open (their check is still on)' (@($fj2.findings | Where-Object { $_.type -eq 'lookalike-domain' }).Count -ge 1)

$script:Results | Export-Csv (OutPath 'sources-results.csv') -NoTypeInformation
"{0} passed, {1} failed" -f @($script:Results | Where-Object Result -eq 'PASS').Count, @($script:Results | Where-Object Result -eq 'FAIL').Count
