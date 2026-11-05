# Demo video and screenshots

The README's screenshots and tour (`docs/images/`) and the full-length demo video are made from the
**UAT lab**: a made-up company, `acme-corp.test`, with fake certificate, DNS and exposure-data sources
and realistic weaknesses (a dangling CNAME, exposed services, CVEs, weak email security). Nothing real
is scanned, so the pictures can be shared freely.

Everything is drawn with tools in this repository and the standard library: no screen recorder,
video editor or encoder has to be installed. Only Chrome or Edge is needed.

## Make them again

1. **Start the lab** (it runs the whole agent on `127.0.0.1:18100`):

   ```powershell
   $env:EASM_LAB = '1'; $env:EASM_LAB_DIR = "$env:TEMP\easm-lab"
   go test -c -ldflags "-X easm-agent.version=1.9.18" -o lab.test.exe .
   .\lab.test.exe -test.run '^TestLab$' -test.timeout 180m
   ```

   Open http://127.0.0.1:18100, create the administrator with the setup code in
   `$env:EASM_LAB_DIR\lab.setup-code`, hide the welcome card, and add `acme-corp.test` (expected ASN
   `AS64500`, keyword `ACME`, with active scanning and port confirmation ticked). Wait until no scan is running.

2. **Capture** the screenshots, title cards and scrolling clips ([demo/script.txt](demo/script.txt)).
   The capture signs in with your browser session cookie, read from the environment so it is never on
   a command line:

   ```powershell
   $env:EASM_DEMO_COOKIE = 'easm_session=<the value from your browser>'
   go run ./tools/democap -script docs/demo/script.txt -out frames
   ```

3. **Assemble** the video and the README tour ([demo/storyboard.txt](demo/storyboard.txt)):

   ```powershell
   go run ./tools/demovideo -frames frames -avi easm-agent-demo.avi -gif docs/images/demo.gif -gif-width 800 -gif-fps 3
   ```

   Copy `frames/dashboard.png`, `findings.png`, `domain.png`, `evidence.png`, `assets.png`, `report.png`
   and `dashboard-dark.png` to `docs/images/`.

The AVI (Motion-JPEG, 1440×900, about 55 seconds) is for YouTube and other video sites, which accept
AVI uploads. It is about 110 MB, so it is not committed. The GIF (about 5 MB) is what the README shows.

## Title, description and tags for YouTube

**Title:** EASM Agent: free, open-source external attack surface monitoring (1-minute tour)

**Description:**

> EASM Agent finds what your organisation exposes on the internet (sub-domains, servers, open
> services, vulnerable software, take-over risks, weak email security, public storage and leaked keys)
> and tells you when it changes. It is one signed program for Windows, Linux, Docker and Kubernetes
> that runs on your own machine, with an encrypted database and nothing sent anywhere else.
>
> Every finding comes with its evidence, the risk and the fix. The tour uses a made-up company from
> the project's test lab.
>
> Download: https://github.com/cyberjangle101/cybersour-attack-surface-scanner

**Tags:** attack surface management, EASM, external attack surface, subdomain takeover, security
monitoring, open source security, shadow IT, vulnerability management, blue team
