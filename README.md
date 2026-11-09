# ScopeWeave

A browser-based VAPT assessment assistant prototype for the DataOps Innovation Hackathon problem. The app runs locally, with an optional local Ollama planner or an explicitly selected Groq cloud evidence-review provider. This folder is a clean implementation and does not import code from the earlier desktop app.

## Run it

1. Install Python 3 if it is not already installed.
2. From PowerShell, open this folder and run:

   ```powershell
   python server.py
   ```

3. Open `http://127.0.0.1:8765` in a browser and choose **Enter workspace**. Press `Ctrl+C` in PowerShell to stop the local server. A mentor can run the same launcher on their computer and enter the workspace without an account.

There are no Python package dependencies or external fonts. The browser app and server bind to localhost. Optional scanner integration calls the local ZAP API; ZAP itself sends requests to the approved lab. The analyst can select either local Ollama or Groq cloud in the planner. Groq requests require a server-side key and an explicit cloud-sharing confirmation for that request. If the selected provider is unavailable or its response fails validation, the app labels and uses the deterministic rule fallback. Scope, findings, import history, analyst context, and the audit log are saved in this browser's local storage; selected summaries are also sent to Groq when cloud review is confirmed.

## Current workflow

1. Register the exact lab origin, authorization reference, exclusions, and allowed actions. Choose **My own local practice lab** for a lab you run on this computer, or **Organizer-approved lab** for an organizer-provided target. For your running personal Juice Shop instance on port 3000, **Fill local Juice Shop details** fills the form. Confirm ownership and save. The app keeps each origin separate and checks its saved permissions before scans, imports, or reviews.
2. Optionally start a scoped OWASP ZAP Spider crawl with passive checks, after the app asks for confirmation.
3. Import genuine scanner exports from the approved lab.
4. On **Assessment**, check **Live next step**. It updates locally when you import a scanner report or change a finding’s review status. Open **Why use or skip a tool?** to see which evidence the app can reuse, which approved export could fill a gap, and why other tools are on hold. Use **Open recommended finding** when the next step names a finding.
5. Review normalized and correlated findings with per-source evidence, import outcomes, and transparent analyst context for prioritization.
   - Choose **Review finding** to inspect the imported evidence and save **Needs review**, **Confirmed issue**, or **False positive** with a reason. A confirmed issue or false positive needs supporting evidence or a reference. The report shows the analyst review separately from the scanner’s evidence, severity, and validation status.
   - Choose **Draft bug report** on an individual finding. Review its source evidence, enter the verified reproduction steps and results, and select your assessed severity. Copy the draft or download it as a text file. The export includes the finding reference and any evidence excerpt you choose to include.
   - Choose **Remediation**, select bugs from the active lab, and choose **Track selected bugs**. Save fix notes and status for each tracked bug. After saving **Fix reported**, use **Record retest** to log your result and evidence from the approved scope. The report preview and PDF show these details for the included findings.
   - Optionally select Groq in the planner, review the cloud-sharing notice, and ask a question about the available evidence. The model returns a summary and source-linked observations plus a permission-checked next step. It cannot start scans.
6. If the scope permits Layer review, record an approval or rejection decision for demonstration. An approval is recorded as not executed.
7. Choose **Report options**, select a mode, and open **Preview report**. Choose **Save PDF** to save directly to **Downloads → ScopeWeave Reports**. This uses Chrome or Microsoft Edge in the background. **Print** opens the regular browser print dialog.
8. Choose **Saved PDFs** to reopen reports from **ScopeWeave Reports** and earlier ScopeWeave PDFs in Downloads. The newest reports appear first.

## Assessment features

1. The findings page shows the risk formula and each input. The total appears only when source CVSS and all three analyst-entered 0–10 values are present.
2. The planner can use local Ollama for a JSON next-step suggestion or Groq cloud for a summary, source-linked observations, limitations, and a suggested next step. An explicit request supplies scanner coverage and the selected findings’ review statuses along with the existing evidence summaries. Analyst review notes stay local. The server checks the suggestion against saved scope permissions and labels the rule-based result as **Fallback mode** if the provider fails. When imports or review statuses change, the app labels the older response and uses the current local recommendation in the report.
3. The activity page shows a local audit table with actor, action, time, and result.
4. Failed imports and ZAP errors are recorded with a short recovery hint.
5. The print report has six sections covering the summary, permission, methodology and integration matrix, evidence, findings and risk review, and approvals and limitations.
6. Each finding can expand an evidence trace with the source tool, filename, timestamp, parser reference, parsed evidence text, and an **Observed in imported report** label. The current parsers do not preserve the original file text or exact source line numbers.
7. A rule-based agreement badge counts distinct tools for an exact normalized title-and-asset match: one tool is **Low agreement**; two or more are **Medium agreement**. This is source corroboration, not confirmation.
8. **Include all** shows every saved finding and source record. **Remove the duplicates** combines matching findings and repeated evidence. **Only duplicates** shows groups with duplicate findings, corroboration from multiple tools, or repeated evidence. The report matches recognized names for a missing CSP, HSTS, or X-Content-Type-Options header when the recorded URLs match exactly. **Duplicate summary** shows the counts, and the report keeps source references for merged findings and repeated evidence.

Findings flag parsed scanner text that matches common instructions aimed at AI. Open **Evidence** to see the matching snippet and its report source. In Groq mode, the sharing notice lists flagged fields from the selected summaries and excerpts. **Exclude flagged fields from this Groq request** is checked by default for each review. The original evidence remains available in Findings. The warning checks for common phrases and model markers, so analysts still need to review the selected evidence before sharing it.

Exact source-line jump links and Metasploit integration remain planned.

## Optional Groq cloud setup

Create your own key at [Groq API Keys](https://console.groq.com/keys). A Groq key authenticates with Groq's service; it is not an OpenAI Platform API key. The default cloud model is `openai/gpt-oss-120b`, an OpenAI open-weight model hosted by Groq. Model access and free-plan allowances depend on your account; see the [Groq quickstart](https://console.groq.com/docs/quickstart) and [current rate limits](https://console.groq.com/docs/rate-limits).

On Windows, double-click **Start ScopeWeave.cmd**. The launcher opens the workspace in your browser while ZAP starts in the background. It loads a saved Groq key when available. For first-time Groq setup, stop the launcher and open **Update Groq Key.cmd**. Paste your key into the hidden prompt and enter **y** to remember it for this Windows account. You can minimize the launcher window and press **Ctrl+C** there when you are done.

Alternatively, from PowerShell in this folder, run:

```powershell
.\start-groq.ps1
```

The launcher reopens an existing ScopeWeave session if it is already running. If the browser does not open automatically, wait for the server's ready message and open `http://127.0.0.1:8765`. If the port is busy, check the launcher message before retrying.

A current-user Windows startup task can run `start-groq.ps1 -Background` to serve the app after sign-in. This mode uses a saved Groq key when available and keeps the browser startup separate. If you use a task created for this launcher, manage it in Windows Task Scheduler. End the task before running **Update Groq Key.cmd**, then start the task again after the key update session ends.

If you opt in to remembering the key, Windows encrypts it for your account in `%LOCALAPPDATA%\SentinelDesk\groq-key.dpapi`. To replace it, stop ScopeWeave and double-click **Update Groq Key.cmd**. An explicit `GROQ_API_KEY` in the launcher's environment takes precedence on a regular start. Keep the key out of browser inputs, chat, screenshots, and the repository. If local script execution is blocked, the following invocation permits this script for that PowerShell process only:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\start-groq.ps1
```

In **Make a review plan**, select **Groq**, read the cloud notice, and confirm sharing before submitting each request. The request sends the registered target origin, prompt, excluded paths, allowed actions, and at most 10 finding summaries. The summary text for each finding is capped at 240 characters and can include up to three source-report excerpts of 180 characters each. Raw report files, the API key, and the organizer approval reference are not sent to the model. Use only evidence that may be shared with the chosen cloud service.

The response cites supplied finding IDs. The app checks those references before showing source links, but a valid reference does not prove that an AI interpretation is correct. Review the linked scanner evidence. Each cloud request is attempted once with a 2,200 completion-token cap. An incomplete, unavailable, rejected, or rate-limited response uses the clearly labelled local rule fallback; it is not presented as a successful AI review. Groq cannot browse or scan the selected target through this integration.

Live Groq verification requires the key to be configured on the machine running the app. A working implementation or a mocked test alone is not proof of a successful live model request.

## Running on a mentor's computer

Copy this folder and the authorized scanner report files. The mentor needs Python 3, a browser, internet access for Groq, and their own valid Groq key. On Windows, double-click **Start ScopeWeave.cmd** and follow the same provider/consent flow. The PowerShell script is also available directly. No local AI model or GPU is required for Groq inference. ZAP is needed separately only to demonstrate the live crawl; importing existing reports does not require it.

Saved scopes and findings belong to the original browser's local storage and do not travel with the project folder. Register the approved lab and import its report files on the mentor's computer. Do not bundle a personal API key with the project. A limit error or an expired/revoked key requires the account/key to be checked; the fallback remains available.

## Optional local Ollama planner

Install and start Ollama separately, and make sure the model is already available locally. ScopeWeave defaults to the model name `qwen2.5:3b`; set `OLLAMA_MODEL` to another installed model if needed, then start the app:

```powershell
$env:OLLAMA_MODEL = "qwen2.5:3b"
python server.py
```

The app calls Ollama's local `/api/chat` endpoint with a JSON schema. The model may choose only from review steps allowed by the registered lab permissions. It cannot start scans. Invalid or unavailable model responses fall back to local rules and appear as **Fallback mode**. See the [Ollama chat API](https://docs.ollama.com/api/chat).

## Optional OWASP ZAP setup

With ZAP and Java installed, **Start ScopeWeave.cmd** starts ZAP in the background or connects to a running local ZAP it recognizes. It configures the API key automatically. The launcher-managed ZAP profile lives in `%LOCALAPPDATA%\SentinelDesk\zap` and listens at `127.0.0.1:8080`. Its generated API key is stored in `zap-api.properties` in the ScopeWeave data directory. Press **Ctrl+C** in the launcher to stop ScopeWeave and the background ZAP it started. The first background launch can take up to a minute.

For a custom ZAP install directory, set `ZAP_INSTALL_DIR` before launching. When starting `server.py` directly with an independently managed ZAP instance, provide its key in `ZAP_API_KEY`:

```powershell
$env:ZAP_API_KEY = "your-zap-api-key"
python server.py
```

The app creates a temporary ZAP context for the registered origin and excluded paths. It starts only the traditional Spider crawl, waits for passive checks to finish, and imports the results. The adapter does not invoke ZAP's active scanner.

The crawl sends normal HTTP requests to the registered lab. It is capped by a three-minute crawl timeout and a 150-alert import limit. Review organizer rules before starting it. ZAP must remain on its default loopback API address; the adapter does not accept a user-supplied API address.

## Integration truth

| Tool | Status | File accepted |
|---|---|---|
| Nmap | Import-only | XML (`-oX`) |
| Nessus | Import-only | `.nessus` XML |
| OpenVAS / Greenbone | Import-only | Report XML |
| Nikto | Import-only | XML |
| OWASP ZAP | Local scoped Spider + passive checks; JSON import | JSON report |
| Burp Suite | Import-only | XML issue export |
| Metasploit | Planned | No adapter or execution path |

The application sends target traffic only when the analyst explicitly starts a ZAP crawl for the registered local or organizer-approved lab. Other scanners remain import-only. Files and live ZAP alerts are filtered to the registered origin and excluded paths; host aliases are not inferred. Review exclusions and allowed ports against the organizer's rules before scanning or importing network results.

## Important limitations

- Ollama uses a separately installed local model. Groq requires internet access, a valid server-side key, available allowance, and explicit per-request cloud sharing. The default planner selection remains local Ollama; cloud review is optional. Provider failures use local rules and show **Fallback mode**.
- Groq review covers only the bounded evidence included in that request. A source-linked AI observation is an interpretation, not a verified vulnerability or proof of remediation.
- The coverage map reports files recorded in this browser and recommends a next review from those records. A missing report means no file was imported here; it does not mean the lab was tested or found safe.
- The ZAP adapter performs a bounded Spider crawl with passive checks only. It has no active scan or active validation executor.
- The browser decision log is local convenience state, not tamper-proof audit storage.
- Local approval/rejection decisions are gated by the saved Layer review permission and never execute validation.
- Remediation and retest details are analyst-entered and saved in this browser. The tracker keeps the latest retest for each finding and marks it as previous evidence if the fix notes or status change. The app records this workflow without applying fixes or running retests.
- Findings are scanner-reported and unvalidated unless their source says otherwise.
- Finding reviews are analyst-entered and saved for the active lab in this browser. A false-positive decision stays visible with the original scanner evidence for traceability. Recording a finding review does not execute a test.
- Review priority starts from source-reported severity. A separate project score uses the stated weighted formula only when source CVSS and all three analyst-entered 0–10 components are present. Missing values do not receive invented defaults. The score does not confirm a vulnerability.
- Direct PDF saving uses a local Chrome or Edge installation. Browser printing is available separately.
- **Delete scope** moves a scope and its assessment records out of the active workspace. Use **Scope Trash → Restore** to bring them back in the same browser.
- **Delete** in **Saved PDFs** moves a matching ScopeWeave report to Trash. Use **PDF Trash → Restore** to put it back in its original report folder.
- The organizer authorization reference is a local analyst attestation; the app cannot independently confirm the organizer's permission.

See [ARCHITECTURE.md](ARCHITECTURE.md) for data flow, trust boundaries, and implemented capability status.

## Run the tests

```powershell
python -B -m unittest discover -s tests
```
