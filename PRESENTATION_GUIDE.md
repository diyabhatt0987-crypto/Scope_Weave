# ScopeWeave: Simple Demo Guide

You do not need to explain HTML or CSS in the demo. Explain what the app helps an analyst do, what evidence it uses, and what safety limits it has.

## Short opening (about 30 seconds)

> “ScopeWeave is a VAPT assessment assistant prototype that runs locally. It records an authorized lab scope, imports genuine scanner results, groups related findings with their evidence, and prepares a report. The analyst can choose local Ollama planning or explicitly send a bounded evidence summary to Groq for a source-linked AI review. A separately confirmed ZAP crawl uses passive checks; AI does not execute scans or exploits.”

## Five parts for the project presentation

1. **Lab and permission:** Record which lab is approved and what actions are allowed.
2. **Plan and report status:** Show what evidence is already present and what the app suggests reviewing next.
3. **Scanner results:** Run the limited ZAP check after confirmation, or import a genuine report file from the approved lab. The app checks results against the saved lab rules and keeps each source with its evidence.
4. **Findings and review:** Show grouped findings, original scanner evidence, and analyst review context.
5. **Decision and report:** Record the analyst’s decision and prepare a print-ready report. Recording a decision does not run a test or exploit.

## Seven features judges can check

1. **Risk score:** “CVSS is taken from the scanner report. I enter exposure, exploitability, and asset impact from 0 to 10 and add a note. The app shows each weighted part and the total only when all four values are present.”
2. **Planner:** “I can choose local Ollama for a next-step suggestion, or Groq cloud for a summary, source-linked observations, evidence gaps, and a suggested review step. Before each Groq request I confirm which selected target and evidence summaries leave this computer. The app checks the returned action and finding references. If the provider fails or returns invalid output, local rules take over and the screen says Fallback mode.”
3. **Audit log:** “The table records who did what, when, and the result, so the demo actions can be reviewed later.”
4. **Failure recovery:** “If a report file cannot be read or ZAP stops, the app records the error and tells the analyst how to recover.”
5. **Report:** “The PDF has six sections: summary, scope and permission, method and tool status, imported evidence, findings and risk review, and approvals with limitations.”
6. **Evidence trace:** “Open a finding to see which tool and file it came from, its time, report reference, parsed evidence text, and the label Observed. This parser does not keep the original file lines, so it does not claim an exact line number.”
7. **Cross-tool agreement:** “One matching tool is Low agreement; two or more distinct tools are Medium agreement. This shows corroboration only. It does not confirm a vulnerability.”

The audit log is saved in this browser and is not tamper-proof. The report and score help a human review the evidence; they do not confirm vulnerabilities.

Part 3 has two clearly separate paths in **Scanner results**: ZAP can run locally with permission and confirmation; Nmap, Nessus, Greenbone, Nikto, and Burp provide files to import. Metasploit is listed as planned and is not connected. A missing report is shown as missing evidence, not proof that the lab is safe.

## Show the app in this order

1. **Scope:** “First, the analyst records the exact approved origin, the approval reference, excluded paths, and permitted actions. A different port or subdomain needs its own approval. The app keeps lab records separate, lets the analyst select the active lab, and checks actions and evidence against its saved rules. Scanner imports require an approved source area; local review decisions also require Layer review permission. The approval reference is an analyst attestation; the app cannot verify it with the organizer.”
2. **Coverage:** “This map shows the latest report status for each supported import tool and how many finding groups link to it. If a report is missing, the app says it has no file in this workspace; it does not call the lab safe.”
3. **Plan:** “The provider selector starts with local Ollama. To show Groq, I select its cloud option, read the sharing notice, and confirm this request. Groq receives the selected target, my prompt, scope rules, and up to 10 finding summaries with bounded source excerpts. Its response links back to supplied finding IDs so I can review the original scanner evidence. Local Ollama remains available for a next-step suggestion. A failed provider request is labelled Fallback mode. Neither provider starts a scan from the prompt.”
4. **Evidence / Part 3:** “On Scanner results, the analyst can run the scoped ZAP crawl after confirmation or import genuine scanner export files from the approved lab. The app checks each result against the saved lab rules and keeps its source and supporting evidence. The import history shows which files were accepted, excluded, had no observations, or could not be read.”
5. **Review:** “Related records can be grouped, but the source evidence is retained. The score is CVSS times 0.4, plus exposure, exploitability, and asset impact times 0.2 each. The screen shows every part. CVSS comes from the report; I enter the other three scores with a note. If a value is missing, the app does not show a total. This score helps order review; it does not prove a vulnerability.”
   - To show this, open **Analyst context & priority**, choose values supported by the approved lab/source, add a short note, and save.
6. **Approval and report:** “The prototype records a human decision for validation, but does not execute validation. The print-ready report includes findings, evidence sources, human decisions, file import outcomes, and the coverage map with its next-review reason.”

## Likely judge questions

**Does it run live scans?**  
“It can run a bounded OWASP ZAP Spider crawl with passive checks for the exact registered lab after confirmation. It sends normal web requests. Active scan rules and exploit validation are not enabled.”

**Which tools are connected?**  
“OWASP ZAP can run through its local API for a scoped crawl and passive checks. Nmap, Nessus, Greenbone, Nikto, and Burp are supported for importing result files. Metasploit is planned and is not connected.”

**Where is the AI model?**  
“The selected mode tells us. Ollama runs a separately installed model on this computer. Groq hosts the default GPT-OSS model in its cloud and needs internet plus a server-side Groq key. Selecting Groq also requires explicit sharing confirmation before evidence is sent. A displayed Fallback mode means local rules were used rather than a successful AI answer. I only claim live AI operation after an actual successful request.”

**Is that an OpenAI API key?**  
“No. Groq hosts OpenAI's open-weight GPT-OSS model, but the key and inference service belong to Groq. This is different from OpenAI Platform API access.”

**Can the mentor run it on another computer?**  
“Yes. Copy the project folder and authorized scanner reports, install Python 3, and double-click Start ScopeWeave.cmd on Windows. The mentor enters their own Groq key in the hidden prompt and can choose to save it with Windows encryption for their account. A browser and internet connection are needed for Groq. Saved assessment data stays in the original browser, so the approved lab and reports need to be registered and imported again. With ZAP and Java installed, the launcher can start live ZAP in the background.”

**How does it stop out-of-scope work?**  
“A scope must be registered with an organizer approval reference and allowed actions. The ZAP crawl uses the exact registered origin and excluded paths. Imported records outside that scope are rejected. No active scan or exploitation runs.”

**How does it choose the next review step?**  
“The selected model recommends an action using only the supplied scope and evidence. The app checks that action against the saved permissions. Groq also returns observations linked to known finding IDs. If the provider is unavailable or output fails validation, local evidence rules make the suggestion instead. Starting ZAP still needs a separate confirmation. A missing report does not mean the lab is safe.”

**Does the approval button launch Metasploit or another tool?**  
“No. It records the analyst’s decision for the demonstration. No active validation is executed.”

**How do you avoid made-up findings?**  
“Findings come from scanner records, including results from a separately started ZAP crawl. AI text is shown as an interpretation of the supplied findings, not added as a scanner result. Source links must reference finding IDs included in the request, and I inspect the underlying evidence because a valid link alone does not prove the model is correct.”

**Does agreement from two tools confirm a vulnerability?**  
“No. The badge counts distinct tools reporting the same normalized title and asset. It shows Low or Medium agreement only; technical validation remains separate.”

**Can the app jump to the exact source file line?**  
“It shows the source file, parser reference, timestamp, and parsed evidence text. This build does not retain original file lines, so direct line jump links remain planned.”

**How is a finding prioritized?**  
“The separate score is CVSS×0.4 + exposure×0.2 + exploitability×0.2 + asset impact×0.2. The app shows each component. CVSS comes from the source file; I enter and explain the other three. It stays blank if any input is missing, and it does not replace source severity.”

**What happens when an import or ZAP request fails?**  
“The import history or ZAP status shows the error and a next step, such as re-exporting valid XML, checking the local ZAP API key, or retrying after a timeout when the lab rules allow it.”

**What is the main limitation?**  
“Only ZAP has a limited live workflow, and it only crawls and checks responses passively. Groq needs cloud access and a valid account allowance, reviews at most 10 selected finding summaries, and can misinterpret evidence. Ollama needs a separately installed local model. Provider failures are labelled as rule fallback. The score depends partly on analyst-entered values. The audit log is local browser data, not tamper-proof.”

## If they ask about the code

> “HTML lays out the screen, CSS controls its appearance, and JavaScript handles the buttons and assessment workflow. My demo focuses on how the assessment is kept in scope and how imported evidence becomes a traceable report.”

## Before presenting

- Use an organizer-authorized lab target and genuine exports only, if those are provided.
- If no authorized lab data is available, show the workflow and clearly say that findings are not populated. Do not present invented scanner output as real.
- Be clear that this is a local prototype, ZAP performs only a scoped crawl with passive checks, and active validation is not executed.
- Double-click **Start ScopeWeave.cmd** on Windows, enter the Groq key if prompted, and make one genuine evidence-review request before claiming a live AI demo. Keep keys private in screenshots, chat, slides, and shared project files.
- Keep an authorized report file available for re-import on a different machine. Browser-local saved findings do not transfer with the folder.
- If the network, account limit, or key is unavailable during the demo, show the labelled fallback honestly and explain the recovery step.
