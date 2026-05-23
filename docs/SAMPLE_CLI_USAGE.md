# Sample CLI Command Examples

Here are the most common commands used to run the pipeline via the `threatcli` tool.

### 1. Collect Data from all sources
Fetches data from NVD, OTX, and RSS feeds for the last 7 days.
```bash
python -m cli.main collect --source all --days 7
```

### 2. Search for a specific keyword
Fetches only items related to "Confluence" across all sources.
```bash
python -m cli.main collect --source all --query "Confluence"
```

### 3. Run Preprocessing
Strips HTML, deduplicates, and encapsulates newly collected raw items.
```bash
python -m cli.main preprocess
```

### 4. Enrich Data
Runs the extraction pipeline (Regex + NER + LLM TTP mapping) on preprocessed items.
```bash
python -m cli.main enrich
```

### 5. Generate Analyst Reports
Runs the LLM report generator for all items that have been enriched but don't have a report yet.
```bash
python -m cli.main report
```

### 6. Review Reports (Human-in-the-Loop)
Starts the interactive CLI session to approve, reject, or escalate pending reports.
```bash
python -m cli.main review
```

### 7. Run Full Pipeline End-to-End
Runs all the above stages in sequence for a specific target.
```bash
python -m cli.main run-all --source otx --days 1
```
