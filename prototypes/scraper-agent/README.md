# Federal-Register → Summary Provenance Demo

Prototype to show how **EQTY** captures raw data, AI output, and full lineage in tamper-evident CIDs using Federal Registry Data.
This script demonstrates a very simple agentic AI provenance pipeline: it scrapes data from the federal registry site (URL hardcoded), applies an AI model to generate a summary, and records the full lineage of that process using EQTY. Each step produces cryptographically signed artefacts that can be independently verified and traced through the outputes manifest.json file containing verificable credentials and visualized in EQTY's lineage explorer.

---

## Run It Locally 

```bash
# Clone Repo
git clone <repo-url> && cd scraper-agent

# Activate Python 3.10+ venv
python -m venv .venv
source .venv/bin/activate       

# Install EQTY SDK (private) and dependencies
export USER='<pypi-user>'           # obtain from EQTY team
export PASSWORD='<pypi-pass>'
export REPO=http://$USER:$PASSWORD@eqty-pypi.westus2.cloudapp.azure.com/simple

pip install --upgrade pip
pip install --extra-index-url "$REPO" \
            --trusted-host eqty-pypi.westus2.cloudapp.azure.com \
            eqty_sdk
pip install requests beautifulsoup4 lxml transformers torch

```

## What's Happening

### 1. Data ingestion  
Fetches the July 28, 2025 issue of the Federal Register in XML format from [govinfo.gov](https://www.govinfo.gov/), then strips tags to produce a plain-text version.

### 2. AI agent execution  
The plain text is fed into a pre-trained summarisation model (`sshleifer/distilbart-cnn-12-6` from Hugging Face), which returns a ~200-token summary.

### 3. Agent metadata capture  
A metadata block is constructed that includes:
- The model name and versions (transformers, torch, Python)
- Agent run ID and timestamp
- Summary parameters (`max_length`, `min_length`)
This metadata is bundled into another variable called output that contains pointers (in the form of CIDs) to the larger metadata objects.

###  4. EQTY signing and registration  
- A new ED25519 keypair is created via `Signer.new()` and made active.
- Two separate EQTY datasets are registered:
  - Plain text (as a standalone input)
  - Summary (as the AI output)
- A `Computation` record links the plain text to the summary and embeds tool metadata (model, run ID). This shows *how* the output was derived from the input.

### 5. Manifest export  
All integrity statements (datasets, computation, signer identity) are exported to a single `manifest.json`, which can be:
- Verified offline
- Uploaded to EQTY's Lineage Explorer
- Shared as a portable provenance bundle

### 6. Optional cleanup  
The local integrity store is wiped after the manifest is created. Comment out if needed.

---
## Lineage Explorer Visualization

<img width="1685" height="970" alt="Screenshot 2025-08-02 at 8 55 46 PM" src="https://github.com/user-attachments/assets/303413e4-afec-4c4c-af57-445868a3832f" />
<img width="1686" height="963" alt="Screenshot 2025-08-02 at 8 55 54 PM" src="https://github.com/user-attachments/assets/b502fdfd-fdcf-4828-9764-e17f5ee0fffb" />


