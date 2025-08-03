import requests
import uuid, platform
from datetime import datetime, timezone
from bs4 import BeautifulSoup
import transformers
from transformers import pipeline
import torch
from eqty_sdk import init, Did, Dataset, Signer, SIGNER_ALGORITHMS, set_active_signer, Computation, generate_manifest,  purge_integrity_store




FEDERAL_REGISTER_URL = (
        "https://www.govinfo.gov/content/pkg/FR-2025-07-28/xml/FR-2025-07-28.xml"
)

FULL_FR_TEXT = "fr_2025_07_28_full.txt"
RUN_ID = uuid.uuid4().hex
MAX_MODEL_CHARS = 5000


# helpers

# Get XML from the Federal Register site and return it as plain text
def fetch_xml(url: str) -> str:
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.text

# convert XML into text paragraphs
def xml_to_text(xml_text: str) -> str:
    soup = BeautifulSoup(xml_text, "xml") # use xml parser
    if soup.TOC:
        soup.TOC.decompose()
    paragraphs = [
        p.get_text(" ", strip=True) # join text with spaces
        for p in soup.find_all("P") # separating paragraphs
    ]
    return "\n\n".join(paragraphs)


# download xml and parse
if __name__ == "__main__":
    xml_text = fetch_xml(FEDERAL_REGISTER_URL)
    full_text = xml_to_text(xml_text)

    
    # save as plain text for any future manual checks/reviews
    with open(FULL_FR_TEXT, "w", encoding="utf-8") as f:
        f.write(full_text)
    
    print("saved federal register contents")


    model_input = full_text[:MAX_MODEL_CHARS]

    summarizer = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6")
    summary = summarizer(
        model_input, max_length=400, min_length=30, do_sample=False) [0] ["summary_text"]
    
    print(
        "created federal registry summary\n"
        "--- SUMMARY ---\n"
        f"{summary}\n"
        "----------------"
    )

    agent_info = {
        "agent_name":        "fr-summariser",
        "agent_version":     "v0.1",
        "model":             "sshleifer/distilbart-cnn-12-6",
        "transformers_ver":  transformers.__version__,
        "torch_ver":         torch.__version__,
        "python_ver":        platform.python_version(),
        "run_id":            RUN_ID,
        "run_timestamp":     datetime.now(timezone.utc).isoformat(),
        "summary_params":    {"max_length": 200, "min_length": 30},
        "src_url":           FEDERAL_REGISTER_URL,
    }

    output = {
        "full_text":   full_text,
        "model_input": model_input,
        "summary":     summary,
        "metadata":    agent_info,
        "xml":         xml_text,       # raw source 
    }


    init()

    signer = Signer.new(SIGNER_ALGORITHMS.ED25519)
    set_active_signer(signer)

    did = Did.from_signer(
        signer, 
        name="fr-provenance-key", 
        description="Signing key for Federal Register dataset integrity statements."
    )

    ds = Dataset.from_object(
        output,
        name="FR 2025-07-28",
        description="Federal Register issue and web scraper agent provenance",
    )

    # Add computation provanence for summary generation

    fulltext_ds = Dataset.from_object(
        full_text,
        name="FR 2025-07-28 full extraction of text",
        descriptions=" Extracted Federal Register from XML pulled on 2025-08-02"
    )

    summary_ds = Dataset.from_object(
        summary,
        name="FR 2025-07-28 summary",
        description="summary of FR",
        model="sshleifer/distilbart-cnn-12-6",
        run_id=RUN_ID
    )

    comp = (
        Computation
        .new(name="fr-summariser v0.1 run",
            description="XML ➜ plain text ➜ BART summary on 2025-08-02",
            model="sshleifer/distilbart-cnn-12-6",
            run_id=RUN_ID,
            fr_outputs=ds.cid
        )
        .add_input_cid(fulltext_ds.cid)   # input A, extracted text from xml
        .add_output_cid(summary_ds.cid)   # output B, summary generated
    )
                 
    comp.finalize() # finalize returns none. builder pattern to assemble/puttign it all together, simply makign a json claim

    
computation_details = comp.__getstate__()
print(computation_details)

generate_manifest("./manifest.json")
purge_integrity_store()


















