import requests
import uuid, platform, datetime
from bs4 import BeautifulSoup
from transformers import pipeline
import torch
# from eqty_sdk import init, DID, Dataset




FEDERAL_REGISTER_URL = (
        "https://www.govinfo.gov/content/pkg/FR-2025-07-28/xml/FR-2025-07-28.xml"
)

FULL_FR_TEXT = "fr_2025_07_28_full.txt"
RUN_ID = uuid.uuid4().hex
MAX_CHARS = 5000


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


    model_input = full_text[:MAX_CHARS]

    summarizer = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6")
    summary = summarizer(
        model_input, max_length=200, min_length=30, do_sample=False) [0] ["summary_text"]
    
    print(
        "created federal registry summary\n"
        "--- SUMMARY ---\n"
        f"{summary}\n"
        "----------------"
    )



    














