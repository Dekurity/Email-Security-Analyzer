import re
import requests
import dns.resolver
import asyncio
import aiohttp
import whois
import argparse
import email
import os
import hashlib
import concurrent.futures
from email import policy
from email.parser import BytesParser
from fpdf import FPDF
from transformers import pipeline

# API Key for VirusTotal (replace with your own)
VIRUSTOTAL_API_KEY = "YOUR_API_KEY"

# List of scam keywords
SCAM_KEYWORDS = ["urgent", "reset password", "verify now", "click here", "immediate action required"]

# List of RBL servers
RBL_SERVERS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]

# Initialize NLP pipeline for scam keyword detection
nlp = pipeline("zero-shot-classification")

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if "v=spf1" in str(rdata):
                return "[✔] SPF found: " + str(rdata)
        return "[✘] SPF not found!"
    except Exception as e:
        return "[✘] Could not check SPF! Error: " + str(e)

def check_dkim(domain):
    try:
        selector = "default"  # Change as needed
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        return "[✔] DKIM found!"
    except Exception as e:
        return "[✘] DKIM not found! Error: " + str(e)

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        return "[✔] DMARC found!"
    except Exception as e:
        return "[✘] DMARC not found! Error: " + str(e)

def extract_links(email_text):
    urls = re.findall(r"https?://[^\s]+", email_text)
    return urls if urls else ["[✘] No links found!"]

def detect_scam_keywords(email_text):
    for keyword in SCAM_KEYWORDS:
        if keyword.lower() in email_text.lower():
            return f"[⚠] Scam keyword detected: {keyword}"
    return "[✔] No scam keywords detected"

def detect_scam_nlp(email_text):
    labels = ["phishing", "safe", "spam"]
    result = nlp(email_text, candidate_labels=labels)
    if result["labels"][0] == "phishing" and result["scores"][0] > 0.8:
        return "[⚠] Email terdeteksi sebagai phishing!"
    return "[✔] Email aman!"

def hash_url(url):
    url_id = hashlib.sha256(url.encode()).hexdigest()
    return url_id

async def check_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Step 1: Submit URL for scanning
    async with aiohttp.ClientSession() as session:
        async with session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}) as post_response:
            if post_response.status == 200:
                data = await post_response.json()
                url_id = data["data"]["id"]
            else:
                return "[⚠] VirusTotal submission failed!"

        # Step 2: Retrieve scan results
        await asyncio.sleep(10)  # Wait for the scan to be processed
        async with session.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=headers) as response:
            if response.status == 200:
                result = await response.json()
                detections = result["data"]["attributes"]["stats"]["malicious"]
                return f"[⚠] URL is suspicious! Detections: {detections}" if detections > 0 else "[✔] URL is safe!"
            return "[⚠] URL check failed!"

def resolve_rbl(ip, rbl):
    try:
        query = ".".join(reversed(ip.split("."))) + "." + rbl
        answers = dns.resolver.resolve(query, 'A')
        if answers:
            return f"[⚠] IP is blacklisted in {rbl}"
    except:
        return None

def check_rbl(domain):
    try:
        ip = dns.resolver.resolve(domain, 'A')[0].to_text()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(lambda rbl: resolve_rbl(ip, rbl), RBL_SERVERS))
        return next((r for r in results if r), "[✔] IP is not blacklisted")
    except Exception as e:
        return "[✘] Could not check RBL! Error: " + str(e)

def check_whois(domain):
    try:
        w = whois.whois(domain)
        if w.creation_date:
            return f"[✔] Domain creation date: {w.creation_date}"
        return "[✘] Could not retrieve WHOIS information!"
    except Exception as e:
        return "[✘] WHOIS lookup failed! Error: " + str(e)

async def check_attachment_virustotal(filename, payload):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    files = {"file": (filename, payload)}

    async with aiohttp.ClientSession() as session:
        async with session.post("https://www.virustotal.com/api/v3/files", headers=headers, data=files) as response:
            if response.status == 200:
                result = await response.json()
                file_id = result["data"]["id"]

        # Wait and retrieve scan results
        await asyncio.sleep(15)
        async with session.get(f"https://www.virustotal.com/api/v3/analyses/{file_id}", headers=headers) as scan_response:
            if scan_response.status == 200:
                scan_result = await scan_response.json()
                detections = scan_result["data"]["attributes"]["stats"]["malicious"]
                return f"[⚠] File {filename} terdeteksi berbahaya!" if detections > 0 else f"[✔] File {filename} aman!"
            return f"[⚠] Gagal mengecek file {filename}"

async def analyze_attachments(msg):
    results = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        if filename and payload:
            result = await check_attachment_virustotal(filename, payload)
            results.append(result)
    return results

def generate_report(domain, spf_result, dkim_result, dmarc_result, scam_result, scam_nlp_result, links, virustotal_results, rbl_result, whois_result, attachment_results, verbose):
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", size = 12)
    pdf.cell(200, 10, txt = "Email Security Analyzer Report", ln = True, align = 'C')
    
    pdf.cell(200, 10, txt = f"Domain: {domain}", ln = True)
    pdf.cell(200, 10, txt = f"SPF: {spf_result}", ln = True)
    pdf.cell(200, 10, txt = f"DKIM: {dkim_result}", ln = True)
    pdf.cell(200, 10, txt = f"DMARC: {dmarc_result}", ln = True)
    pdf.cell(200, 10, txt = f"Scam Keywords: {scam_result}", ln = True)
    pdf.cell(200, 10, txt = f"Scam Keywords NLP: {scam_nlp_result}", ln = True)
    pdf.cell(200, 10, txt = f"RBL Check: {rbl_result}", ln = True)
    pdf.cell(200, 10, txt = f"WHOIS Check: {whois_result}", ln = True)
    
    pdf.cell(200, 10, txt = "Links found:", ln = True)
    for link in links:
        pdf.cell(200, 10, txt = link, ln = True)
    
    pdf.cell(200, 10, txt = "VirusTotal Results:", ln = True)
    for result in virustotal_results:
        pdf.cell(200, 10, txt = result, ln = True)
    
    pdf.cell(200, 10, txt = "Attachment Analysis:", ln = True)
    for result in attachment_results:
        pdf.cell(200, 10, txt = result, ln = True)
    
    pdf.output("email_security_report.pdf")

    if verbose:
        print("\n[🔍] Detailed Analysis Report")
        print(f"Domain: {domain}")
        print(f"SPF: {spf_result}")
        print(f"DKIM: {dkim_result}")
        print(f"DMARC: {dmarc_result}")
        print(f"Scam Keywords: {scam_result}")
        print(f"Scam Keywords NLP: {scam_nlp_result}")
        print(f"RBL Check: {rbl_result}")
        print(f"WHOIS Check: {whois_result}")
        print("Links found:")
        for link in links:
            print(link)
        print("VirusTotal Results:")
        for result in virustotal_results:
            print(result)
        print("Attachment Analysis:")
        for result in attachment_results:
            print(result)

def parse_eml(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return msg
    except Exception as e:
        print(f"[✘] Gagal membaca file EML! Error: {str(e)}")
        return None

async def main(email_header, verbose):
    domain_match = re.search(r'@([\w.-]+)', email_header)
    if domain_match:
        domain = domain_match.group(1)
        if verbose:
            print("\n[🔍] Analyzing Domain:", domain)
        spf_result = check_spf(domain)
        dkim_result = check_dkim(domain)
        dmarc_result = check_dmarc(domain)
        scam_result = detect_scam_keywords(email_header)
        scam_nlp_result = detect_scam_nlp(email_header)
        rbl_result = check_rbl(domain)
        whois_result = check_whois(domain)
        if verbose:
            print(spf_result)
            print(dkim_result)
            print(dmarc_result)
            print(scam_result)
            print(scam_nlp_result)
            print(rbl_result)
            print(whois_result)

        links = extract_links(email_header)
        if verbose:
            print("\n[🔗] Links found:", links)
        
        virustotal_results = await asyncio.gather(*[check_virustotal(link) for link in links if "http" in link])
        
        if verbose:
            for result in virustotal_results:
                print(result)
        
        attachment_results = await analyze_attachments(parse_eml(email_header))
        generate_report(domain, spf_result, dkim_result, dmarc_result, scam_result, scam_nlp_result, links, virustotal_results, rbl_result, whois_result, attachment_results, verbose)
        if verbose:
            print("[✔] Report generated: email_security_report.pdf")
    else:
        print("[✘] Domain not found in header!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Email Security Analyzer")
    parser.add_argument("--email", type=str, help="Email header or path to .eml file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode")
    args = parser.parse_args()

    if args.email:
        if os.path.isfile(args.email) and args.email.endswith(".eml"):
            email_message = parse_eml(args.email)
            if email_message:
                email_header = email_message.as_string()
                asyncio.run(main(email_header, args.verbose))
            else:
                print("[✘] Failed to parse the provided .eml file.")
        else:
            email_header = args.email
            asyncio.run(main(email_header, args.verbose))
    else:
        print("Please provide an email header or .eml file path with --email argument.")