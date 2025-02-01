import email
import csv
import Levenshtein
from fuzzywuzzy import process
import json
import dns.resolver
from email import policy
from email.parser import BytesParser

def sender_checker(email_eml):
    # The main dictionary where we store all analysis results
    analysis_results = dict()

    # Helper function to check if the sender's domain is trusted
    def is_trusted(sender_domain):
        with open("trusted_domains.txt", "w", encoding="utf-8") as output:
            with open("majestic_million.csv", "r", encoding="utf-8") as file:
                reader = csv.reader(file)
                next(reader)  # Skip header
                for row in reader:
                    domain = row[2].strip()  # Column 2 contains the domain name
                    output.write(domain + "\n")

        print("✅ Trusted domains saved to trusted_domains.txt")
        
        with open("trusted_domains.txt", "r", encoding="utf-8") as file:
            if any(sender_domain == line.strip() for line in file):
                return True
            else:
                return False

    # Open the .eml file
    with open(email_eml, "r", encoding="utf-8") as f:
        msg = email.message_from_file(f)

    # Extract sender's email
    from_email = msg["From"]
    print("Sender Email:", from_email)

    # Extract domain
    if "<" in from_email and ">" in from_email:  # If format is "Name <email@domain.com>"
        from_email = from_email.split("<")[1].split(">")[0]

    sender_domain = from_email.split("@")[-1]
    print("Sender Domain:", sender_domain)

    analysis_results["sender_analysis"] = dict()
    is_Trusted = is_trusted(sender_domain)
    analysis_results["sender_analysis"]["legitimate_website"] = is_Trusted

    # Display Name Matching Check
    def is_display_name_legit(display_name, email_address):
        if "@" in email_address:
            email_domain = email_address.split("@")[-1]
        else:
            return False

        if email_domain.lower() in display_name.lower():
            return True
        else:
            return False

    def is_display():
        with open(email_eml, "r", encoding="utf-8") as f:
            msg = email.message_from_file(f)

        from_field = msg["From"]
        print("From Field:", from_field)

        if "<" in from_field and ">" in from_field:
            display_name = from_field.split("<")[0].strip()
            email_address = from_field.split("<")[1].split(">")[0]
        else:
            display_name = ""
            email_address = from_field.strip()

        print("Display Name:", display_name)
        print("Actual Email Address:", email_address)

        if is_display_name_legit(display_name, email_address):
            return True
        else:
            return False

    is_display_match = is_display()
    analysis_results["sender_analysis"]["display-match"] = is_display_match
    print(is_display_match)

    # Typosquatting Detection
    def load_trusted_domains(file_path="trusted_domains.txt"):
        with open(file_path, "r", encoding="utf-8") as file:
            trusted_domains = [line.strip() for line in file]
        return trusted_domains

    def detect_typosquatting_levenshtein(sender_domain, trusted_domains, threshold=2):
        for trusted in trusted_domains:
            distance = Levenshtein.distance(sender_domain, trusted)
            if distance <= threshold:
                return True
        return False

    def fuzzy_detect(sender_domain, trusted_domains, threshold=85):
        match, score = process.extractOne(sender_domain, trusted_domains)
        if score >= threshold:
            return True
        return False

    def is_combined_typosquatting_check(sender_domain, trusted_domains, levenshtein_threshold=2, fuzzy_threshold=85):
        levenshtein_result = detect_typosquatting_levenshtein(sender_domain, trusted_domains, levenshtein_threshold)
        fuzzy_result = fuzzy_detect(sender_domain, trusted_domains, fuzzy_threshold)
        return False == fuzzy_result or False == levenshtein_result

    trusted_domains = load_trusted_domains("trusted_domains.txt")  # Load domains from the text file

    typo_check_result = is_combined_typosquatting_check(sender_domain, trusted_domains)
    analysis_results["sender_analysis"]["typosquatting"] = typo_check_result
    print("Typosquatting:", typo_check_result)

    # SPF Check
    def check_spf(domain):
        try:
            result = dns.resolver.resolve(domain, 'TXT')
            
            for txt_record in result:
                if txt_record.to_text().lower().startswith('"v=spf1'):
                    return True
            
            return False
        
        except dns.resolver.NoAnswer:
            return "No TXT records found for the domain."
        
        except dns.resolver.NXDOMAIN:
            return "The domain does not exist."
        
        except dns.resolver.Timeout:
            return "DNS query timed out."
        
        except Exception as e:
            return f"Error checking SPF: {e}"

    spf_result = check_spf(sender_domain)
    analysis_results["sender_analysis"]["spf"] = spf_result
    print("SPF:", spf_result)

    # DMARC Check
    def check_dmarc(domain):
        try:
            result = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            
            for txt_record in result:
                if txt_record.to_text().lower().startswith('"v=dmarc1'):
                    return True
            
            return False
        
        except dns.resolver.NoAnswer:
            return "No DMARC TXT records found for the domain."
        
        except dns.resolver.NXDOMAIN:
            return "The domain or subdomain does not exist."
        
        except dns.resolver.Timeout:
            return "DNS query timed out."
        
        except Exception as e:
            return f"Error checking DMARC: {e}"

    dmarc_result = check_dmarc(sender_domain)
    analysis_results["sender_analysis"]["dmarc"] = dmarc_result
    print("DMARC:", dmarc_result)

    # DKIM Check
    def extract_dkim_selectors_and_domain(eml_file_path):
        try:
            with open(eml_file_path, 'rb') as eml_file:
                msg = BytesParser(policy=policy.default).parse(eml_file)

            dkim_signatures = msg.get_all('DKIM-Signature')
            if not dkim_signatures:
                return "No DKIM-Signature headers found in the email."

            selectors = []
            domains = []
            for dkim_signature in dkim_signatures:
                selector = None
                domain = None
                for part in dkim_signature.split(';'):
                    part = part.strip()
                    if part.startswith('s='):
                        selector = part[2:].lower()
                    elif part.startswith('d='):
                        domain = part[2:].lower()
                
                if selector and domain:
                    selectors.append(selector)
                    domains.append(domain)

            if selectors and domains:
                return selectors, domains
            else:
                return [], []

        except Exception as e:
            return f"Error extracting DKIM selectors and domain: {e}"

    def check_dkim_record(domain, selector):
        try:
            dkim_record = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
            for record in dkim_record:
                return True
            return False
        except Exception as e:
            return False

    def dkim_check(eml_file_path):
        result = extract_dkim_selectors_and_domain(eml_file_path)

        if isinstance(result, tuple) and len(result) == 2:
            selectors, domains = result
            print(f"DKIM Selectors: {selectors}")
            print(f"DKIM Domains: {domains}")

            dkim_check_results = []
            for selector, domain in zip(selectors, domains):
                dkim_check_results.append(check_dkim_record(domain, selector))

            print(f"DKIM Check Results: {dkim_check_results}")
            return True
        else:
            print(result)  # Print error message if extraction fails
            return False

    dkim_result = dkim_check(email_eml)
    analysis_results["sender_analysis"]["dkim"] = dkim_result
    print("DKIM:", dkim_result)

    # Returning the complete JSON of analysis
    return json.dumps(analysis_results, indent=4)

# Example usage:
print(sender_checker("email.eml"))
