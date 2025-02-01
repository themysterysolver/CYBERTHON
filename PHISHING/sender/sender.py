import email
import csv

import Levenshtein
from fuzzywuzzy import process

import dns.resolver
from email import policy
from email.parser import BytesParser

#sender with legitimate email----------------------------------------------
def is_trusted(sender_domain):
    with open("trusted_domains.txt", "w", encoding="utf-8") as output:
        with open("majestic_million.csv", "r", encoding="utf-8") as file:
            reader = csv.reader(file)
            next(reader)  # Skip header
            for row in reader:
                domain = row[2].strip()  # Column 2 contains the domain name
                output.write(domain + "\n")

    print("✅ Trusted domains saved to trusted_domains.txt")
    sender_domain = "microsoftt.com"

    with open("trusted_domains.txt", "r", encoding="utf-8") as file:
        if any(sender_domain == line.strip() for line in file):
            return True
        else:
            return False


# Open the .eml file
with open("email.eml", "r", encoding="utf-8") as f:
    msg = email.message_from_file(f)

# Extract sender's email
from_email = msg["From"]
print("Sender Email:", from_email)

# Extract domain
if "<" in from_email and ">" in from_email:  # If format is "Name <email@domain.com>"
    from_email = from_email.split("<")[1].split(">")[0]

domain = from_email.split("@")[-1]
print("Sender Domain:", domain)

close_matches = is_trusted(domain)
print(close_matches)
#display---------------------------------------------------------------------------------------------------------------
def is_display():
    # Load the email from a .eml file
    with open("email.eml", "r", encoding="utf-8") as f:
        msg = email.message_from_file(f)

    # Extract the "From" field
    from_field = msg["From"]
    print("From Field:", from_field)

    # Extract display name and email separately
    if "<" in from_field and ">" in from_field:
        display_name = from_field.split("<")[0].strip()
        email_address = from_field.split("<")[1].split(">")[0]
    else:
        display_name = ""
        email_address = from_field.strip()

    print("Display Name:", display_name)
    print("Actual Email Address:", email_address)

    def is_display_name_legit(display_name, email_address):
        """
        Check if the display name matches the actual email address domain.
        """
        if "@" in email_address:
            email_domain = email_address.split("@")[-1]  # Extract domain
        else:
            return False  # Invalid email format

        # The display name should contain the domain name (e.g., "Google Support" -> google.com)
        if email_domain.lower() in display_name.lower():
            return True  # Looks legitimate
        else:
            return False  # Suspicious

    # Example check
    if is_display_name_legit(display_name, email_address):
        return True
    else:
        return False
dis=is_display()
print(dis)
#mispelling in domain--------------------------------------------------
def load_trusted_domains(file_path="trusted_domains.txt"):
    """
    Load the trusted domains from the text file into a list.
    """
    with open(file_path, "r", encoding="utf-8") as file:
        trusted_domains = [line.strip() for line in file]
    return trusted_domains

def detect_typosquatting_levenshtein(sender_domain, trusted_domains, threshold=2):
    """
    Check if the sender's domain has slight misspellings using Levenshtein distance.
    """
    Flag1=False
    for trusted in trusted_domains:
        distance = Levenshtein.distance(sender_domain, trusted)
        if distance <= threshold:
            flag1=True
    
    return flag1

def fuzzy_detect(sender_domain, trusted_domains, threshold=85):
    """
    Check if the sender's domain is similar to any trusted domain using fuzzy matching.
    """
    match, score = process.extractOne(sender_domain, trusted_domains)
    Flag2=False
    if score >= threshold:
        Flag2=True
    
    return Flag2

def is_combined_typosquatting_check(sender_domain, trusted_domains, levenshtein_threshold=2, fuzzy_threshold=85):
    """
    Check for typosquatting using both Levenshtein distance and fuzzy matching.
    """
    # Apply Levenshtein Distance Check
    levenshtein_result = detect_typosquatting_levenshtein(sender_domain, trusted_domains, levenshtein_threshold)

    # Apply Fuzzy Matching Check
    fuzzy_result = fuzzy_detect(sender_domain, trusted_domains, fuzzy_threshold)
    return False==fuzzy_result or False==levenshtein_result

# Example usage
trusted_domains = load_trusted_domains("trusted_domains.txt")  # Load domains from the text file

sender_domain = "microsoftt.com"  # Example suspicious sender domain
result_typo = is_combined_typosquatting_check(sender_domain, trusted_domains)
print("typo:{}".format(result_typo)) 
#spf-------------------------------------------------
import dns.resolver
def check_spf(domain):
    try:
        # Query the domain's TXT records
        result = dns.resolver.resolve(domain, 'TXT')
        
        # Iterate through all TXT records
        for txt_record in result:
            # Check if the record starts with 'v=spf1' (case insensitive)
            if txt_record.to_text().lower().startswith('"v=spf1'):
                return True
        
        # If no SPF record is found
        return False
    
    except dns.resolver.NoAnswer:
        return "No TXT records found for the domain."
    
    except dns.resolver.NXDOMAIN:
        return "The domain does not exist."
    
    except dns.resolver.Timeout:
        return "DNS query timed out."
    
    except Exception as e:
        return f"Error checking SPF: {e}"

# Example usage
domain = "microsoft.com"  # Example domain to check
print(check_spf(sender_domain))

#DKIM-------------------------------------------------------------------------
import dns.resolver

def check_dmarc(domain):
    try:
        # DMARC record is stored as a TXT record with "_dmarc" as the subdomain
        result = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        
        # Iterate through all TXT records
        for txt_record in result:
            # Check if the record starts with 'v=DMARC1' (case insensitive)
            if txt_record.to_text().lower().startswith('"v=dmarc1'):
                return True
        
        # If no DMARC record is found
        return False
    
    except dns.resolver.NoAnswer:
        return "No DMARC TXT records found for the domain."
    
    except dns.resolver.NXDOMAIN:
        return "The domain or subdomain does not exist."
    
    except dns.resolver.Timeout:
        return "DNS query timed out."
    
    except Exception as e:
        return f"Error checking DMARC: {e}"

# Example usage
domain = "internshala.com"  # Example domain to check
print("dmkim",check_dmarc(sender_domain))
#-DKIM------------------------------------------------------------------
def dkim(eml_file_path):
    def extract_dkim_selectors_and_domain(eml_file_path):
        try:
            # Open and parse the .eml file
            with open(eml_file_path, 'rb') as eml_file:
                msg = BytesParser(policy=policy.default).parse(eml_file)
            
            # Look for DKIM-Signature headers
            dkim_signatures = msg.get_all('DKIM-Signature')
            if not dkim_signatures:
                return "No DKIM-Signature headers found in the email."
            
            selectors = []
            domains = []
            # Iterate over all DKIM-Signature headers
            for dkim_signature in dkim_signatures:
                selector = None
                domain = None
                # Split the DKIM-Signature header by semicolon and extract the selector and domain
                for part in dkim_signature.split(';'):
                    part = part.strip()
                    if part.startswith('s='):  # Extract selector
                        selector = part[2:].lower()  # Normalize to lowercase
                    elif part.startswith('d='):  # Extract domain
                        domain = part[2:].lower()  # Normalize to lowercase
                
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
        """
        Check the DKIM record for the given domain and selector.
        Returns True if DKIM record exists, False otherwise.
        """
        try:
            # Query the DKIM record in DNS using the selector
            dkim_record = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
            for record in dkim_record:
                # If a record is found, it's valid
                return True
            return False  # No DKIM record found for this selector
        except Exception as e:
            return False  # If there's an error (e.g., DNS resolution fails), return False

    # Example usage
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
print("dkim",dkim("email.eml"))
