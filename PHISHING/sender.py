import email
import csv

import Levenshtein
from fuzzywuzzy import process


#sender with legitimate email----------------------------------------------
def trusted(sender_domain):
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

close_matches = trusted(domain)
print(close_matches)
#display---------------------------------------------------------------------------------------------------------------
def display():
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
dis=display()
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

def combined_typosquatting_check(sender_domain, trusted_domains, levenshtein_threshold=2, fuzzy_threshold=85):
    """
    Check for typosquatting using both Levenshtein distance and fuzzy matching.
    """
    # Apply Levenshtein Distance Check
    flag1=False
    levenshtein_result = detect_typosquatting_levenshtein(sender_domain, trusted_domains, levenshtein_threshold)
    if flag1:
        return False

    # Apply Fuzzy Matching Check
    fuzzy_result = fuzzy_detect(sender_domain, trusted_domains, fuzzy_threshold)
    return fuzzy_result

# Example usage
trusted_domains = load_trusted_domains("trusted_domains.txt")  # Load domains from the text file

sender_domain = "microsoftt.com"  # Example suspicious sender domain
result_typo = False==combined_typosquatting_check(sender_domain, trusted_domains)
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
print(check_spf(domain))
#

