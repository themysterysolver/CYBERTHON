import dns.resolver
from email import policy
from email.parser import BytesParser

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
eml_file_path = "email.eml"  # Path to your .eml file
result = extract_dkim_selectors_and_domain(eml_file_path)

if isinstance(result, tuple) and len(result) == 2:
    selectors, domains = result
    print(f"DKIM Selectors: {selectors}")
    print(f"DKIM Domains: {domains}")
    
    dkim_check_results = []
    for selector, domain in zip(selectors, domains):
        dkim_check_results.append(check_dkim_record(domain, selector))
    
    print(f"DKIM Check Results: {dkim_check_results}")
else:
    print(result)  # Print error message if extraction fails