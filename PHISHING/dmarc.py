import dns.resolver

def check_dmarc(domain):
    try:
        # DMARC record is stored as a TXT record with "_dmarc" as the subdomain
        result = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        
        # Iterate through all TXT records
        for txt_record in result:
            # Check if the record starts with 'v=DMARC1' (case insensitive)
            if txt_record.to_text().lower().startswith('"v=dmarc1'):
                return f"DMARC Record found: {txt_record}"
        
        # If no DMARC record is found
        return "No DMARC record found."
    
    except dns.resolver.NoAnswer:
        return "No DMARC TXT records found for the domain."
    
    except dns.resolver.NXDOMAIN:
        return "The domain or subdomain does not exist."
    
    except dns.resolver.Timeout:
        return "DNS query timed out."
    
    except Exception as e:
        return f"Error checking DMARC: {e}"

# Example usage
domain = "google.com"  # Example domain to check
print(check_dmarc(domain))