import dns.resolver

def check_spf(domain):
    try:
        # Query the domain's TXT records
        result = dns.resolver.resolve(domain, 'TXT')
        
        # Iterate through all TXT records
        for txt_record in result:
            # Check if the record starts with 'v=spf1' (case insensitive)
            if txt_record.to_text().lower().startswith('"v=spf1'):
                return f"SPF Record found: {txt_record}"
        
        # If no SPF record is found
        return "No SPF record found."
    
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