import Levenshtein
from fuzzywuzzy import process

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
    for trusted in trusted_domains:
        distance = Levenshtein.distance(sender_domain, trusted)
        if distance <= threshold:
            return f"⚠️ Possible spoofing! {sender_domain} looks like {trusted} (Levenshtein Distance: {distance})"
    
    return "✅ No typosquatting detected."

def fuzzy_detect(sender_domain, trusted_domains, threshold=85):
    """
    Check if the sender's domain is similar to any trusted domain using fuzzy matching.
    """
    match, score = process.extractOne(sender_domain, trusted_domains)
    
    if score >= threshold:
        return f"⚠️ Possible phishing! {sender_domain} looks like {match} (Fuzzy Match: {score}%)"
    
    return "✅ No typosquatting detected."

def combined_typosquatting_check(sender_domain, trusted_domains, levenshtein_threshold=2, fuzzy_threshold=85):
    """
    Check for typosquatting using both Levenshtein distance and fuzzy matching.
    """
    # Apply Levenshtein Distance Check
    levenshtein_result = detect_typosquatting_levenshtein(sender_domain, trusted_domains, levenshtein_threshold)
    if "⚠️" in levenshtein_result:
        return levenshtein_result

    # Apply Fuzzy Matching Check
    fuzzy_result = fuzzy_detect(sender_domain, trusted_domains, fuzzy_threshold)
    return fuzzy_result

# Example usage
trusted_domains = load_trusted_domains("trusted_domains.txt")  # Load domains from the text file

sender_domain = "microsoftt.com"  # Example suspicious sender domain
result = combined_typosquatting_check(sender_domain, trusted_domains)
print(result)
