import csv
import Levenshtein
trusted_domains = set()

with open("majestic_million.csv", "r", encoding="utf-8") as file:
    reader = csv.reader(file)
    next(reader)  # Skip header
    for row in reader:
        domain = row[2].strip()  # Column 2 contains the domain name
        trusted_domains.add(domain)
        
def detect_typosquatting(sender_domain, trusted_domains, threshold=2):
    """
    Check if the sender's domain is similar to any trusted domain.
    A small Levenshtein distance (1-2) means it's likely typosquatting.
    """
    for trusted in trusted_domains:
        distance = Levenshtein.distance(sender_domain, trusted)
        if distance <= threshold:  # Small edit distance means suspicious
            return f"⚠️ Warning! {sender_domain} looks like {trusted} (distance: {distance})"

    return "✅ No typosquatting detected."

# Example: Check a suspicious domain
sender_domain = "microsoftt.com"
result = detect_typosquatting(sender_domain, trusted_domains)
print(result)