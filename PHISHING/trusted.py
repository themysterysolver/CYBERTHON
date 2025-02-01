import csv

# Save trusted domains to a text file instead of memory
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
        print(f"✅ {sender_domain} is a legitimate domain!")
    else:
        print(f"⚠️ {sender_domain} is NOT in the Majestic list! Be cautious.")