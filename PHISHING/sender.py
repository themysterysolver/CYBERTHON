import email
import csv

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
