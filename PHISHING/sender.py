import email
import csv

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
