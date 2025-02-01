import email

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
    print("✅ Display name matches the email domain.")
else:
    print("⚠️ Warning! Display name and email domain do not match.")
