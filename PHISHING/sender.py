import email

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
