import argparse
from time import sleep
import re
import whois
import os
import email
from email import policy
from email.parser import BytesParser
from rich import print
import hashlib

def extract_artifacts(content):
    subject = None
    sender = None
    rec = None
    var_date = None
    reply_to = None
    x_ip = None
    r_dns = None
    f_match = None
    filename = None

    #print("Following artifacts are extracted!")
    print("  ")
    print("  ")

    #Extracting Subject from email
    subject_match = re.search(r'^Subject: (.*)$', content, re.MULTILINE)
    if subject_match:
        subject = subject_match.group(1)
        print(f"Subject: {subject}")
    else:
        print("No subject found in the email headers.")

    #Extracting Senders email
    sender_match = re.search(r'^From: (.*)$', content, re.MULTILINE)
    if sender_match:
        sender = sender_match.group(1)
        print(f"Email Received From : {sender}")
    else:
        print("Senders email not found.")

    #Extracting Receipients Email
    receipt_match = re.search(r'^To: (.*)$', content, re.MULTILINE)
    if receipt_match:
        rec = receipt_match.group(1)
        print(f"Recipient Email : {rec}")
    else:
        print("Recipient email not found.")

    #Extracting Date from the email
    date_match = re.search(r'^Date: (.*)$', content, re.MULTILINE)
    if date_match:
        var_date = date_match.group(1)
        print(f"Date : {var_date}")
    else:
        print("Date not found.")

    #Extracting Reply-To Email
    reply_match = re.search(r'^Reply-To: (.*)$', content, re.MULTILINE)
    if reply_match:
        reply_to = reply_match.group(1)
        print(f"Reply-To Email : {reply_to}")  
    else:
        print("Reply-To Email NOT Found.")

    #Extracting X-Sender-IP and Reverse DNS
    x_match = re.search(r'^X-Sender-IP: (.*)$', content, re.MULTILINE)
    if x_match:
        x_ip = x_match.group(1)
        print(f"X-Sender-IP : {x_ip}")
        print(" ")
        print("Performing reverse DNS on Sender-IP...")
        print(" ")
        r_dns = whois.whois(x_ip)
        print(r_dns)
    else:
        print("X-Sender-IP NOT Found.")

    #Extracting Filename
    file_match = re.search(r'filename="([^"]*)"', content, re.IGNORECASE)
    if file_match:
        f_match = file_match.group(1)
        print(f"\n Attachment Found: {f_match}")
        file_analysis(content)
        return f_match
    else:
        print("\n Attachment Not Found")
        return None
    

    #save_to_file(subject, sender, rec, var_date, reply_to, x_ip, r_dns, f_match)

"""This function is used to extract attachment from the email
this uses python's email module"""
def file_analysis(content):
    """Extracts and saves the attachment from the email content."""
    msg = email.message_from_string(content, policy=policy.default)
    
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            with open(filename, 'wb') as f:
                f.write(part.get_payload(decode=True))
            print(f"Attachment saved as {filename}")
            return filename
        else:
            print("No valid filename for attachment.")
            
    
def delete_attachment(f_match):
    user_input = input("Do You want to delete the attachment file (Y/N): ")
    if user_input == 'Y':
        if f_match and os.path.isfile(f_match):
            print(f"File {f_match} exists. Deleting it...")
            os.remove(f_match)
            print(f"File {f_match} has been deleted.")
        else:
            print("No file found or file does not exist.")
    else:
        print(f"[bold red]DO NOT OPEN {f_match}, IT MAY CONTAIN MALWARE.[/bold red]")

#Function to calculate file hash
def calc_hash(filename):
    algorithm='sha256'
    hash_func = hashlib.new(algorithm)

    with open(filename, 'rb') as file: #Open file in binary mode

        while chunk := file.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest() #Returns hexadecimal string
    

# Function to Create a report
def save_to_file(subject, sender, rec, var_date, reply_to, x_ip, r_dns):
    print("Generating Report...")

    f = open("report.txt", "w")
    sub = ["Subject: \n", subject]
    f.writelines(sub)
    f.close()

    

def main():
    parser = argparse.ArgumentParser(description="PhishCatcher - Phishing Email Analysis Tool")
    parser.add_argument("eml_file", type=open, help="Path to the .eml file to be analyzed")

    # Parse the arguments
    args = parser.parse_args()

    # Read the file content
    eml_content = args.eml_file.read()
    print("Successfully loaded the .eml file.")
    sleep(2)
    print("Extracting Artifacts from the Email...")
    sleep(2)

    #Calling function to Extract Artifacts
    f_match = extract_artifacts(eml_content)

    #Calculate SHA256 Hash
    if f_match:
        try:
            file_hash = calc_hash(f_match)
            print(f"The SHA256 hash of the file is: {file_hash}")    
        except FileNotFoundError:
            print("File not found. Please enter a valid file path.")
    else:
        print(" ")

    #Deleting attachment file
    if f_match:
        delete_attachment(f_match)
    else:
        print("\n \n [yellow on blue]Thanks for using this tool...[/yellow on blue]")
    # Close the file
    args.eml_file.close()


if __name__ == "__main__":
    main()
