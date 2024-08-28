import argparse
from time import sleep
import re
import whois

def extract_artifacts(content):

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
        reply = reply_match.group(1)
        print(f"Reply-To Email : {reply}")
        
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

    extract_artifacts(eml_content)
    # Close the file
    args.eml_file.close()

if __name__ == "__main__":
    main()
