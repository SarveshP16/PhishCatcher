# **PhishCatcher - Phishing Email Analysis Tool**

## **Table of Contents**
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)


## **Introduction**
PhishCatcher is a command-line tool designed to help cybersecurity professionals analyze phishing emails efficiently. The tool extracts critical information from `.eml` files, including subject lines, email addresses, and attachments, and performs basic malware detection on attached files.

## **Features**
- **Extract Email Metadata:** Quickly gather information such as the sender, recipient, subject, and date.
- **Attachment Analysis:** Automatically extract and analyze attachments for potential malware.
- **Hash Calculation:** Compute the hash of email attachments for further investigation.
- **Command-Line Interface:** Easy-to-use CLI for quick integration into your workflow.

## **Installation**
### **Prerequisites**
- Python 3.6 or later
- Required Python libraries: `email`, `hashlib`, `argparse`

### **Clone the Repository**
```bash
git clone https://github.com/SarveshP16/PhishCatcher.git
cd PhishCatcher
```

### **Install Dependencies**
```bash
pip install -r requirements.txt
```

## **Usage**
PhishCatcher is used directly from the command line. Here’s how you can get started:

```bash
python3 phishcatcher.py email.eml
```

### **Command-Line Arguments**
- `eml_file`: Path to the `.eml` file to be analyzed.
- You can run `python3 phishcatcher.py -h` to view the help manual.
- Example: `python3 phishcatcher.py sample_email.eml`