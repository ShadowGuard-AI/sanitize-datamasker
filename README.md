# sanitize-DataMasker
A command-line tool that replaces sensitive data (e.g., names, addresses, phone numbers) in text files or CSV files with randomly generated but realistic data using Faker library. Configuration via CLI arguments, specifying fields to mask. - Focused on Provides tools for anonymizing and redacting sensitive data in text files, logs, or databases. Includes techniques like pseudonymization, generalization, and masking to protect personally identifiable information (PII) during testing or sharing.

## Install
`git clone https://github.com/ShadowStrikeHQ/sanitize-datamasker`

## Usage
`./sanitize-datamasker [params]`

## Parameters
- `-h`: Show help message and exit
- `--fields`: No description provided
- `--file_type`: No description provided
- `--locale`: No description provided
- `--seed`: Optional seed for Faker

## License
Copyright (c) ShadowStrikeHQ
