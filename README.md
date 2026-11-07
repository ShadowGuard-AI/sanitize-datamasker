# sanitize-DataMasker
A command-line tool that replaces sensitive data (e.g., names, addresses, phone numbers) in text files or CSV files with randomly generated but realistic data using Faker library. Configuration via CLI arguments, specifying fields to mask. - Focused on Provides tools for anonymizing and redacting sensitive data in text files, logs, or databases. Includes techniques like pseudonymization, generalization, and masking to protect personally identifiable information (PII) during testing or sharing.

## Install
`git clone https://github.com/ShadowGuard-AI/sanitize-datamasker`

## Usage
`python3 main.py input_file output_file --fields FIELD [FIELD ...] [--file_type text|csv]`

The output file must not be the input file; such a run is refused with exit code 1 before any file is opened, and the input is left unchanged. Both modes read the whole input before any output is written, and an output file is written only when the run succeeds. An empty input ends the run with exit code 1 and a plain nothing to sanitize message in both modes.

## Parameters
- `input_file` (required): The input file to sanitize (text or CSV).
- `output_file` (required): The output file to write the sanitized data to. It must not be the input file.
- `-h, --help`: Show help message and exit
- `--fields` (required): The fields to mask. In CSV mode each field is a column header, matched case-insensitively, so a field written as name matches a header Name; if any requested field matches no column, the run exits with code 1 naming the unmatched fields and writes nothing. In text mode each field is a regex pattern that matches the text to mask (one instruction for both the help text and this README: text mode fields are regex patterns, not bare field names). Worked text mode example: `--fields "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"` masks email addresses in the text, because the pattern matches an address. The bare word email as a pattern would match only the literal word email. In text mode, replacements are counted per field; a field with zero replacements ends the run with exit code 1 and a not masked status naming the field, and no output file is left behind. A successful run reports the per field replacement counts.
- `--file_type`: The type of input file, text or csv. Defaults to text.
- `--locale`: The locale for generating fake data. Defaults to en_US.
- `--seed`: Optional seed for Faker

## License
MIT License. See LICENSE.
