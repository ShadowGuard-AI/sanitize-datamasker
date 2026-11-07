import argparse
import csv
import io
import logging
import os
import random
import re
import sys

from faker import Faker

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Sanitize data in text or CSV files by replacing sensitive information with fake data."
    )
    parser.add_argument(
        "input_file",
        help="The input file to sanitize (text or CSV).",
        type=str
    )
    parser.add_argument(
        "output_file",
        help="The output file to write the sanitized data to.",
        type=str
    )
    parser.add_argument(
        "--fields",
        nargs="+",
        help="A list of fields to mask. For CSV files, each field is a column header, matched case-insensitively. For text files, each field is a regex pattern that matches the text to mask, for example '[A-Za-z0-9._%%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}' for email addresses.",
        required=True,
        type=str
    )
    parser.add_argument(
        "--file_type",
        choices=["text", "csv"],
        default="text",
        help="The type of input file (text or csv). Defaults to text.",
        type=str
    )
    parser.add_argument(
        "--locale",
        default="en_US",
        help="The locale for generating fake data (e.g., en_US, de_DE). Defaults to en_US.",
        type=str
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Optional seed for Faker's random number generator, for reproducible results."
    )

    return parser


def sanitize_text(input_file, output_file, fields, faker, seed=None):
    """
    Sanitizes a text file by replacing sensitive data with fake data based on provided regex patterns.

    Args:
        input_file (str): Path to the input text file.
        output_file (str): Path to the output text file.
        fields (list): List of regex patterns representing fields to mask.
        faker (Faker): Faker instance for generating fake data.
        seed (int, optional): Seed value for Faker's random generator for reproducibility.
    """
    # seed is tested for truth, here and in the CSV twin below, so a
    # seed of 0 is silently ignored and the run is not reproducible
    # even though the user passed the flag.
    if seed:
        random.seed(seed)
        faker.seed(seed)  # Seed the Faker instance for reproducibility

    try:
        # Read the whole input fully before any write opens.
        with open(input_file, "r", encoding="utf-8") as infile:
            lines = infile.readlines()

        if not lines:
            logging.error("Nothing to sanitize: the input file is empty.")
            sys.exit(1)

        counts = {field: 0 for field in fields}
        sanitized_lines = []
        for line in lines:
            sanitized_line = line
            for field in fields:
                try:
                    # Sanitize using Faker providers based on the field name
                    if "name" in field.lower():
                        replacement = faker.name()
                    elif "address" in field.lower():
                        replacement = faker.address()
                    elif "phone" in field.lower():
                        replacement = faker.phone_number()
                    elif "email" in field.lower():
                        replacement = faker.email()
                    else:
                        # Default masking with random string
                        replacement = faker.pystr(min_chars=10, max_chars=20)
                    # One replacement value is generated per field per
                    # line and reused for every match on that line. Two
                    # different addresses on one line both become the
                    # same fake address, and a later pattern can match
                    # inside the fake text an earlier field inserted.
                    sanitized_line, made = re.subn(
                        field, lambda match: replacement, sanitized_line
                    )
                    counts[field] += made
                except re.error as e:
                    logging.error(f"Regex error for pattern '{field}': {e}")
                    sys.exit(1)
            sanitized_lines.append(sanitized_line)

        for field in fields:
            if counts[field] == 0:
                logging.error(f"Not masked: field '{field}' made 0 replacements.")
                sys.exit(1)

        with open(output_file, "w", encoding="utf-8") as outfile:
            outfile.writelines(sanitized_lines)
        for field in fields:
            logging.info(f"Masked field '{field}': {counts[field]} replacement(s)")
        logging.info(f"Successfully sanitized text file from {input_file} to {output_file}")

    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
        sys.exit(1)
    except IOError as e:
        logging.error(f"I/O error: {e}")
        sys.exit(1)


# The CSV path behaves differently from the text path above: every
# row gets a fresh fake value, and an empty cell is filled with fake
# data and counted as masked just like a cell that held real data.
def sanitize_csv(input_file, output_file, fields, faker, seed=None):
    """
    Sanitizes a CSV file by replacing data in specified columns with fake data.

    Args:
        input_file (str): Path to the input CSV file.
        output_file (str): Path to the output CSV file.
        fields (list): List of column headers to mask.
        faker (Faker): Faker instance for generating fake data.
        seed (int, optional): Seed value for Faker's random generator for reproducibility.
    """
    if seed:
        random.seed(seed)
        faker.seed(seed)  # Seed the Faker instance for reproducibility

    try:
        # Read the whole input fully before any write opens.
        with open(input_file, "r", newline="", encoding="utf-8") as infile:
            content = infile.read()

        if not content.strip():
            logging.error("Nothing to sanitize: the input file is empty.")
            sys.exit(1)

        reader = csv.DictReader(io.StringIO(content))
        if reader.fieldnames is None:
            logging.error("CSV error: the input file has no header row (fieldnames is None).")
            sys.exit(1)
        rows = list(reader)
        if not rows:
            logging.error("Nothing to sanitize: the input file holds no data rows.")
            sys.exit(1)

        # Match requested fields against headers case-insensitively,
        # before writing anything.
        header_by_lower = {header.lower(): header for header in reader.fieldnames}
        matched = {}
        unmatched = []
        for field in fields:
            header = header_by_lower.get(field.lower())
            if header is None:
                unmatched.append(field)
            else:
                matched[field] = header
        if unmatched:
            logging.error(f"Requested field(s) matched no CSV column: {', '.join(unmatched)}")
            sys.exit(1)

        counts = {field: 0 for field in fields}
        for row in rows:
            for field in fields:
                header = matched[field]
                try:
                    # Sanitize using Faker providers based on the field name
                    if "name" in field.lower():
                        row[header] = faker.name()
                    elif "address" in field.lower():
                        row[header] = faker.address()
                    elif "phone" in field.lower():
                        row[header] = faker.phone_number()
                    elif "email" in field.lower():
                        row[header] = faker.email()
                    else:
                        row[header] = faker.pystr(min_chars=10, max_chars=20)
                    counts[field] += 1
                except Exception as e:
                    logging.error(f"Error sanitizing field '{field}': {e}")
                    sys.exit(1)

        for field in fields:
            if counts[field] == 0:
                logging.error(f"Not masked: field '{field}' made 0 replacements.")
                sys.exit(1)

        with open(output_file, "w", newline="", encoding="utf-8") as outfile:
            writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
            writer.writeheader()  # Write the header to the output file
            writer.writerows(rows)
        for field in fields:
            logging.info(f"Masked field '{field}': {counts[field]} replacement(s)")
        logging.info(f"Successfully sanitized CSV file from {input_file} to {output_file}")

    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
        sys.exit(1)
    except IOError as e:
        logging.error(f"I/O error: {e}")
        sys.exit(1)
    except csv.Error as e:
        logging.error(f"CSV error: {e}")
        sys.exit(1)


def main():
    """
    Main function to parse arguments and call the appropriate sanitization function.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    if not os.path.exists(args.input_file):
        logging.error(f"Input file does not exist: {args.input_file}")
        sys.exit(1)

    if os.path.realpath(args.output_file) == os.path.realpath(args.input_file):
        logging.error("Output file must not be the input file.")
        sys.exit(1)

    try:
        faker = Faker(args.locale)
    except AttributeError:
        logging.error(f"Invalid locale: {args.locale}")
        sys.exit(1)
    except ImportError:
        logging.error(f"Faker locale {args.locale} not installed. Install it using 'pip install faker_{args.locale.replace('-', '_')}'")
        sys.exit(1)
    
    if args.file_type == "text":
        sanitize_text(args.input_file, args.output_file, args.fields, faker, args.seed)
    elif args.file_type == "csv":
        sanitize_csv(args.input_file, args.output_file, args.fields, faker, args.seed)
    else:
        logging.error(f"Invalid file type: {args.file_type}")
        sys.exit(1)


if __name__ == "__main__":
    main()