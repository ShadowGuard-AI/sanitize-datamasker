import argparse
import csv
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
        help="A list of fields to mask (e.g., name, address, phone).  For CSV files, this is the column header.  For text files, this should be a regex pattern.",
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
    if seed:
        random.seed(seed)
        faker.seed(seed)  # Seed the Faker instance for reproducibility

    try:
        with open(input_file, "r", encoding="utf-8") as infile, open(
            output_file, "w", encoding="utf-8"
        ) as outfile:
            for line in infile:
                sanitized_line = line
                for field in fields:
                    try:
                        # Sanitize using Faker providers based on the field name
                        if "name" in field.lower():
                            sanitized_line = re.sub(
                                field, faker.name(), sanitized_line
                            )
                        elif "address" in field.lower():
                            sanitized_line = re.sub(
                                field, faker.address(), sanitized_line
                            )
                        elif "phone" in field.lower():
                            sanitized_line = re.sub(
                                field, faker.phone_number(), sanitized_line
                            )
                        elif "email" in field.lower():
                            sanitized_line = re.sub(
                                field, faker.email(), sanitized_line
                            )
                        else:
                            # Default masking with random string
                            sanitized_line = re.sub(
                                field, faker.pystr(min_chars=10, max_chars=20), sanitized_line
                            )  # Mask any other fields with random strings
                    except re.error as e:
                        logging.error(f"Regex error for pattern '{field}': {e}")
                        sys.exit(1)

                outfile.write(sanitized_line)
        logging.info(f"Successfully sanitized text file from {input_file} to {output_file}")

    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
        sys.exit(1)
    except IOError as e:
        logging.error(f"I/O error: {e}")
        sys.exit(1)


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
        with open(input_file, "r", newline="", encoding="utf-8") as infile, open(
            output_file, "w", newline="", encoding="utf-8"
        ) as outfile:
            reader = csv.DictReader(infile)
            writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
            writer.writeheader()  # Write the header to the output file

            for row in reader:
                for field in fields:
                    if field in row:
                        try:
                            # Sanitize using Faker providers based on the field name
                            if "name" in field.lower():
                                row[field] = faker.name()
                            elif "address" in field.lower():
                                row[field] = faker.address()
                            elif "phone" in field.lower():
                                row[field] = faker.phone_number()
                            elif "email" in field.lower():
                                row[field] = faker.email()
                            else:
                                row[field] = faker.pystr(min_chars=10, max_chars=20)
                        except Exception as e:
                            logging.error(f"Error sanitizing field '{field}': {e}")
                            sys.exit(1)
                    else:
                        logging.warning(f"Field '{field}' not found in CSV file.")
                writer.writerow(row)
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