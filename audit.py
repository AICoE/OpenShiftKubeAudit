#!/usr/bin/env python3

import os
import re
import glob
import argparse
import configparser


# Regex to ignore commented lines
regex_ignore_comment = "^[^#\\n]*"
# Regex for any number of lines, used to match in-between regexes
regex_gap = ".*(\\n.*)*"


# Printer for auditing results, just takes in the list of dicts
# and prints out the fields in them in a pretty print way
def print_audit_results(results: [dict]):
    print("Audit Results:")
    print()
    for result in results:
        if result['affected_files'] != []:
            print("Issue: " + result['name'])
            print("Severity: " + result['severity'])
            print("Resolution: " + result['message'])
            print("Affected Files:")
            for file in result['affected_files']:
                print("  " + file)
            print()


# Takes in each audit spec, and search for the regex in each file, and
# if found adds the file to a list of files affected by the given audit
def audit(auditspec: os.PathLike, targetdir: os.PathLike) -> dict:
    # Walk the target directory and gather all the files into single paths
    targetfiles = [os.path.join(r, file)
                   for r, d, f in os.walk(targetdir) for file in f]

    # Create INI config parser, used because it's easier
    config = configparser.ConfigParser()
    # Read in given config file
    config.read(filenames=auditspec)
    # Don't need to worry about sections, just chop it down to Default section
    auditconfig = config['Default']

    # Holder for fully built regex
    finalregex = ""

    # Check if regex key is blank, if so we need to construct a big one
    if auditconfig['regex'].strip('"') == "":
        # If blank, get the regexes section
        regexconfig = config['regexes']
        # Iterate over all keys in the section, since we don't actually care
        # what they're called
        for regexspec in regexconfig:
            # Prepend the ignoring comments regex, and append the gap
            # then add it to the big regex. Each regex is added in order
            # and ignores commented lines. It matches each item with any
            # number of lines in-between
            finalregex += regex_ignore_comment + \
                regexconfig[regexspec].strip('"') + regex_gap
    else:
        # With a single regex, just prepend the ignoring of comments
        finalregex = regex_ignore_comment + auditconfig['regex'].strip('"')

    regex = re.compile(pattern=finalregex, flags=re.IGNORECASE + re.MULTILINE)

    # Gather up the other fields
    # TODO(spryor): add check for unpopulated fields?
    auditresults = {
        "name": auditconfig['name'].strip('"'),
        "severity": auditconfig['severity'].strip('"'),
        "message": auditconfig['message'].strip('"'),
        "affected_files": [],
    }

    # Iterate over all the files in the target directory, and
    # add any affected files to the affected_files array
    for file in targetfiles:
        # With to ensure it's closed properly
        with open(file=file, mode='r') as openfile:
            # Read file into memory and search it all for regex
            pattern_in_file = re.search(pattern=regex,
                                        string=str(openfile.read()))
            # If any match found, add it to the affected_files list
            if pattern_in_file:
                auditresults['affected_files'].append(file)

    return auditresults


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target", help="Target directory containing files to audit")
    args = parser.parse_args()

    targetdir = args.target
    auditdir = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "audits/")
    # Get all audit files by the .audit extension
    auditfiles = glob.glob(pathname=auditdir + "*.audit", recursive=True)

    # Collector for all the audit results
    all_audit_results = []
    # Run over each .audit file
    for auditfile in auditfiles:
        # Add audit results to array, pass the audit file to the audit routine
        all_audit_results.append(audit(auditfile, targetdir))

    # Pass on all results for printing
    print_audit_results(all_audit_results)


if __name__ == '__main__':
    main()
