#!/usr/bin/env python3

import os
import re
import glob
import argparse
import configparser
import packaging.version


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
            if "fixedin" in result:
                print("Fixed in Version: " + str(result['fixedin']))
            print("Affected Files:")
            for file in result['affected_files']:
                print("  " + file)
            print()


# Takes in each audit spec, and search for the regex in each file, and
# if found adds the file to a list of files affected by the given audit
def audit(auditspec: os.PathLike, target_dir: os.PathLike,
          target_ver: str) -> dict:
    # Walk the target directory and gather all the files into single paths
    target_files = [os.path.join(r, file)
                    for r, d, f in os.walk(target_dir) for file in f]

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

    # Finally compile the regex, ignorecase and multiline for good measure
    regex = re.compile(pattern=finalregex, flags=re.IGNORECASE + re.MULTILINE)

    # Gather up the other fields
    # TODO(spryor): add check for unpopulated fields?
    auditresults = {
        "name": auditconfig['name'].strip('"'),
        "severity": auditconfig['severity'].strip('"'),
        "message": auditconfig['message'].strip('"'),
        "affected_files": [],
    }

    # If there's a version that it's fixed in, check whether or not we use it
    if "fixedin" in auditconfig:
        # Parse in our version, using packaging.version for convenience
        fixedin_ver = packaging.version.parse(
            auditconfig["fixedin"].strip('"'))
        target_ver = packaging.version.parse(target_ver)
        # Set this in either case
        auditresults["fixedin"] = fixedin_ver
        # If it's fixed in the version we're testing against, just return
        # with auditresults["affected_files"] == []
        if target_ver >= fixedin_ver:
            return auditresults

    # Iterate over all the files in the target directory, and
    # add any affected files to the affected_files array
    for file in target_files:
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
    parser.add_argument(
        "-v", "--version", help="Target version of OpenShift to check against")
    args = parser.parse_args()

    target_dir = args.target
    target_ver = args.version
    auditdir = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "audits/")
    # Get all audit files by the .audit extension
    auditfiles = glob.glob(pathname=auditdir + "*.audit", recursive=True)

    # Collector for all the audit results
    all_audit_results = []
    # Run over each .audit file
    for auditfile in auditfiles:
        # Pass the audit file to the routine
        all_audit_results.append(
            audit(auditspec=auditfile, target_dir=target_dir,
                  target_ver=target_ver))

    # Pass on all results for printing
    print_audit_results(all_audit_results)


if __name__ == '__main__':
    main()
