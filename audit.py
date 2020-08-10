#!/usr/bin/env python3

import jq
import os
import re
import glob
import yaml
import argparse
import configparser
import packaging.version


# TODO(spryor): Need to turn this local
parse_errors = []


# Printer for auditing results, just takes in the list of dicts
# and prints out the fields in them in a pretty print way
def print_audit_results(results: [dict]):
    print("Audit Results:")
    print()
    # Apply sorting based on the severity key, hence why we prepend an integer
    for result in sorted(results, key=lambda k: k['severity']):
        # If we have an empty affected_files list, skip
        if result['affected_files']['regex'] != [] or \
                result['affected_files']['query'] != []:
            print("Issue: " + result['name'])
            print("Severity: " + result['severity'])
            print("Resolution: " + result['message'])
            if "fixed_in" in result:
                print("Fixed in Version: " + str(result['fixed_in']))
            print("Affected Files:")
            if result['affected_files']['regex'] != []:
                print("  Matched regex:")
                for file in result['affected_files']['regex']:
                    print("  " + file)
            if result['affected_files']['query'] != []:
                print("  Matched query:")
                for file in result['affected_files']['query']:
                    print("    " + file)
            print()

    # If there was any error parsing, print out the files
    if parse_errors != []:
        print("File parsing errors:")
        for err in parse_errors:
            print("  " + err)


# Walks the directories and returns a list of files that match a given "type"
# extension
def walk_directories(target_dir: os.PathLike, type: str) -> [os.PathLike]:
    target_files = []
    # Walk the target directory
    for r, d, f in os.walk(target_dir):
        # Iterate over files to join them to form full paths
        for file in f:
            # Split off the extension, check against the type
            if os.path.splitext(file)[-1].lower() == "." + type:
                # If the type matches, add it to the target files array
                target_files.append(os.path.join(r, file))
    return target_files


def build_regex(config: configparser.ConfigParser) -> re.Pattern:
    # Regex to ignore commented lines
    regex_ignore_comment = "^[^#\\n]*"
    # Regex for any number of lines, used to match in-between regexes
    regex_gap = ".*(\\n.*)*"
    # Default section convenience
    audit_config = config['Default']

    # Holder for fully built regex
    final_regex = ""

    # If we have a single regex and it's not blank, use it
    if 'regex' in audit_config and audit_config['regex'].strip('"') != "":
        # With a single regex, just prepend the ignoring of comments
        final_regex = regex_ignore_comment + audit_config['regex'].strip('"')
    else:
        # If blank, get the regexes section
        regex_config = config['regexes']
        # Iterate over all keys in the section, since we don't actually care
        # what they're called
        for regex_spec in regex_config:
            # Prepend the ignoring comments regex, and append the gap
            # then add it to the big regex. Each regex is added in order
            # and ignores commented lines. It matches each item with any
            # number of lines in-between
            final_regex += regex_ignore_comment + \
                regex_config[regex_spec].strip('"') + regex_gap

    # Finally compile the regex, multiline for good measure
    return re.compile(pattern=final_regex, flags=re.MULTILINE)


def audit_regex(regex: re.Pattern,
                target_files: [os.PathLike]) -> [os.PathLike]:
    # Holder for all affected files
    affected_files = []
    # Iterate over all the files in the target directory, and
    # add any affected files to the affected_files array
    for file in target_files:
        # With to ensure it's closed properly
        with open(file=file, mode='r') as open_file:
            # Read file into memory and search it all for regex
            pattern_in_file = re.search(pattern=regex,
                                        string=str(open_file.read()))
            # If any match found, add it to the affected_files list
            if pattern_in_file:
                affected_files.append(file)

    return affected_files


def build_query(config: configparser.ConfigParser) -> str:
    # Grab the Default section
    audit_config = config['Default']
    # Return the compiled query
    return jq.compile(audit_config['query'])


def query_file_data(query: jq._Program, yaml_data: list) -> bool:
    # Iterate over all the data returned from load_all
    # May contain nested lists for multi-yaml files
    for yaml_doc in yaml_data:
        # If we have a nested one, test against all nested elements
        if isinstance(yaml_doc, (list,)):
            # Iterate over each inner yaml
            for yaml_inner_doc in yaml_doc:
                # If the query evaluates to True, append the file
                return True in query.input(yaml_inner_doc).all()
        else:
            # Else if we only have a single doc, just test that
            return True in query.input(yaml_doc).all()


def audit_query(query: jq._Program,
                target_files: [os.PathLike]) -> [os.PathLike]:
    # Holder for all affected files
    affected_files = []
    # Iterate over all the target files, applying the query to each file
    for file in target_files:
        if file not in parse_errors:
            # Open each file in read-only mode
            with open(file=file, mode='r') as open_file:
                # Load the yaml data into a dict so we can parse with jq query
                yaml_data = yaml.safe_load_all(stream=open_file)

                try:
                    if query_file_data(query=query, yaml_data=yaml_data):
                        affected_files.append(file)
                except yaml.constructor.ConstructorError as e:
                    if file not in parse_errors:
                        parse_errors.append(file)
                except yaml.parser.ParserError as e:
                    if file not in parse_errors:
                        parse_errors.append(file)
                except yaml.scanner.ScannerError as e:
                    if file not in parse_errors:
                        parse_errors.append(file)

    # Finally return the list of files that we found issues in
    return affected_files


# Takes in each audit spec, and search for the regex in each file, and
# if found adds the file to a list of files affected by the given audit
def audit(audit_spec: os.PathLike, target_dir: os.PathLike,
          target_ver: str, type: str) -> dict:

    # Walk the target directory and gather all the files into single paths
    target_files = walk_directories(target_dir=target_dir, type=type)

    # Create INI config parser, used because it's easier
    config = configparser.ConfigParser()
    # Read in given config file
    config.read(filenames=audit_spec)
    # Don't need to worry about sections, just chop it down to Default section
    audit_config = config['Default']

    # Gather up the other fields
    audit_results = {
        "name": audit_config['name'].strip('"'),
        "severity": audit_config['severity'].strip('"'),
        "message": audit_config['message'].strip('"'),
        "affected_files": {
            "regex": [],
            "query": [],
        }
    }

    # If we set target_ver, check it, otherwise skip
    if target_ver:
        # If there's a version that it's fixed in, check whether or not we
        # specified a target version
        if "fixed_in" in audit_config:
            # Parse in our version, using packaging.version for convenience
            fixed_in_ver = packaging.version.parse(
                audit_config["fixed_in"].strip('"'))
            target_ver = packaging.version.parse(target_ver)
            # Set this in either case
            audit_results["fixed_in"] = fixed_in_ver
            # If it's fixed in the version we're testing against, just return
            # with audit_results["affected_files"] == []
            if target_ver >= fixed_in_ver:
                # Return the blank affected_files, since that will get skipped
                return audit_results

    # Hold the intermediate affected_files
    affected_files_regex = []
    affected_files_query = []
    if type == "yaml":
        # If we have regexes set in the config, check that
        if 'regex' in audit_config or 'regexes' in config:
            # Get list of affected files by regex
            affected_files_regex += audit_regex(
                regex=build_regex(config), target_files=target_files)
        # If we have the jq query set, use that as well
        if 'query' in audit_config:
            # Get list of affected files by jq string
            affected_files_query += audit_query(
                query=build_query(config), target_files=target_files)
    # Else if type not 'yaml' for now, just pass
    else:
        pass

    # Finally set the affected_files to our final list
    affected_files_regex = list(set(affected_files_regex))
    affected_files_regex.sort()
    affected_files_query = list(set(affected_files_query))
    affected_files_query.sort()
    audit_results['affected_files']['regex'] = affected_files_regex
    audit_results['affected_files']['query'] = affected_files_query

    return audit_results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target", help="Target directory containing files to audit")
    parser.add_argument(
        "-v", "--version", help="Target version of OpenShift to check against")
    parser.add_argument(
        "-t", "--type", help="Type of audit to perform: yaml, go, helm. \
        Currently OpenShift manifests (yaml) are the only supported type")
    args = parser.parse_args()

    target_dir = args.target
    target_ver = args.version
    type = args.type

    if type:
        pass
    else:
        type = "yaml"

    # Auditdir will be audits/filetype
    audit_dir = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "audits/", type)

    # Get all audit files by the .audit extension
    audit_files = glob.glob(pathname=os.path.join(
        audit_dir, "*.audit"), recursive=True)

    # Collector for all the audit results
    audit_results = []
    # Run over each .audit file
    for audit_file in audit_files:
        # Pass the audit file to the routine
        audit_result = audit(audit_spec=audit_file, target_dir=target_dir,
                             target_ver=target_ver, type=type)
        if audit_result['affected_files']['regex'] != [] or \
                audit_result['affected_files']['query'] != []:
            audit_results.append(audit_result)

    # Pass on all results for printing
    print_audit_results(audit_results)


if __name__ == '__main__':
    main()
