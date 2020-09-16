#!/usr/bin/env python3

import jq
import os
import re
import glob
import yaml
import argparse
import configparser
import packaging.version


class Audit(object):
    """Class to hold audit values and functions
    When built, it will take the configparser for a file and populate the
    values if they exist
    """

    def __init__(self, config: configparser.ConfigParser):
        # Grab required fields and use them
        self.name: str = config['Default']['name'].strip('"')
        self.severity: str = config['Default']['severity'].strip('"')
        self.message: str = config['Default']['message'].strip('"')

        if "fixed_in" in config['Default']:
            self.fixed_in = packaging.version.parse(
                config['Default']['fixed_in'].strip('"'))

        self.is_fixed: bool = False

        if 'regex' in config['Default'] or 'regexes' in config:
            self.regex: re.Pattern = self.build_regex(config)
        elif 'query' in config['Default']:
            self.query: jq._Program = self.build_query(config)
        else:
            raise Exception("Audit file missing either regex or jq query")

        self.affected_files = {
            "regex": [],
            "query": [],
        }

    def is_fixed_in(self, target_ver: str) -> bool:
        target_ver = packaging.version.parse(target_ver)
        if hasattr(self, 'fixed_in'):
            if target_ver >= self.fixed_in:
                self.is_fixed = True

        return self.is_fixed

    def __str__(self) -> str:
        str_repr = ("Issue: {name}"
                    "\nSeverity: {severity}"
                    "\nResolution: {resolution}"
                    ).format(name=self.name,
                             severity=self.severity,
                             resolution=self.message)
        if self.has_fixed_in():
            if not self.is_fixed:
                str_repr += "\nFixed in Version: " + str(self.fixed_in)
        str_repr += "\nAffected Files:"
        if self.affected_files['regex'] != []:
            str_repr += "\n  Matched regex:"
            for file in self.affected_files['regex']:
                str_repr += "\n  {}".format(file)
        if self.affected_files['query'] != []:
            str_repr += "\n  Matched query:"
            for file in self.affected_files['query']:
                str_repr += "\n  {}".format(file)
        return str_repr

    def build_regex(self, config: configparser.ConfigParser) -> re.Pattern:
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
            final_regex = regex_ignore_comment + \
                audit_config['regex'].strip('"')
        else:
            # If blank, get the regexes section
            regex_config = config['regexes']
            # Iterate over all keys in the section, since we don't actually
            # care what they're called
            for regex_spec in regex_config:
                # Prepend the ignoring comments regex, and append the gap
                # then add it to the big regex. Each regex is added in order
                # and ignores commented lines. It matches each item with any
                # number of lines in-between
                final_regex += regex_ignore_comment + \
                    regex_config[regex_spec].strip('"') + regex_gap

        # Finally compile the regex, multiline for good measure
        return re.compile(pattern=final_regex, flags=re.MULTILINE)

    def build_query(self, config: configparser.ConfigParser) -> str:
        # Return the compiled query
        return jq.compile(config['Default']['query'])

    def audit_regex(self, file: os.PathLike):
        with open(file=file, mode='r') as open_file:
            # Read file into memory and search it all for regex
            pattern_in_file = re.search(pattern=self.regex,
                                        string=str(open_file.read()))

            if pattern_in_file:
                self.affected_files['regex'].append(file)

    def audit_query(self, file: os.PathLike):
        with open(file=file, mode='r') as open_file:
            yaml_data = yaml.safe_load_all(stream=open_file)
            # Iterate over all the data returned from load_all
            # May contain nested lists for multi-yaml files
            for yaml_doc in yaml_data:
                # If we have a nested yaml, test against all nested elements
                if isinstance(yaml_doc, (list,)):
                    # Iterate over each inner yaml
                    for yaml_inner_doc in yaml_doc:
                        # Return True if any yaml in the file
                        # satisfies the query
                        if True in self.query.input(yaml_inner_doc).all():
                            self.affected_files['query'].append(file)
                else:
                    # Else if we only have a single doc, just test that
                    if True in self.query.input(yaml_doc).all():
                        self.affected_files['query'].append(file)

    def has_affected_regex(self) -> bool:
        return self.affected_files['regex'] != []

    def has_affected_query(self) -> bool:
        return self.affected_files['query'] != []

    def has_no_affected_files(self) -> bool:
        return ((not self.has_affected_query()) and
                (not self.has_affected_regex()))

    def has_fixed_in(self) -> bool:
        return hasattr(self, "fixed_in")

    def has_regex(self) -> bool:
        return hasattr(self, "regex")

    def has_query(self) -> bool:
        return hasattr(self, "query")


# Printer for auditing results, just takes in the list of dicts
# and prints out the fields in them in a pretty print way
def print_audit_results(results: [Audit], parse_errors: [os.PathLike]):
    print("Audit Results:")
    print()
    # Apply sorting based on the severity key, hence why we prepend an integer
    for result in sorted(results, key=lambda k: k.severity):
        print(result)
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


def audit_yaml(audits: [Audit], target_files: [os.PathLike]):

    # Holder for parsing errors in files
    parse_errors = []

    # Critical section of the code
    # Iterate over all target files and apply audits to each
    for file in target_files:
        # Iterate over all audits for each file
        # May need to change this structure for multi-file audits
        # Maybe do a multi-file function that can just pass in the target_files
        # array
        for audit_class in audits:
            # If we have a regex in the audit, use it
            if audit_class.has_regex():
                # Results of this get stored into the class
                audit_class.audit_regex(file=file)

            # If we have a jq query, we need to do a try/catch
            if audit_class.has_query():
                # Skip the file if the yaml parser can't pick it up
                if file not in parse_errors:
                    try:
                        # Try applying the query to the file. Since it only
                        # actually parses the file at runtime, wrap it here
                        # in the try/catch
                        audit_class.audit_query(file=file)
                    except yaml.YAMLError:
                        # If we hit an error, add it to parse_errors list
                        # so we can skip it on next iteration
                        parse_errors.append(file)

    # Sort the parse errors and return the accumulators
    return audits, sorted(parse_errors)


# Takes in each audit spec, and search for the regex in each file, and
# if found adds the file to a list of files affected by the given audit
def audit(audit_specs: [os.PathLike], target_dir: os.PathLike,
          target_ver: str, type: str) -> dict:

    audits = []
    for audit_file in audit_specs:
        # Create INI config parser, used because it's easier
        config = configparser.ConfigParser()

        # Read in given config file
        config.read(filenames=audit_file)

        audit_class = Audit(config)
        # If we have a target version specified, check it
        if target_ver:
            # If it's already fixed, just continue on
            if not audit.is_fixed_in(target_ver):
                continue

        audits.append(audit_class)

    # Walk the target directory and gather all the files into single paths
    target_files = walk_directories(target_dir=target_dir, type=type)

    if type == "yaml":
        audit_results = []
        audits, parse_errors = audit_yaml(audits, target_files)
        for audit_class in audits:
            if not audit_class.has_no_affected_files():
                audit_results.append(audit_class)

        return audit_results, parse_errors
    # Else if type not 'yaml' for now, just pass
    else:
        pass


def main():
    # Create parser for CLI arguments
    parser = argparse.ArgumentParser()
    # Target directory, files in here get enumerated by the code
    parser.add_argument(
        "target", help="Target directory containing files to audit")
    # Optional version argument to compare against for audits that contain
    # a version that they're fixed in
    parser.add_argument(
        "-v", "--version", help="Target version of OpenShift to check against")
    # Type of audit to perform, currently only yaml
    parser.add_argument(
        "-t", "--type", help="Type of audit to perform: yaml, go, helm. \
        Currently OpenShift manifests (yaml) are the only supported type")

    # Parse all the CLI arguments
    args = parser.parse_args()

    # Split the arguments into variables
    target_dir = args.target
    target_ver = args.version
    type = args.type

    # Set a default value for type
    if type:
        pass
    else:
        type = "yaml"

    # Get the path of the audit files, will always be relative to script
    # location
    audit_dir = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "audits/", type)

    # Get all audit files by the .audit extension
    audit_files = glob.glob(pathname=os.path.join(
        audit_dir, "*.audit"), recursive=True)

    # Run the actual audit method here
    audit_results, parse_errors = audit(audit_specs=audit_files,
                                        target_dir=target_dir,
                                        target_ver=target_ver, type=type)

    # Pass on all results for printing
    print_audit_results(audit_results, parse_errors)


if __name__ == '__main__':
    main()
