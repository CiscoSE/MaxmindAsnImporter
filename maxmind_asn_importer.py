#!/usr/bin/env python
#  -*- coding: utf-8 -*-
"""
This is a script to import MaxMind's ASN to IP range mappings into Tags (Host Groups)
within Stealthwatch Enterprise.

maxmind_asn_importer.py
----------------
Author: Alan Nix
Property of: Cisco Systems
"""

import argparse
import csv
import getpass
import json
import os
import shutil
import time
import zipfile

import requests

from stealthwatch_client import StealthwatchClient

# Config Paramters
CONFIG_FILE = "config.json"
CONFIG_DATA = {}

ZIP_FILE_NAME = "maxmind_data.zip"

# Set a wait interval (in seconds) - Default is one day
INTERVAL = 86400


####################
#    FUNCTIONS     #
####################


def load_config(retry=False):
    """Load configuration data from file."""

    print("Loading configuration data...")

    # If we have a stored config file, then use it, otherwise terminate
    if os.path.isfile(CONFIG_FILE):

        # Open the CONFIG_FILE and load it
        with open(CONFIG_FILE, "r") as config_file:
            CONFIG_DATA = json.loads(config_file.read())

        print("Configuration data loaded successfully.")

        return CONFIG_DATA

    else:
        # Check to see if this is the initial load_config attempt
        if not retry:

            # Print that we couldn't find the config file, and attempt to copy the example
            print("The configuration file was not found. Copying 'config.example.json' file to '{}', and retrying...".format(CONFIG_FILE))
            shutil.copyfile('config.example.json', CONFIG_FILE)

            # Try to reload the config
            return load_config(retry=True)
        else:

            # Exit gracefully if we cannot load the config
            print("Unable to automatically create config file. Please copy 'config.example.json' to '{}' manually.".format(CONFIG_FILE))
            exit()


def save_config():
    """Save configuration data to file."""

    with open(CONFIG_FILE, "w") as output_file:
        json.dump(CONFIG_DATA, output_file, indent=4)


def get_current_version():
    """Retrieve the latest version number of the MaxMind ASN database."""

    # Build the URL to request
    url = CONFIG_DATA["MAXMIND_VERSION_URL"] + "&license_key=" + CONFIG_DATA["MAXMIND_LICENSE_KEY"]

    try:
        # Fetch the version info from MaxMind
        response = requests.get(url)

        # Check to make sure the GET was successful
        if response.status_code == 200:

            # Return the md5 of the current ASN database file
            return response.content.decode('ascii')

    except Exception as err:
        print("Error fetching version info from MaxMind: " + str(err))
        exit(1)


def get_new_addresses():
    """Retrieve the latest IP address data from MaxMind and save the file."""

    print("Fetching address ranges from MaxMind...")

    # Build the URL to request
    url = CONFIG_DATA["MAXMIND_DATASET_URL"] + "&license_key=" + CONFIG_DATA["MAXMIND_LICENSE_KEY"]

    try:
        # Get the latest address feed from MaxMind
        response = requests.get(url, allow_redirects=True)

        # If the request was successful
        if response.status_code >= 200 or response.status_code < 300:

            # Write downloaded zip file to disk
            open(ZIP_FILE_NAME, 'wb').write(response.content)

        else:
            print("Failed to get data from MaxMind. Terminating.")
            exit()

    except Exception as err:
        print("Unable to get the MaxMind ASN data - Error: {}".format(err))
        exit()


def search_maxmind_data():
    """Unzip the fetched MaxMind data, search it, then return the Org-to-IP mappings."""

    print("Unzipping downloaded files...")

    file_list = []

    # Unzip the file from MaxMind
    try:
        with zipfile.ZipFile(ZIP_FILE_NAME, "r") as z:
            file_names = z.namelist()

            for file_name in file_names:
                if '.csv' in file_name:
                    file_list.append(file_name)
                    z.extract(file_name, "temp_csv")

    except Exception as err:
        print("Failed to unzip the file downloaded from MaxMind.  Check the file and MaxMind API key.")
        exit(1)

    return_data = []

    # Go through each "search" entry from the config.json
    for org, keywords in CONFIG_DATA['SEARCH_DATA'].items():

        # Create an placeholder for the org data
        org_data = {
            "name": org,
            "ranges": []
        }

        print("Getting IP ranges for {}...".format(org))

        # Iterate through each CSV file
        for file_name in file_list:

            print("Opening {}...".format(file_name))

            # Open the CSV file and parse it
            with open("temp_csv/" + file_name, "r", encoding="ISO-8859-1") as csvfile:

                # Set up the CSV Reader
                csv_reader = csv.reader(csvfile)

                # Iterate through each keyword specified for the Host Group
                for keyword in keywords:

                    # Reset back to the beginning of the CSV
                    csvfile.seek(0)

                    # Go through each row of the CSV
                    for row in csv_reader:

                        # Check to see if the keyword is an ASN number
                        if keyword.isnumeric():

                            # If the keyword is in the description, then add it to our array
                            if keyword == row[1]:

                                # Add the IP range to our array
                                org_data["ranges"].append(row[0])

                                # Print details about the find
                                print("Found IP range {} for {} with ASN '{}'".format(row[0], org, keyword))

                        else:

                            # If the keyword is in the description, then add it to our array
                            if keyword.lower() in row[2].lower():

                                # Add the IP range to our array
                                org_data["ranges"].append(row[0])

                                # Print details about the find
                                print("Found IP range {} for {} with keyword '{}' in '{}'".format(row[0], org, keyword, row[2]))
        
        # Append the org data to the return data
        return_data.append(org_data)

    # Clean up the extracted files
    shutil.rmtree("temp_csv")

    # Clean up the Zip file
    os.remove(ZIP_FILE_NAME)

    return return_data


def main():
    """This is a function to run the main logic of the MaxMind ASN Importer."""

    # Get the latest version of the feed from MaxMind
    current_version = get_current_version()

    # If the latest version is not equal to last imported version, then import the new stuff
    if current_version != CONFIG_DATA["LAST_VERSION_IMPORTED"]:

        # Instantiate a new StealthwatchClient
        stealthwatch = StealthwatchClient(validate_certs=False)

        # Login to Stealthwatch
        stealthwatch.login(CONFIG_DATA["SW_ADDRESS"], CONFIG_DATA["SW_USERNAME"], CONFIG_DATA["SW_PASSWORD"])

        # If a Domain ID wasn't specified, then get one
        if not CONFIG_DATA["SW_TENANT_ID"]:

            # Get Tenants from REST API, and save it
            CONFIG_DATA["SW_TENANT_ID"] = stealthwatch.get_tenants()
            save_config()

        else:

            # Set the Tenant ID
            stealthwatch.set_tenant_id(CONFIG_DATA["SW_TENANT_ID"])

        # If a parent Tag isn't specified, then create one
        if not CONFIG_DATA["SW_PARENT_TAG"]:

            # Create the Tag
            response = stealthwatch.create_tag(0, "MaxMind Data")

            # Save the parent Tag/Host Group ID
            CONFIG_DATA["SW_PARENT_TAG"] = response["data"][0]["id"]
            save_config()

        # Get the latest ASN data from MaxMind
        get_new_addresses()

        # Search through the latest MaxMind data
        current_asn_data = search_maxmind_data()

        print("Getting Tags from Stealthwatch...")

        # Get all of the Tags (Host Groups) from Stealthwatch
        current_tags = stealthwatch.get_tags()

        print("Uploading Tag data to Stealthwatch...")

        # Iterate through the returned MaxMind data
        for org in current_asn_data:

            # Make a Tag ID placeholder
            tag_id = 0

            # If the Tag name is found, update the tag_id placeholder
            for current_tag in current_tags["data"]:
                if current_tag["name"] == org["name"]:
                    
                    # Get the found Tag
                    response = stealthwatch.get_tag(current_tag["id"])

                    # Get the parent of the found tag
                    parent_tag = response["data"]["parentId"]

                    # If the parent is the one we want
                    if parent_tag is CONFIG_DATA["SW_PARENT_TAG"]:

                        # Use the tag ID to update
                        tag_id = current_tag["id"]
                        break

            if tag_id:

                print("Updating Tag ID {} for Org {}...".format(tag_id, org["name"]))

                # Update the Tag (Host Group) with the latest data
                stealthwatch.update_tag(CONFIG_DATA["SW_PARENT_TAG"], tag_id, org["name"], org["ranges"])
            else:

                print("Creating Tag for Org {}...".format(org["name"]))

                # Create a new Tag (Host Group) for the org
                stealthwatch.create_tag(CONFIG_DATA["SW_PARENT_TAG"], org["name"], org["ranges"])

        # Update the latest imported version
        CONFIG_DATA["LAST_VERSION_IMPORTED"] = current_version
        save_config()

        print("MaxMind addresses successfully imported.")

    else:
        print("Last imported data is up-to-date.")
        return


####################
# !!! DO WORK !!!  #
####################


if __name__ == "__main__":

    # Set up an argument parser
    parser = argparse.ArgumentParser(description="A script to import MaxMind ASN data into Stealthwatch")
    parser.add_argument("-d", "--daemon", help="Run the script as a daemon", action="store_true")
    args = parser.parse_args()

    # Load configuration data from file
    CONFIG_DATA = load_config()

    # If there's no MAXMIND_LICENSE_KEY, then notify the user and exit.
    if not CONFIG_DATA["MAXMIND_LICENSE_KEY"]:

        print("A license key from MaxMind is now required.  They're free, but please register on their site to generate one.")
        exit()

    # If not hard coded, get the SMC Address, Username and Password
    if not CONFIG_DATA["SW_ADDRESS"]:
        CONFIG_DATA["SW_ADDRESS"] = input("Stealthwatch IP/FQDN Address: ")
        save_config()
    if not CONFIG_DATA["SW_USERNAME"]:
        CONFIG_DATA["SW_USERNAME"] = input("Stealthwatch Username: ")
        save_config()
    if not CONFIG_DATA["SW_PASSWORD"]:
        CONFIG_DATA["SW_PASSWORD"] = getpass.getpass("Stealthwatch Password: ")
        save_config()

    if args.daemon:
        while True:
            main()
            print("Waiting {} seconds...".format(INTERVAL))
            time.sleep(INTERVAL)
    else:
        main()
