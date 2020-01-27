#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# stealthwatch_client.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 10/20/2019
#
############################################################

import json

import requests

from requests.packages import urllib3

class StealthwatchClient:
    """A class to allow easy interaction with Stealthwatch."""

    __debug = False
    __session = None
    __smc_address = None
    __smc_username = None
    __smc_password = None
    __tenant_id = None
    __version = None

    def __init__(self, debug=False, *args, **kwargs):
        """Initialize the Stealthwatch Client object."""

        self.__debug = debug
        if self.__session is not None:
            self.__session.close()
        self.__smc_address = None
        self.__smc_username = None
        self.__smc_password = None
        self.__tenant_id = None
        self.__version = None

    def login(self, smc_address, smc_username, smc_password):
        """Log in to the Stealthwatch instance."""

        # Set the Stealthwatch credentials
        self.__smc_address = smc_address
        self.__smc_username = smc_username
        self.__smc_password = smc_password

        # Reset the session
        if self.__session is not None:
            self.__session.close()
        self.__session = requests.Session()

        # Set the version
        self.__version = self.get_version()

        # Require version 6.9+
        if self.__version[0] <= 6 and self.__version[1] <= 8:
            print("Stealthwatch must be 6.9 or higher.")
            exit()

        access_token = self.get_access_token()

        return access_token

    def logout(self):
        """Log out of the Stealthwatch instance."""

        # Set up the Logout URL
        url = 'https://{}/token'.format(self.__smc_address)

        # Send a DELETE request to the SMC
        self.__session.delete(url, verify=False)

        # End the requests session
        if self.__session is not None:
            self.__session.close()
        self.__session = None

    def get_access_token(self):
        """Get an Access Token from the Stealthwatch API."""

        if self.__debug:
            print("Authenticating to Stealthwatch...")

        # The URL to authenticate to the SMC
        url = "https://{}/token/v2/authenticate".format(self.__smc_address)

        # JSON to hold the authentication credentials
        login_credentials = {
            "username": self.__smc_username,
            "password": self.__smc_password
        }

        if self.__debug:
            print("Stealthwatch Authentication URL: {}".format(url))

        try:
            # Make an authentication request to the SMC
            response = self.__session.post(url, data=login_credentials, verify=False)

            # If the request was successful, then proceed
            if response.status_code == 200:
                if self.__debug:
                    print("Successfully Authenticated.")

                return response.text

            else:
                print("SMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(response.status_code, response.text))
                exit()

        except Exception as err:
            print("Unable to post to the SMC - Error: {}".format(err))
            exit()

    def get_tags(self):
        """Get all Tags (Host Groups) from Stealthwatch."""

        # Build the URL to create a Tag
        url = "https://{}/smc-configuration/rest/v1/tenants/{}/tags".format(self.__smc_address, self.__tenant_id)

        # Build the data to submit
        data = {
            "domainId": self.__tenant_id,
        }

        try:
            if self.__debug:
                print("Getting Stealthwatch Tags...")

            # Send the create request
            response = self.__session.get(url, json=data, verify=False)

            # If the request was successful, then proceed, otherwise terminate.
            if response.status_code == 200:
                if self.__debug:
                    print("Tag Request Successful.")

                # Parse the response as JSON
                tag_data = response.json()

                # Return the Tag ID
                return tag_data

            else:
                print("SMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(response.status_code, response.text))
                exit()

        except Exception as err:
            print("Unable to get from the SMC - Error: {}".format(err))
            exit()

    def create_tag(self, parent_tag_id, tag_name, ip_list=[], host_baselines=False,
                   suppress_excluded_services=True, inverse_suppression=False, host_trap=False, send_to_cta=False):
        """Create a new Tag (Host Group) in Stealthwatch."""

        # Build the URL to create a Tag
        url = "https://{}/smc-configuration/rest/v1/tenants/{}/tags/".format(self.__smc_address, self.__tenant_id)

        data = [{
            "name": tag_name,
            "ranges": ip_list,
            "hostBaselines": host_baselines,
            "suppressExcludedServices": suppress_excluded_services,
            "inverseSuppression": inverse_suppression,
            "hostTrap": host_trap,
            "sendToCta": send_to_cta,
            "domainId": self.__tenant_id,
            "parentId": parent_tag_id
        }]

        try:
            if self.__debug:
                print("Creating Stealthwatch Tag...")

            # Send the create request
            response = self.__session.post(url, json=data, verify=False)

            # If the request was successful, then proceed, otherwise terminate.
            if response.status_code == 200:
                if self.__debug:
                    print("Tag Request Successful.")

                # Parse the response as JSON
                tag_id = response.json()["data"][0]["id"]

                # Return the Tag ID
                return tag_id

            else:
                print("SMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(response.status_code, response.text))
                exit()

        except Exception as err:
            print("Unable to post to the SMC - Error: {}".format(err))
            exit()

    def update_tag(self, parent_tag_id, tag_id, tag_name, ip_list=[], host_baselines=False,
                   suppress_excluded_services=True, inverse_suppression=False, host_trap=False, send_to_cta=False):
        """Update a Tag (Host Group) in Stealthwatch."""

        # Build the URL to create a Tag
        url = "https://{}/smc-configuration/rest/v1/tenants/{}/tags/".format(self.__smc_address, self.__tenant_id)

        data = [{
            "id": tag_id,
            "name": tag_name,
            "ranges": ip_list,
            "hostBaselines": host_baselines,
            "suppressExcludedServices": suppress_excluded_services,
            "inverseSuppression": inverse_suppression,
            "hostTrap": host_trap,
            "sendToCta": send_to_cta,
            "domainId": self.__tenant_id,
            "parentId": parent_tag_id
        }]

        try:
            if self.__debug:
                print("Updating Stealthwatch Tag...")

            # Send the update request
            response = self.__session.put(url, json=data, verify=False)

            # If the request was successful, then proceed, otherwise terminate.
            if response.status_code == 200:
                if self.__debug:
                    print("Tag Request Successful.")

                # Parse the response as JSON
                tag_id = response.json()["data"][0]["id"]

                # Return the Tag ID
                return tag_id

            else:
                print("SMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(response.status_code, response.text))
                exit()

        except Exception as err:
            print("Unable to post to the SMC - Error: {}".format(err))
            exit()

    def get_tenant_id(self):
        """Gets the current Tenant ID being used by the object."""
        return self.__tenant_id

    def set_tenant_id(self, tenant_id):
        """Sets the current Tenant ID being used by the object."""
        self.__tenant_id = tenant_id

    def get_tenants(self):
        """Get the "tenants" (domains) from Stealthwatch"""

        if self.__debug:
            print("Fetching Stealthwatch Tenants...")

        # The URL to get tenants
        url = "https://{}/sw-reporting/v1/tenants/".format(self.__smc_address)

        if self.__debug:
            print("Stealthwatch Tenant URL: {}".format(url))

        try:
            # Get the tenants from Stealthwatch
            response = self.__session.get(url, verify=False)

            # If the request was successful, then proceed, otherwise terminate.
            if response.status_code == 200:

                # Parse the response as JSON
                tenants = response.json()["data"]

                # Set the Domain ID if theres only one, or prompt the user if there are multiple
                if len(tenants) == 1:
                    selected_tenant_id = tenants[0]["id"]
                else:
                    selected_item = self.__selection_list("Tenants", "displayName", tenants)
                    selected_tenant_id = selected_item["id"]

                self.__tenant_id = selected_tenant_id

                return selected_tenant_id

            else:
                print("SMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(response.status_code, response.text))
                exit()

        except Exception as err:
            print("Unable to post to the SMC - Error: {}".format(err))
            exit()

    def get_version(self):
        """Gets the version of the Stealthwatch instance."""

        # Set up a version list
        version = []

        # Get the Stealthwatch login page
        response = self.__session.get("https://{}/smc/login.html".format(self.__smc_address), verify=False)

        # Parse the version number out of the response
        version_str = str(response.text.split('<div id="loginMessage">')[1]
                          .replace('<br />', '<br/>')
                          .replace('<br>', '<br/>')
                          .split('<br/>')[1]
                          .split('</div>')[0]
                          .replace("\n", "")
                          .replace("\r", "")
                          .strip()).split('.')

        # Append all version numbers to the version list
        for i in version_str:
            version.append(int(i))

        return version

    def __selection_list(self, item_name, item_name_key, item_dict):
        """This is a function to allow users to select an item from a dict."""

        print("\nPlease select one of the following {}s:\n".format(item_name))

        index = 1

        # Print the options that are available
        for item in item_dict:
            print("{}) {}".format(index, item[item_name_key]))
            index += 1

        # Prompt the user for the item
        selected_item = input("\n{} Selection: ".format(item_name))

        # Make sure that the selected item was valid
        if 0 < int(selected_item) <= len(item_dict):
            selected_item = int(selected_item) - 1
        else:
            print("ERROR: {} selection was not correct.".format(item_name))
            exit()

        return item_dict[selected_item]
