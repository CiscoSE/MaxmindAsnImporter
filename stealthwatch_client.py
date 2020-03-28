#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is an API client for Cisco Stealthwatch Enterprise.

stealthwatch_client.py
----------------
Author: Alan Nix
Property of: Cisco Systems
"""

import json

import requests

from requests.packages import urllib3

try:
    urllib3.disable_warnings()
except Exception as err:
    pass


class StealthwatchClient:
    """This is an API client for Cisco Stealthwatch Enterprise."""

    __session = None
    __smc_address = None
    __smc_username = None
    __smc_password = None
    __tenant_id = None
    __validate_certs = None
    __version = None

    __debug = False

    def __init__(self, debug=False, validate_certs=True, *args, **kwargs):
        """Initialize the Stealthwatch Client object."""

        if self.__session is not None:
            self.__session.close()
        self.__smc_address = None
        self.__smc_username = None
        self.__smc_password = None
        self.__tenant_id = None
        self.__validate_certs = validate_certs
        self.__version = None

        self.__debug = debug

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

        access_token = self.get_access_token()

        # Set the version
        self.__version = self.get_version()

        # Require version 6.9+
        if self.__version[0] <= 6 and self.__version[1] <= 8:
            print("Stealthwatch must be 6.9 or higher.")
            exit()

        return access_token

    def logout(self):
        """Log out of the Stealthwatch instance."""

        # Set up the Logout URL
        url = 'https://{}/token'.format(self.__smc_address)

        # Send a DELETE request to the SMC
        self.__session.delete(url, verify=self.__validate_certs)

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

        # Post authentication to Stealthwatch
        response = self._post_request(url, data=login_credentials)

        return response.text

    def get_tags(self):
        """Get all Tags (Host Groups) from Stealthwatch."""

        # Build the URL to create a Tag
        url = "https://{}/smc-configuration/rest/v1/tenants/{}/tags".format(self.__smc_address, self.__tenant_id)

        # Build the data to submit
        data = {
            "domainId": self.__tenant_id,
        }

        if self.__debug:
            print("Getting Stealthwatch Tags...")

        # Get Tag data from Stealthwatch
        response = self._get_request(url, json=data)

        return response.json()
    
    def get_tag(self, tag_id):
        """Get a Tag (Host Group) from Stealthwatch"""

        if self.__debug:
            print("Getting Stealthwatch Tag...")

        # Build the URL to create a Tag
        url = "https://{}/smc-configuration/rest/v1/tenants/{}/tags/{}".format(self.__smc_address, self.__tenant_id, tag_id)

        # Post Tag data to Stealthwatch
        response = self._get_request(url)

        return response.json()

    def create_tag(self, parent_tag_id, tag_name, ip_list=[], host_baselines=False,
                   suppress_excluded_services=True, inverse_suppression=False, host_trap=False, send_to_cta=False):
        """Create a new Tag (Host Group) in Stealthwatch."""

        if self.__debug:
            print("Creating Stealthwatch Tag...")

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

        # Post Tag data to Stealthwatch
        response = self._post_request(url, json=data)

        return response.json()

    def update_tag(self, parent_tag_id, tag_id, tag_name, ip_list=[], host_baselines=False,
                   suppress_excluded_services=True, inverse_suppression=False, host_trap=False, send_to_cta=False):
        """Update a Tag (Host Group) in Stealthwatch."""

        if self.__debug:
            print("Updating Stealthwatch Tag...")

        # Build the URL to update a Tag
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

        # Post Tag update to Stealthwatch
        response = self._put_request(url, json=data)

        return response.json()

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

        response = self._get_request(url)

        # Parse the response as JSON
        tenants = response.json()["data"]

        # Set the Domain ID if theres only one, or prompt the user if there are multiple
        if len(tenants) == 1:
            selected_tenant_id = tenants[0]["id"]
        else:
            selected_item = self.__selection_list("Tenants", "displayName", tenants)
            selected_tenant_id = selected_item["id"]

        self.set_tenant_id(selected_tenant_id)

        return selected_tenant_id

    def get_version(self):
        """Gets the version of the Stealthwatch instance."""

        # Set up a version list
        version = []

        response = self._get_request("https://{}/cm/monitor/appliances/status".format(self.__smc_address))

        try:
            # Iterate through all the appliances
            for appliance in response.json():

                # If we found the referenced SMC
                if appliance["applianceType"] == "SMC":

                    # Split the version string
                    version_str = appliance["version"].split(".")

                    # Convert strings to integers
                    for i in version_str:
                        version.append(int(i))

                    return version

        except Exception as err:
            print("Unable to get Appliance Status from the SMC, falling back to login page parsing...\nError: {}".format(err))

        # The following block of code is just a fall-back for older versions of Stealthwatch

        # Get the Stealthwatch login page
        response = self._get_request("https://{}/smc/login.html".format(self.__smc_address))

        try:
            # Parse the version number out of the response
            version_str = str(response.text.split('<div id="loginMessage">')[1]
                              .replace('<br />', '<br/>')
                              .replace('<br>', '<br/>')
                              .split('<br/>')[1]
                              .split('</div>')[0]
                              .replace("\n", "")
                              .replace("\r", "")
                              .strip()).split('.')

            # Append all version numbers to the version list as integers
            for i in version_str:
                version.append(int(i))

            return version

        except Exception as err:
            # Exit if we weren't able to parse the response
            print("Unable to parse response from Stealthwatch.")
            exit()

    def _get_request(self, url, json=None):
        """Performs an HTTP GET request."""

        if self.__debug:
            print("Get URL: {}".format(url))

        try:
            # Make a GET request to the SMC
            if json:
                response = self.__session.get(url, json=json, verify=self.__validate_certs)
            else:
                response = self.__session.get(url, verify=self.__validate_certs)

            # If the request was successful, then proceed
            if response.status_code >= 200 and response.status_code < 300:
                if self.__debug:
                    print("Stealthwatch Returned Response: {}\n".format(response.text))

                return response

            else:
                print("SMC Connection Failure!\nHTTP Return Code: {}\nResponse: {}".format(response.status_code, response.text))
                exit()

        except Exception as err:
            print("Unable to GET from the SMC!\nError: {}".format(err))
            exit()

    def _post_request(self, url, data=None, json=None):
        """Performs an HTTP POST request."""

        if self.__debug:
            print("Post URL: {}".format(url))

        try:
            # Make a POST request to the SMC
            if data:
                response = self.__session.post(url, data=data, verify=self.__validate_certs)
            elif json:
                response = self.__session.post(url, json=json, verify=self.__validate_certs)
            else:
                response = self.__session.post(url, verify=self.__validate_certs)

            # If the request was successful, then proceed
            if response.status_code >= 200 and response.status_code < 300:
                if self.__debug:
                    print("Stealthwatch Returned Response: {}\n".format(response.text))

                return response

            else:
                print("SMC Connection Failure!\nHTTP Return Code: {}\nResponse: {}".format(response.status_code, response.text))
                exit()

        except Exception as err:
            print("Unable to POST from the SMC!\nError: {}".format(err))
            exit()

    def _put_request(self, url, data=None, json=None):
        """Performs an HTTP POST request."""

        if self.__debug:
            print("Put URL: {}".format(url))

        try:
            # Make a PUT request to the SMC
            if data:
                response = self.__session.put(url, data=data, verify=self.__validate_certs)
            elif json:
                response = self.__session.put(url, json=json, verify=self.__validate_certs)
            else:
                response = self.__session.put(url, verify=self.__validate_certs)

            # If the request was successful, then proceed
            if response.status_code >= 200 and response.status_code < 300:
                if self.__debug:
                    print("Stealthwatch Returned Response: {}\n".format(response.text))

                return response

            else:
                print("SMC Connection Failure!\nHTTP Return Code: {}\nResponse: {}".format(response.status_code, response.text))
                exit()

        except Exception as err:
            print("Unable to POST from the SMC!\nError: {}".format(err))
            exit()

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
