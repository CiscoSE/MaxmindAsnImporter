# Stealthwatch Enterprise: MaxMind ASN Importer

## Summary

This is a script to import MaxMind's ASN to IP range mappings into Tags (Host Groups) within Stealthwatch Enterprise.

This allows for more granular tuning and identification of network flows within Stealthwatch Enterprise.

You can find more information on Stealthwatch's APIs on [Cisco DevNet](https://developer.cisco.com/docs/stealthwatch/).

## Requirements

1. Python 3.x
2. Stealthwatch Enterprise 7.0 or higher
    - Updates files and documentation can be found in the Network Visibility and Segementation product category on [software.cisco.com](https://software.cisco.com/download/home/286307082)
3. Stealthwatch Enterprise user credentials with the "Master Admin" role assigned.
    - User roles are configured in the Stealthwatch web interface.  Simply navigate to *Global Settings -> User Management*.
4. A MaxMind API key.  Information on that below.

## Configuration File

The ***config.json*** file contains the following variables:

- LAST_VERSION_IMPORTED: The MD5 hash of the last imported dataset. (String)
- MAXMIND_LICENSE_KEY: The API key to be used when fetching data from MaxMind. (String)
- MAXMIND_VERSION_URL: The URL to get the MD5 of the dataset from MaxMind. (String)
- MAXMIND_DATASET_URL: The URL to get the ZIP file containing the dataset from MaxMind. (String)
- SEARCH_DATA: The Tag (Host Group) names, and search strings for each organization to be imported. (String)
- SW_ADDRESS: The IP or FQDN of the Stealthwatch SMC. (String)
- SW_USERNAME: The Username to be used to authenticate to Stealthwatch. (String)
- SW_PASSWORD: The Password to be used to authenticate to Stealthwatch. (String)
- SW_TENANT_ID: The Stealthwatch Tenant (Domain) ID to be used. (Integer)
- SW_PARENT_TAG: The parent Tag (Host Group) ID where each MaxMind organization will be imported. (Integer)

## How To Run

1. Prior to running the script for the first time, copy the ***config.example.json*** to ***config.json***.
    * ```cp config.example.json config.json```
    * **OPTIONAL:** You can manually enter configuration data in the ***config.json*** file if desired. By default, the script will assume it needs to create a parent Tag (Host Group) called "MaxMind Data" in the **Outside** host group. If you wish to use a different Tag (Host Group), create it in Stealthwatch, then add the ID number to ***config.json***.  Typically, you would import the data into the "Trusted Internet Hosts" group.
2. Install the required packages from the ***requirements.txt*** file.
    * If running locally, you'll probably want to set up a virtual environment: [Python 'venv' Tutorial](https://docs.python.org/3/tutorial/venv.html)
    * Activate the Python virtual environment, if you created one.
    * ```pip install -r requirements.txt```
3. Run the script with ```python maxmind_asn_importer.py```

> If you didn't manually enter configuration data, you'll get prompted for the Stealthwatch IP/FQDN, Username, and Password. The script will store these credentials in the ***config.json*** file for future use. **This means you'll want to make the ***config.json*** file read-only. You probably will also want to create unique credentials for scripting/API purposes.**

The script will automatically try to determine your Stealthwatch Tenant ID, and store that in the ***config.json*** file as well.

## MaxMind API Credentials

1. Log in to your MaxMind account, or create a new one using the following link: https://www.maxmind.com/en/geolite2/signup
2. Under Services -> My License Key, click the "Generate new license key" button.
3. Save the generated API key to the ***config.json*** file for use with this script.

## Docker Container

This script is Docker friendly, and can be deployed as a container.

To build the container, run the script once to populate the ***config.json*** file, or manually populate the configuration variables.

Once the ***config.json*** file is populated, run the following command to build the container:

- ```docker build -t maxmind-asn-importer .```

You can then run the container as a daemon with the following command:

- ```docker run -d --name maxmind-asn-importer maxmind-asn-importer```