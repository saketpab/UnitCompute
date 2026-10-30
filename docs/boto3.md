## Overview

This guide explains how to run Python scripts locally that use the `boto3` Python library.

## Prerequisites

- Install the AWS CLI
- Set up and activate the Python virtual environment using the `requirements.txt` file in the repository

## Instructions

1. Run `aws login --profile unicompute` in terminal
2. If prompoted, enter `us-east-2` for the region
3. The CLI will attempt to open your default browser to sign in to the AWS console
4. Sign in via the UniCompute Gmail (credentials in Google Drive). If needed, click the use the new AWS sign in experience to enable sign in via Google.
5. You should now be able to run any Python script that uses `boto3`. If you are developing your own script, ensure you use the following lines:
```python
session = boto3.Session(profile_name='unicompute', region_name='us-east-2')
client = session.client('...') # create your desired cloent
```