#!/usr/bin/env python3

import dotenv
import json
import os
import requests
import sys

def identifyKnownCVEsForPackageVersion(packageName, packageVersion):
    print(f"Identifying known CVEs for package: {packageName} {packageVersion}")
    
    payload = {
        'version': packageVersion,
        'package': {
            'name': packageName,
            'ecosystem': 'Packagist'
        }
    }

    response = requests.post(
        'https://api.osv.dev/v1/query',
        json=payload,
    )
    data = response.json()

    print(json.dumps(data, indent=2))

def checkDotEnvFileExists():
    if not os.path.exists(".env"):
        errorMessage(".env file not found. Please create a .env file based on the .env.example file and add the required environment variables.")

def loadEnvironmentVariables():
    dotenv.load_dotenv()
    existingVars = ["GITHUB_TOKEN"]
    for var in existingVars:
        if var not in os.environ:
            errorMessage(f"{var} environment variable not set within .env file")

def errorMessage(message):
    print(f"\033[91m{message}\033[0m")
    sys.exit(1)

if __name__ == '__main__':
    checkDotEnvFileExists()
    loadEnvironmentVariables()

    print("SecAware - Currently Work in Progress")

    identifyKnownCVEsForPackageVersion("librenms/librenms", "25.12.0")
