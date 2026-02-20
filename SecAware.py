#!/usr/bin/env python3

import dotenv
import json
import os
import requests
import sys

class SoftwareCompositionAnalysis:
    packages: dict

    def __init__(self):
        self.packages = {}

    def getKnownCVEsForPackageVersion(self, packageName, packageVersion):
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

        dumpJsonToFile("apiResponse.json", data)

        # Format the response into something a bit more usable
        for vuln in data.get('vulns', []):
            if packageName not in self.packages:
                self.packages[packageName] = []
            
            self.packages[packageName].append({
                'id': vuln.get('id'),
                'aliases': vuln.get('aliases', []),
                'published': vuln.get('published'),
            })

    
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

def dumpJsonToFile(filename, data):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

if __name__ == '__main__':
    sca = SoftwareCompositionAnalysis()

    checkDotEnvFileExists()
    loadEnvironmentVariables()

    print("SecAware - Currently Work in Progress")

    sca.getKnownCVEsForPackageVersion("librenms/librenms", "26.0.0")

    print(json.dumps(sca.packages, indent=2))
