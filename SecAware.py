#!/usr/bin/env python3

import dotenv
import json
import os
import requests
import sys

class SoftwareCompositionAnalysis:
    packages: dict
    packageGraph: dict

    def __init__(self):
        self.packages = {}
        self.packageGraph = {}

    def generatePackageUrl(self, packageName, packageVersion):
        return f"pkg:packagist/{packageName}@{packageVersion}"

    def populateDataFromPackageLockFile(self, lockFilePath="composer.lock"):
        with open(lockFilePath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Combine all production and development dependencies into a single list
        allDependencies = data.get('packages', []) + data.get('packages-dev', [])
        
        # Require packages don't include the specific locked version, so we need a lookup
        nameAndVersion = {package['name']: package['version'] for package in allDependencies}

        for dependency in allDependencies:
            name = dependency['name']
            version = dependency['version']
            packageUrl = self.generatePackageUrl(name, version)

            # Add the package to the internal data structure
            self.packages[packageUrl] = {
                'name': name,
                'version': version,
                'ecosystem': 'Packagist',
                'vulnerabilities' : []
            }

            self.packageGraph[packageUrl] = []

            # Build the dependency graph
            coreRequirements = dependency.get('require', {})
            for coreName in coreRequirements:
                # Strip out any platform requirements (e.g. php, ext-*)
                if coreName.startswith("php") or coreName.startswith("ext-"):
                    continue
                
                # Find what version of this dependency is actually used in the lock file
                coreVersion = nameAndVersion.get(coreName)
                if coreVersion:
                    subDependencyPackageUrl = self.generatePackageUrl(coreName, coreVersion)
                    self.packageGraph[packageUrl].append(subDependencyPackageUrl)

        dumpJsonToFile("dependencies.json", self.packages)
        dumpJsonToFile("dependencyGraph.json", self.packageGraph)

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

    sca.populateDataFromPackageLockFile()
