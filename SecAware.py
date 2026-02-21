#!/usr/bin/env python3

import dotenv
import json
import os
import requests
import sys

class SoftwareCompositionAnalysis:
    dependencies: dict
    dependencyGraph: dict
    rawLockData: dict
    rawManifestData: dict
    versionLookup: dict

    def __init__(self):
        self.dependencies = {}
        self.dependencyGraph = {}
        self.rawLockData = {}
        self.rawManifestData = {}
        self.versionLookup = {}

        self.ingestPackageManifests()
        self.buildInventory()
        self.buildAdjacencyList()

    def generatePackageUrl(self, packageName, packageVersion):
        return f"pkg:packagist/{packageName}@{packageVersion}"
    
    def ingestPackageManifests(self, manifestPath = "test-data/composer.json", lockfilePath = "test-data/composer.lock", ):
        with open(manifestPath, 'r', encoding='utf-8') as f:
            self.rawManifestData = json.load(f)
        with open(lockfilePath, 'r', encoding='utf-8') as f:
            self.rawLockData = json.load(f)

        packages = self.rawLockData.get('packages', []) + self.rawLockData.get('packages-dev', [])
        self.versionLookup = {package['name']: package['version'] for package in packages}

    def buildInventory(self):
        allPackages = self.rawLockData.get('packages', []) + self.rawLockData.get('packages-dev', [])
        for package in allPackages:
            packageUrl = self.generatePackageUrl(package['name'], package['version'])
            self.dependencies[packageUrl] = {
                'name': package['name'],
                'version': package['version'],
                'ecosystem': 'Packagist',
                'vulnerabilities': []
            }

    def buildAdjacencyList(self):
        allPackages = self.rawLockData.get('packages', []) + self.rawLockData.get('packages-dev', [])
        for package in allPackages:
            parentPackageUrl = self.generatePackageUrl(package['name'], package['version'])
            self.dependencyGraph[parentPackageUrl] = []

            requirements = package.get('require', {})
            for requirement in requirements:
                if requirement == 'php' or requirement.startswith('ext-'): continue

                requirementVersion = self.versionLookup.get(requirement)
                if requirementVersion:
                    childRequirementPackageUrl = self.generatePackageUrl(requirement, requirementVersion)
                    self.dependencyGraph[parentPackageUrl].append(childRequirementPackageUrl)

    def getNestedDependencies(self):
        results = {
            "production": {},
            "development": {}
        }

        productionRootDependencies = self.rawManifestData.get('require', {})
        developmentRootDependencies = self.rawManifestData.get('require-dev', {})

        for dependencyType in results.keys():
            rootDependencies = productionRootDependencies if dependencyType == "production" else developmentRootDependencies
            for dependency in rootDependencies:
                if dependency.startswith(('php', 'ext-')): continue
                version = self.versionLookup.get(dependency)
                if version:
                    packageUrl = self.generatePackageUrl(dependency, version)
                    results[dependencyType][packageUrl] = self.getAllNestedDependenciesForPackage(packageUrl)
        
        return results
    
    def getAllNestedDependenciesForPackage(self, packageUrl, visited=None):
        if visited is None:
            visited = set()

        packageInfo = self.dependencies.get(packageUrl, {})

        node = {
            'name': packageInfo.get('name'),
            'version': packageInfo.get('version'),
            'dependencies': {}
        }

        if packageUrl in visited:
            node["note"] = "Circular reference detected"
            return node

        visited.add(packageUrl)

        # Recursively add child dependencies
        childPackageUrl = self.dependencyGraph.get(packageUrl, [])
        for childUrl in childPackageUrl:
            childNode = self.getAllNestedDependenciesForPackage(childUrl, visited.copy())
            if childUrl not in node['dependencies']:
                node['dependencies'][childUrl] = []
            node['dependencies'][childUrl].append(childNode)

        return node
    
    def getKnownCVEsForAllPackages(self):
        # Capture the keys in a list to maintain the original order
        dependencies = list(self.dependencies.keys())
        
        payload = {'queries': []}

        for dep in dependencies:
            data = self.dependencies[dep]
            payload['queries'].append({
                'version': data['version'],
                'package': {
                    'name': data['name'],
                    'ecosystem': 'Packagist',
                }
            }) 

        payload['queries'].append({
            'version': 'v11.9.0',
            'package': {
                'name': 'laravel/framework',
                'ecosystem': 'Packagist',
            }
        })
        
        response = requests.post(
            'https://api.osv.dev/v1/querybatch',
            json=payload,
        )
        data = response.json()

        if 'results' in data:
            for dep, result in zip(dependencies, data['results']):
                vulns = result.get('vulns', [])

                for vuln in vulns:
                    self.dependencies[dep]['vulnerabilities'].append({
                        'id': vuln.get('id')
                    })

        dumpJsonToFile("debug/apiRequest.json", payload)
        dumpJsonToFile("debug/apiResponse.json", data)

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

        dumpJsonToFile("debug/apiResponse.json", data)

        # Format the response into something a bit more usable
        for vuln in data.get('vulns', []):
            if packageName not in self.dependencies:
                self.dependencies[packageName] = []
            
            self.dependencies[packageName].append({
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
    checkDotEnvFileExists()
    loadEnvironmentVariables()

    print("SecAware - Currently Work in Progress")

    sca = SoftwareCompositionAnalysis()
    sca.getKnownCVEsForAllPackages()

    dumpJsonToFile("debug/dependencies.json", sca.dependencies)
    dumpJsonToFile("debug/dependencyGraph.json", sca.dependencyGraph)
    dumpJsonToFile("debug/dependencyNesting.json", sca.getNestedDependencies())
