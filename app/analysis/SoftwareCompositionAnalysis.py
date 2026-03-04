#!/usr/bin/env python3

import json
import os
import requests
import semantic_version

from app.utils.ConsoleColour import ConsoleColour

class SoftwareCompositionAnalysis:
    dependencies: dict
    dependencyGraph: dict
    directoryPath: str
    isSimulatedLockData: bool
    rawLockData: dict
    rawManifestData: dict
    versionLookup: dict

    def __init__(self, directoryPath=None):
        self.dependencies = {}
        self.dependencyGraph = {}
        self.directoryPath = directoryPath
        self.isSimulatedLockData = False
        self.rawLockData = {}
        self.rawManifestData = {}
        self.versionLookup = {}

        if self.directoryPath:
            self.ingestPackageManifests()
            if self.isSimulatedLockData:
                print(ConsoleColour.toYellow("Warning: No lock file found. Simulated lock data generated from manifest, but this may be inaccurate."))
            self.buildInventory()
            self.buildAdjacencyList()

            self.getAllPossibleVersionsForSimulatedData()

            self.getKnownCVEsForAllPackages()
            self.getMoreDetailsForAllKnownCVEs()
        else:
            raise SCAMissingDirectoryError("No directory path provided for Software Composition Analysis.")

    def generatePackageUrl(self, packageName, packageVersion):
        return f"pkg:packagist/{packageName}@{packageVersion}"
    
    def ingestPackageManifests(self):
        manifestPath = os.path.join(self.directoryPath, "composer.json")
        lockfilePath = os.path.join(self.directoryPath, "composer.lock")

        # At least a composer.json file is required to perform SCA
        if not os.path.exists(manifestPath):
            raise SCAMissingDependencyFilesError(f"Missing composer.json in directory {self.directoryPath}. Required to perform Software Composition Analysis.")

        with open(manifestPath, 'r', encoding='utf-8') as f:
            self.rawManifestData = json.load(f)

        # If we also have the lock file, we can perform more accurate analysis with exact versions
        if os.path.exists(lockfilePath):
            with open(lockfilePath, 'r', encoding='utf-8') as f:
                self.rawLockData = json.load(f)
        
            packages = self.rawLockData.get('packages', []) + self.rawLockData.get('packages-dev', [])
            self.versionLookup = {package['name']: package['version'] for package in packages}
        else:
            # We don't have a lock file, so we can simulate one from the manifest, but this is less accurate
            self.generateSimulatedLockData()

    def generateSimulatedLockData(self):
        self.isSimulatedLockData = True
        mockPackages = []
        allDependencies = {**self.rawManifestData.get('require', {}), **self.rawManifestData.get('require-dev', {})}

        for packageName, versionConstraint in allDependencies.items():
            if packageName.startswith(('php', 'ext-')): continue

            mockPackages.append({
                'name': packageName,
                'version': versionConstraint,
                # We don't have exact dependencies without the lock file, so we just leave this empty
                'require': {}
            })
        
        self.rawLockData = {
            'packages': mockPackages,
            'packages-dev': []
        }
        self.versionLookup = {package['name']: package['version'] for package in mockPackages}

    def buildInventory(self):
        allPackages = self.rawLockData.get('packages', []) + self.rawLockData.get('packages-dev', [])
        for package in allPackages:
            packageUrl = self.generatePackageUrl(package['name'], package['version'])
            self.dependencies[packageUrl] = {
                'name': package['name'],
                'version': package['version'],
                'ecosystem': 'Packagist',
                'vulnerabilities': {}
            }

            if self.isSimulatedLockData:
                self.dependencies[packageUrl]['possibleVersions'] = []

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

        # If not simulated data, we can just query the exact version for each dependency
        if not self.isSimulatedLockData:
            payload = {'queries': []}

            for dep in dependencies:
                data = self.dependencies[dep]
                query = {
                    'package': {
                        'name': data['name'],
                        'ecosystem': 'Packagist',
                        'version': data['version']
                    }
                }

                payload['queries'].append(query)
        
            response = requests.post(
                'https://api.osv.dev/v1/querybatch',
                json=payload,
            )
            data = response.json()

            if 'results' in data:
                for dep, result in zip(dependencies, data['results']):
                    vulns = result.get('vulns', [])

                    for vuln in vulns:
                        self.dependencies[dep]['vulnerabilities'][vuln.get('id')] = {
                            'id': vuln.get('id')
                        }
        else:
            # We are using simulated data, so need to get vulnerabilities for each possible version of each dependency
            for dep in dependencies:
                payload = {'queries': []}

                for version in self.dependencies[dep].get('possibleVersions', []):
                    data = self.dependencies[dep]
                    query = {
                        'package': {
                            'name': data['name'],
                            'ecosystem': 'Packagist',
                            'version': version
                        }
                    }
                    payload['queries'].append(query)
                response = requests.post(
                    'https://api.osv.dev/v1/querybatch',
                    json=payload,
                )
                data = response.json()
                if 'results' in data:
                    for result in data['results']:
                        vulns = result.get('vulns', [])
                        for vuln in vulns:
                            # Only populate the vulnerability if it's not already captured - prevents duplicates across versions
                            if vuln.get('id') not in self.dependencies[dep]['vulnerabilities']:
                                self.dependencies[dep]['vulnerabilities'][vuln.get('id')] = {
                                    'id': vuln.get('id')
                                }

    def getMoreDetailsForAllKnownCVEs(self):
        # The /querybatch endpoint doesn't return all details, so we make individual requests for each CVE
        for dep in self.dependencies.keys():
            if len(self.dependencies[dep]['vulnerabilities']) == 0: continue

            for vuln in self.dependencies[dep]['vulnerabilities'].keys():
                print(f"Fetching details for {vuln}...")
                response = requests.get(
                    f"https://api.osv.dev/v1/vulns/{vuln}"
                )
                data = response.json()

                # Different severity types are returned in an array
                severityMapFromResponse = {item['type']: item['score'] for item in data.get('severity', [])}

                existingData = self.dependencies[dep]['vulnerabilities'].get(vuln, {})
                additionalData = {
                    'summary': data.get('summary'),
                    'aliases': data.get('aliases', []),
                    'cwe_ids': data.get('database_specific', {}).get('cwe_ids', []),
                    'severity': {
                        'OSV': data.get('database_specific', {}).get('severity', []),
                        'CVSS_V3': severityMapFromResponse.get('CVSS_V3'),
                        'CVSS_V4': severityMapFromResponse.get('CVSS_V4'),
                    },
                    'published': data.get('published'),
                }

                mergedData = {**existingData, **additionalData}
                self.dependencies[dep]['vulnerabilities'][vuln] = mergedData

    def getAllPossibleVersionsForSimulatedData(self):
        if not self.isSimulatedLockData:
            return
        
        # Get all versions for each package from Packagist API
        for dep in self.dependencies.keys():
            dependency = self.dependencies[dep]

            # https://packagist.org/apidoc
            response = requests.get(f"https://repo.packagist.org/p2/{dependency['name']}.json")
            
            json = response.json()
            allVersions = []

            for data in json.get('packages', {}).get(dependency['name'], []):
                version = data.get('version')
                if version:
                    allVersions.append(version)

            self.dependencies[dep]['possibleVersions'] = self.filterVersionsByConstraint(allVersions, dependency['version'])

    def filterVersionsByConstraint(self, allVersions, constraint):
        normalisedConstraint = constraint.lstrip('vV')
        
        try:
            spec = semantic_version.NpmSpec(normalisedConstraint)
        except ValueError:
            print(ConsoleColour.toYellow(f"Warning: Unable to parse version constraint '{constraint}'. Using all versions."))
            return allVersions
        
        compatibleVersions = []

        for version in allVersions:
            try:
                cleanVersion = version.lstrip('vV')

                # Coerce version to ensure standard format
                coercedVersion = semantic_version.Version.coerce(cleanVersion)
                if coercedVersion in spec:
                    compatibleVersions.append(version)
            except ValueError:
                print(ConsoleColour.toYellow(f"Warning: Unable to parse version '{version}' for package with constraint '{constraint}'. Skipping this version."))
                continue

        return compatibleVersions

class SCAMissingDependencyFilesError(Exception):
    pass

class SCAMissingDirectoryError(Exception):
    pass