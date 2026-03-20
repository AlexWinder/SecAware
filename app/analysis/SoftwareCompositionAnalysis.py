#!/usr/bin/env python3

import cvss
import datetime
import dns.resolver
import json
import os
import pathlib
import requests
import semantic_version

from app.utils.ConsoleColour import ConsoleColour
from app.utils.GitHelper import GitHelper

class SoftwareCompositionAnalysis:
    cacheDirectoryPath: str
    dependencies: dict
    dependencyGraph: dict
    gitProjectDirectoryPath: str
    isSimulatedLockData: bool
    rawLockData: dict
    rawManifestData: dict
    reportContents: list
    userDefinedThresholds: dict
    versionLookup: dict

    def __init__(
            self, logger, cacheDirectoryPath, gitProjectDirectoryPath=None, allowedSPDXLicenses=[], overallCommitMinimumActivityDays=None,
            authorCommitMinimumActivityDays=None, openToClosedIssueRatioThreshold=None, minimumVersionAge=None
        ):
        self.cacheDirectoryPath = cacheDirectoryPath
        self.dependencies = {}
        self.dependencyGraph = {}
        self.gitProjectDirectoryPath = gitProjectDirectoryPath
        self.isSimulatedLockData = False
        self.logger = logger
        self.rawLockData = {}
        self.rawManifestData = {}
        self.reportContents = []
        self.userDefinedThresholds = {
            'allowedSPDXLicenses': allowedSPDXLicenses,
            'overallCommitMinimumActivityDays': overallCommitMinimumActivityDays or 1,
            'authorCommitMinimumActivityDays': authorCommitMinimumActivityDays or 1,
            'openToClosedIssueRatioThreshold': openToClosedIssueRatioThreshold or 0.01,
            'minimumVersionAge': minimumVersionAge or 3650
        }
        self.versionLookup = {}

        if self.gitProjectDirectoryPath:
            self.ingestPackageManifests()
            if self.isSimulatedLockData:
                self.logger.warning(ConsoleColour.toYellow("Warning: No lock file found. Simulated lock data generated from manifest, but this may be inaccurate."))
            self.buildInventory()
            self.buildAdjacencyList()

            self.getAllPossibleVersionsForSimulatedData()

            self.getMetadataForAllDependencies()
            self.createCachedCopyOfDependencyData()

            self.parseMetadataFromComposerManifestFile()
            self.scanMetadataForWeakLinksForAllDependencies()
            self.retrieveRepositoryStatisticsForAllDependencies()
            self.identifyWeakLinksFromSpecifiedFlags()
            self.identifyPassiveWeakLinks()

            self.getKnownCVEsForAllDependencies()
            self.getMoreDetailsForAllKnownCVEs()

            self.buildMarkdownReport()

        else:
            raise SCAMissingDirectoryError("No directory path provided for Software Composition Analysis.")

    def identifyWeakLinksFromSpecifiedFlags(self):
        for dep in self.dependencies.keys():
            dependency = self.dependencies[dep]
            
            # Flag if the license doesn't match the allowed SPDX licenses
            dependencyLicenses = dependency.get('metadata', {}).get('licenses', [])
            for license in dependencyLicenses:
                if license not in self.userDefinedThresholds['allowedSPDXLicenses']:
                    self.dependencies[dep].setdefault('weakLinks', []).append({
                        'field': 'licenses', 
                        'value': license,
                        'message': f"License '{license}' for dependency '{dependency['name']}' is not in SPDX license allow list."
                    })

            # Flag if overall commit activity is below threshold
            latestCommitDate = dependency.get('metadata', {}).get('repositoryStatistics', {}).get('overallRepositoryMostRecentCommitDate')
            if latestCommitDate:
                latestCommitDateTime = datetime.datetime.fromisoformat(latestCommitDate.replace("Z", "+00:00"))
                daysSinceLatestCommit = (datetime.datetime.now(datetime.timezone.utc) - latestCommitDateTime).days

                if daysSinceLatestCommit > self.userDefinedThresholds['overallCommitMinimumActivityDays']:
                    self.dependencies[dep].setdefault('weakLinks', []).append({
                        'field': 'repositoryStatistics.overallRepositoryMostRecentCommitDate', 
                        'value': latestCommitDate,
                        'message': f"Latest commit for dependency '{dependency['name']}' was {daysSinceLatestCommit} days ago, which is beyond the threshold of {self.userDefinedThresholds['overallCommitMinimumActivityDays']} days."
                    })

            # Flag if maintainer commit activity is below threshold
            # We don't care about each individual author, we just want to make sure at least one of them is active
            # Also, no data suggests that the author activity couldn't be found, so we want to consider that as being inactive
            authorCommitDates = dependency.get('metadata', {}).get('repositoryStatistics', {}).get('authorMostRecentCommitDate', {})
            mostRecentCommitDate = None
            for author, commitDate in authorCommitDates.items():
                # If we have a commit date to work with
                if commitDate:
                    commitDateTime = datetime.datetime.fromisoformat(commitDate.replace("Z", "+00:00"))
                    # Check if this is the most recent commit we've seen so far
                    if mostRecentCommitDate is None or commitDateTime > mostRecentCommitDate:
                        mostRecentCommitDate = commitDateTime
                else:
                    # An author has no commit data, so we treat them as inactive
                    mostRecentCommitDate = None
            if not mostRecentCommitDate:
                self.dependencies[dep].setdefault('weakLinks', []).append({
                    'field': 'repositoryStatistics.authorMostRecentCommitDate', 
                    'value': authorCommitDates,
                    'message': f"No recent commit activity found for any authors of dependency '{dependency['name']}'. This could indicate an unmaintained package."
                })
            else:
                daysSinceMostRecent = (datetime.datetime.now(datetime.timezone.utc) - mostRecentCommitDate).days
                if daysSinceMostRecent > self.userDefinedThresholds['authorCommitMinimumActivityDays']:
                    self.dependencies[dep].setdefault('weakLinks', []).append({
                        'field': 'repositoryStatistics.authorMostRecentCommitDate', 
                        'value': authorCommitDates,
                        'message': f"Most recent commit by an author for dependency '{dependency['name']}' was {daysSinceMostRecent} days ago, which is beyond the threshold of {self.userDefinedThresholds['authorCommitMinimumActivityDays']} days. This could indicate an unmaintained package."
                    })

            openIssues = dependency.get('metadata', {}).get('repositoryStatistics', {}).get('totalOpenIssues', 0)
            closedIssues = dependency.get('metadata', {}).get('repositoryStatistics', {}).get('totalClosedIssues', 0)

            if openIssues > 0 and closedIssues > 0:
                openToClosedRatio = openIssues / closedIssues
                if openToClosedRatio > self.userDefinedThresholds['openToClosedIssueRatioThreshold']:
                    self.dependencies[dep].setdefault('weakLinks', []).append({
                        'field': 'repositoryStatistics.openToClosedIssueRatio', 
                        'value': openToClosedRatio,
                        'message': f"Open to closed issue ratio for dependency '{dependency['name']}' is {openToClosedRatio:.2f}, which is above the threshold of {self.userDefinedThresholds['openToClosedIssueRatioThreshold']:.2f}. Open issues: {openIssues}. Closed issues: {closedIssues}. This could indicate an unmaintained package or one with a high number of unresolved issues."
                    })

            # Check that a version being used isn't too new
            usedVersionTimestamp = dependency.get('metadata', {}).get('usedVersion', {}).get('releaseTimestamp')
            usedVersionString = dependency.get('metadata', {}).get('usedVersion', {}).get('version')
            if usedVersionTimestamp:
                usedVersionDateTime = datetime.datetime.fromisoformat(usedVersionTimestamp.replace("Z", "+00:00"))
                versionAgeInDays = (datetime.datetime.now(datetime.timezone.utc) - usedVersionDateTime).days

                if versionAgeInDays < self.userDefinedThresholds['minimumVersionAge']:
                    self.dependencies[dep].setdefault('weakLinks', []).append({
                        'field': 'metadata.usedVersion.releaseTimestamp', 
                        'value': usedVersionTimestamp,
                        'message': f"Used version '{usedVersionString}' for dependency '{dependency['name']}' was released {versionAgeInDays} days ago, which is below the minimum version age threshold of {self.userDefinedThresholds['minimumVersionAge']} days. Using very new versions can be risky as they may be prone to hijack."
                    })
    
    def identifyPassiveWeakLinks(self):
        for dep in self.dependencies.keys():
            dependency = self.dependencies[dep]

            # If a dependency has no source URL, we want to flag it
            gitSourceUrl = dependency.get('metadata', {}).get('gitSource', {}).get('url')
            if not gitSourceUrl:
                self.dependencies[dep].setdefault('weakLinks', []).append({
                    'field': 'metadata.gitSource.url', 
                    'value': gitSourceUrl,
                    'message': f"No source URL found for dependency '{dependency['name']}'. This could make it difficult to verify the legitimacy of the package and track any potential vulnerabilities or issues."
                })

            # Determine if the dependency is using the latest available version
            latestAvailableVersionTimestamp = dependency.get('metadata', {}).get('latestAvailableVersion', {}).get('releaseTimestamp')
            usedVersionTimestamp = dependency.get('metadata', {}).get('usedVersion', {}).get('releaseTimestamp')
            if latestAvailableVersionTimestamp and usedVersionTimestamp:
                latestAvailableVersionDateTime = datetime.datetime.fromisoformat(latestAvailableVersionTimestamp.replace("Z", "+00:00"))
                latestAvailableVersionString = dependency.get('metadata', {}).get('latestAvailableVersion', {}).get('version')
                usedVersionDateTime = datetime.datetime.fromisoformat(usedVersionTimestamp.replace("Z", "+00:00"))
                usedVersionString = dependency.get('metadata', {}).get('usedVersion', {}).get('version')
                if usedVersionDateTime < latestAvailableVersionDateTime:
                    daysBehindLatest = (latestAvailableVersionDateTime - usedVersionDateTime).days
                    self.dependencies[dep].setdefault('weakLinks', []).append({
                        'field': 'metadata.usedVersion.releaseTimestamp', 
                        'value': usedVersionTimestamp,
                        'message': f"Used version ({usedVersionString}) for dependency '{dependency['name']}' is {daysBehindLatest} days behind the latest available version ({latestAvailableVersionString}). Using outdated versions can be risky as they may contain unpatched vulnerabilities."
                    })
    
    def buildMarkdownReport(self):
        reportLines = []
        reportLines.append(f"# Software Composition Analysis (SCA) Report")
        reportLines.append(f"")

        if self.isSimulatedLockData:
            reportLines.append(f"**Note: No lock file found. Simulated lock data generated from manifest. This provides estimated information only.**")
            reportLines.append(f"")

        reportLines.append(f"## Thresholds")
        reportLines.append(f"- Allowed SPDX Licenses: {', '.join(self.userDefinedThresholds['allowedSPDXLicenses']) if self.userDefinedThresholds['allowedSPDXLicenses'] else 'None'}")
        reportLines.append(f"- Overall Commit Minimum Activity Days: {self.userDefinedThresholds['overallCommitMinimumActivityDays']} days")
        reportLines.append(f"- Author Commit Minimum Activity Days: {self.userDefinedThresholds['authorCommitMinimumActivityDays']} days")
        reportLines.append(f"- Open to Closed Issue Ratio Threshold: {self.userDefinedThresholds['openToClosedIssueRatioThreshold']:.2f}")
        reportLines.append(f"")

        reportLines.append(f"## Summary")
        reportLines.append(f"- Total Dependencies Detected: {len(self.dependencies)}")
        totalVulnerabilities = sum(len(self.dependencies[dep]['vulnerabilities']) for dep in self.dependencies)
        reportLines.append(f"- Total Known Vulnerabilities: {totalVulnerabilities}")
        totalWeakLinks = sum(len(self.dependencies[dep].get('weakLinks', [])) for dep in self.dependencies)
        reportLines.append(f"- Total Weak Links Detected: {totalWeakLinks}")
        reportLines.append(f"")

        reportLines.append(f"## Dependency Findings")
        reportLines.append(f"")

        firstLevelDependencies = (
            set(self.getNestedDependencies().get('production', {})) |
            set(self.getNestedDependencies().get('development', {}))
        )

        for dep in self.dependencies.keys():
            dependency = self.dependencies[dep]

            reportLines.append(f"### {dependency['name']}")
            reportLines.append(f"- Version: {dependency['version']}")
            dependencyType = 'Direct' if dep in firstLevelDependencies else 'Transitive'
            reportLines.append(f"- Dependency Type: {dependencyType}")
            if dependencyType == 'Transitive':
                usages = self.findDependencyUsages(dep)
                reportLines.append(f"- Dependency Paths:")
                for usage in usages:
                    reportLines.append(f"   - {' > '.join(usage)}")
            reportLines.append(f"- Known Vulnerabilities: {len(dependency.get('vulnerabilities', {}))}")
            reportLines.append(f"- Weak Links Detected: {len(dependency.get('weakLinks', []))}")
            
            reportLines.append(f"")

            if dependency.get('vulnerabilities'):
                reportLines.append(f"#### Known Vulnerabilities (CVEs)")
                for vulnId, vulnData in dependency['vulnerabilities'].items():
                    aliasesList = vulnData.get('aliases', [])
                    aliases = ', '.join(aliasesList) if aliasesList else 'None'
                    summary = vulnData.get('summary', 'No summary available.')
                    published = vulnData.get('published', 'Unknown publish date')
                    details = (lambda t: t[:300].rstrip() + ('...' if len(t) > 300 else ''))(
                        vulnData.get('details', 'No details available.').replace('\r', '').replace('\n', ' ')
                    )

                    osvCategory = vulnData.get('severity', {}).get('OSV', None)
                    cvssV3Metric = vulnData.get('severity', {}).get('CVSS_V3', None)
                    cvssV4Metric = vulnData.get('severity', {}).get('CVSS_V4', None)
                    cvssV3Score = None
                    cvssV3Severity = None
                    cvssV4Score = None
                    cvssV4Severity = None
                    
                    if cvssV3Metric:
                        cvssV3 = cvss.CVSS3(cvssV3Metric)
                        cvssV3Score = cvssV3.scores()[0] # Only the base score is necessary
                        cvssV3Severity = cvssV3.severities()[0] # Only the base severity is necessary
                    if cvssV4Metric:
                        cvssV4 = cvss.CVSS4(cvssV4Metric)
                        cvssV4Score = cvssV4.scores()[0] # Only the base score is necessary
                        cvssV4Severity = cvssV4.severities()[0] # Only the base severity is necessary
                    scoreString = ""
                    if osvCategory:
                        scoreString += f"{osvCategory}"
                    if cvssV3Score and cvssV3Severity:
                        scoreString += f" | CVSS v3: {cvssV3Score} ({cvssV3Severity})"
                    if cvssV4Score and cvssV4Severity:
                        scoreString += f" | CVSS v4: {cvssV4Score} ({cvssV4Severity})"

                    reportLines.append(f"- **{scoreString} - {vulnId}**")
                    reportLines.append(f"   - Alias(es): {aliases}")
                    reportLines.append(f"   - Summary: {summary}")
                    reportLines.append(f"   - Details: {details}")
                    reportLines.append(f"   - CWE IDs: {', '.join(vulnData.get('cwe_ids', [])) if vulnData.get('cwe_ids') else 'None'}")
                    reportLines.append(f"   - Published: {published}")
                    reportLines.append(f"   - References: {'; '.join(vulnData.get('references', [])) if vulnData.get('references') else 'None'}")
                reportLines.append(f"")
            
            if dependency.get('weakLinks'):
                reportLines.append(f"#### Weak Links")
                for weakLink in dependency['weakLinks']:
                    reportLines.append(f"- {weakLink['message']}")
                reportLines.append(f"")

        self.reportContents = reportLines

    def generatePackageUrl(self, packageName, packageVersion):
        return f"pkg:packagist/{packageName}@{packageVersion}"
    
    def ingestPackageManifests(self):
        self.logger.debug(f"Ingesting package manifests from directory: {self.gitProjectDirectoryPath}")

        manifestPath = os.path.join(self.gitProjectDirectoryPath, "composer.json")
        lockfilePath = os.path.join(self.gitProjectDirectoryPath, "composer.lock")

        # At least a composer.json file is required to perform SCA
        if not os.path.exists(manifestPath):
            raise SCAMissingDependencyFilesError(f"Missing composer.json in directory {self.gitProjectDirectoryPath}. Required to perform Software Composition Analysis.")

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

        self.logger.debug("Completed ingesting package manifests.")
        self.logger.debug("Manifest data")
        self.logger.debug(self.rawManifestData)
        self.logger.debug("Lock data")
        self.logger.debug(self.rawLockData)
        self.logger.debug("Version lookup")
        self.logger.debug(self.versionLookup)

    def generateSimulatedLockData(self):
        self.logger.debug("Generating simulated lock data from manifest dependencies.")

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
        self.logger.debug("Building inventory of dependencies from lock data.")

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

        self.logger.debug(f"Completed building inventory with {len(self.dependencies)} dependencies.")
        self.logger.debug(self.dependencies)

    def buildAdjacencyList(self):
        self.logger.debug("Building adjacency list for dependency graph.")

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
        
        self.logger.debug("Completed building adjacency list for dependency graph.")
        self.logger.debug(self.dependencyGraph)

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
                if dependency == 'php' or dependency.startswith('ext-'): continue
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
    
    def getKnownCVEsForAllDependencies(self):
        # Capture the keys in a list to maintain the original order
        dependencies = list(self.dependencies.keys())

        self.logger.info(f"Querying OSV API for known vulnerabilities for {len(dependencies)} dependencies.")

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
            
            self.logger.info(f"Querying OSV API with exact dependency version data.")
            self.logger.debug(payload)
        
            response = requests.post(
                'https://api.osv.dev/v1/querybatch',
                json=payload,
            )
            data = response.json()

            if 'results' in data:
                for dep, result in zip(dependencies, data['results']):
                    vulns = result.get('vulns', [])

                    self.logger.debug(f"Received {len(vulns)} vulnerabilities for dependency {dep} from OSV API.")

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

                self.logger.info(f"Querying OSV API for dependency {dep} with {len(payload['queries'])} possible versions due to simulated lock data.")
                self.logger.debug(payload)

                response = requests.post(
                    'https://api.osv.dev/v1/querybatch',
                    json=payload,
                )
                data = response.json()
                if 'results' in data:
                    for result in data['results']:
                        vulns = result.get('vulns', [])

                        self.logger.info(f"Received {len(vulns)} vulnerabilities for dependency {dep} with simulated version data from OSV API.")

                        for vuln in vulns:
                            # Only populate the vulnerability if it's not already captured - prevents duplicates across versions
                            if vuln.get('id') not in self.dependencies[dep]['vulnerabilities']:
                                self.dependencies[dep]['vulnerabilities'][vuln.get('id')] = {
                                    'id': vuln.get('id')
                                }

    def getMoreDetailsForAllKnownCVEs(self):
        self.logger.debug("Fetching more details for all known CVEs from OSV API.")

        # The /querybatch endpoint doesn't return all details, so we make individual requests for each CVE
        for dep in self.dependencies.keys():
            if len(self.dependencies[dep]['vulnerabilities']) == 0: continue

            for vuln in self.dependencies[dep]['vulnerabilities'].keys():
                self.logger.info(f"Fetching vulnerability details for {vuln} affecting dependency {dep}.")

                response = requests.get(
                    f"https://api.osv.dev/v1/vulns/{vuln}"
                )
                data = response.json()
                self.logger.debug(data)

                # Different severity types are returned in an array
                severityMapFromResponse = {item['type']: item['score'] for item in data.get('severity', [])}

                # Get the advisory reference
                advisoryReferences = []
                for reference in data.get('references', []):
                    type = reference.get('type')
                    url = reference.get('url')
                    # https://ossf.github.io/osv-schema/
                    if (type and url):
                        advisoryReferences.append(url)

                existingData = self.dependencies[dep]['vulnerabilities'].get(vuln, {})
                additionalData = {
                    'summary': data.get('summary'),
                    'details': data.get('details'),
                    'aliases': data.get('aliases', []),
                    'cwe_ids': data.get('database_specific', {}).get('cwe_ids', []),
                    'severity': {
                        'OSV': data.get('database_specific', {}).get('severity', []),
                        'CVSS_V3': severityMapFromResponse.get('CVSS_V3'),
                        'CVSS_V4': severityMapFromResponse.get('CVSS_V4'),
                    },
                    'references': advisoryReferences,
                    'published': data.get('published'),
                }

                mergedData = {**existingData, **additionalData}
                self.dependencies[dep]['vulnerabilities'][vuln] = mergedData

        self.logger.info("Completed fetching details for known CVEs.")
        dependencyCount = len(self.dependencies)
        totalVulnerabilities = sum(len(self.dependencies[dep]['vulnerabilities']) for dep in self.dependencies)
        self.logger.info(f"Total dependencies with known vulnerabilities: {sum(1 for dep in self.dependencies if len(self.dependencies[dep]['vulnerabilities']) > 0)} out of {dependencyCount} dependencies.")
        self.logger.info(f"Total known vulnerabilities: {totalVulnerabilities}")

    def getAllPossibleVersionsForSimulatedData(self):
        if not self.isSimulatedLockData:
            return
        
        self.logger.debug("Getting all possible versions for dependencies using Packagist API due to simulated lock data.")
        
        # Get all versions for each package from Packagist API
        for dep in self.dependencies.keys():
            dependency = self.dependencies[dep]

            self.logger.debug(f"Fetching versions for {dependency['name']}")

            # https://packagist.org/apidoc
            response = requests.get(f"https://repo.packagist.org/p2/{dependency['name']}.json")
            json = response.json()
            allVersions = []

            for data in json.get('packages', {}).get(dependency['name'], []):
                version = data.get('version')
                if version:
                    allVersions.append(version)

            self.dependencies[dep]['possibleVersions'] = self.filterVersionsByConstraint(allVersions, dependency['version'])

            self.logger.debug(f"Found {len(self.dependencies[dep]['possibleVersions'])} possible versions for {dependency['name']} with constraint {dependency['version']}")
            self.logger.debug(self.dependencies[dep]['possibleVersions'])
        
        self.logger.debug("Completed fetching possible versions for dependencies.")

    def getMetadataForAllDependencies(self):
        for dep in self.dependencies.keys():
            dependency = self.dependencies[dep]

            usedVersion = dependency['version']

            # If we're using simulated data, we don't have exact versions, so we need the most recent version
            if self.isSimulatedLockData and dependency.get('possibleVersions'):
                highestVersion = None
                for v in dependency['possibleVersions']:
                    try:
                        cleanVersion = v.lstrip('vV')
                        coercedVersion = semantic_version.Version.coerce(cleanVersion)
                        
                        cleanHighestVersion = highestVersion.lstrip('vV') if highestVersion else None
                        coercedHighestVersion = semantic_version.Version.coerce(cleanHighestVersion) if highestVersion else None
                        if not highestVersion or coercedVersion > coercedHighestVersion:
                            highestVersion = v
                    except ValueError:
                        self.logger.warning(f"Warning: Unable to parse version '{v}' for package {dependency['name']}. Skipping this version for metadata retrieval.")
                        continue
                if highestVersion:
                    usedVersion = str(highestVersion)
                    self.logger.debug(f"For dependency {dependency['name']}, using highest possible version {usedVersion} for metadata retrieval due to simulated lock data.")
            
            # Get the version timestamp from Packagist API
            self.logger.debug(f"Fetching versions timestamp for {dependency['name']} at version {usedVersion}.")

            # https://packagist.org/apidoc
            response = requests.get(f"https://repo.packagist.org/p2/{dependency['name']}.json")
            json = response.json()

            latestAvailableVersion = None
            latestAvailableVersionTimestamp = None
            latestAvailableVersionDateTime = None
            usedVersionTimestamp = None

            usedVersionSourceUrl = None
            usedVersionSourceReference = None

            if 'packages' in json and dependency['name'] in json['packages']:
                for data in json['packages'][dependency['name']]:
                    version = data.get('version')
                    time = data.get('time')

                    if not version or not time:
                        self.logger.debug(f"Skipping version data for {dependency['name']} due to missing version or time. Version: {version}, Time: {time}")
                        continue

                    # Convert to a datetime for comparison
                    timestamp = datetime.datetime.fromisoformat(time.replace('Z', '+00:00')) if time else None

                    # Track the latest version
                    if (latestAvailableVersionTimestamp is None or timestamp > latestAvailableVersionDateTime):
                        latestAvailableVersionDateTime = timestamp
                        latestAvailableVersionTimestamp = time
                        latestAvailableVersion = version

                    if data.get('version') == usedVersion:
                        usedVersionTimestamp = data.get('time')
                        usedVersionSourceUrl = data.get('source', {}).get('url')
                        usedVersionSourceReference = data.get('source', {}).get('reference')
            
            self.dependencies[dep]['metadata'] = {
                'usedVersion': {
                    'version': usedVersion,
                    'releaseTimestamp': usedVersionTimestamp
                },
                'latestAvailableVersion': {
                    'version': latestAvailableVersion,
                    'releaseTimestamp': latestAvailableVersionTimestamp
                },
                'gitSource': {
                    'url': usedVersionSourceUrl,
                    'reference': usedVersionSourceReference
                }
            }

    def createCachedCopyOfDependencyData(self):
        os.makedirs(self.cacheDirectoryPath, exist_ok=True)

        # Create a clone of each dependency repo
        for dep in self.dependencies.keys():
            dependency = self.dependencies[dep]
            repoUrl = dependency.get('metadata', {}).get('gitSource', {}).get('url')
            repoReference = dependency.get('metadata', {}).get('gitSource', {}).get('reference')

            if not repoUrl:
                self.logger.warning(f"Warning: No repository URL found for dependency {dependency['name']}. Skipping caching for this dependency.")
                continue
    
            gitPath = pathlib.Path(repoUrl)
            self.logger.debug(f"Parsed git path for dependency {dependency['name']}: {gitPath}")
            gitProjectSlug = f"{gitPath.parent.name}/{gitPath.stem}/{repoReference[:7]}"
            clonePath = os.path.join(self.cacheDirectoryPath, gitProjectSlug)

            if repoUrl and repoReference:
                self.logger.info(f"Caching repository for dependency {dependency['name']} from {repoUrl} at reference {repoReference} into {clonePath}.")
                GitHelper.shallowClone(clonePath, repoUrl, repoReference, logger=self.logger, depth=1)

                self.dependencies[dep]['metadata']['gitSource']['cachedPath'] = clonePath
                self.logger.debug(f"Cached repository for dependency {dependency['name']} at {clonePath}.")

    def parseMetadataFromComposerManifestFile(self):
        self.logger.info("Parsing metadata from composer.json manifest files for all dependencies.")
        for dep in self.dependencies.keys():
            dependency = self.dependencies[dep]

            cachedPath = dependency.get('metadata', {}).get('gitSource', {}).get('cachedPath')

            if not cachedPath:
                self.logger.warning(f"Warning: No cached repository path found for dependency {dependency['name']}. Skipping metadata parsing for this dependency.")
                continue

            composerManifestData = self.loadJsonFile(os.path.join(dependency['metadata']['gitSource']['cachedPath'], "composer.json"))
            
            # Get the license values within the composer.json file
            licenseValue = composerManifestData.get('license') or None
            if licenseValue:
                # Determing if the license value is a string or a list
                if isinstance(licenseValue, str):
                    licenseList = [licenseValue]
                elif isinstance(licenseValue, list):
                    licenseList = licenseValue
                else:
                    self.logger.warning(f"Warning: Unrecognized license format for dependency {dependency['name']}. Expected string or list, got {type(licenseValue)}. Skipping license parsing for this dependency.")
                    continue
            
            # Populate the license value in the dependencies data structure
            self.dependencies[dep]['metadata']['licenses'] = licenseList
            self.logger.debug(f"Parsed license for dependency {dependency['name']}: {licenseList}")

            # Retrieve any authors defined - only get their email address
            authorsValue = composerManifestData.get('authors') or None
            if authorsValue and isinstance(authorsValue, list):
                emailList = []
                for author in authorsValue:
                    email = author.get('email')
                    if email and isinstance(email, str) and '@' in email:
                        emailList.append(email)
                self.dependencies[dep]['metadata']['authors'] = emailList
                self.logger.debug(f"Parsed authors for dependency {dependency['name']}: {emailList}")

    def scanMetadataForWeakLinksForAllDependencies(self):
        self.logger.info("Scanning metadata for weak links for all dependencies.")

        # https://getcomposer.org/doc/articles/scripts.md
        scriptKeys = [
            'scripts',
            'pre-install-cmd',
            'post-install-cmd',
            'pre-update-cmd',
            'post-update-cmd',
            'pre-status-cmd',
            'post-status-cmd',
            'pre-archive-cmd',
            'post-archive-cmd',
            'pre-autoload-dump',
            'post-autoload-dump',
            'post-root-package-install',
            'post-create-project-cmd',
            'pre-operations-exec',
            'pre-package-install',
            'post-package-install',
            'pre-package-update',
            'post-package-update',
            'pre-package-uninstall',
            'post-package-uninstall',
            'init',
            'command',
            'pre-file-download',
            'post-file-download',
            'pre-command-run',
            'pre-pool-create',
        ]
        
        def findWeakLinks(data, path=""):
            results  = []

            if isinstance(data, dict):
                for key, value in data.items():
                    fullPath = f"{path}.{key}" if path else key

                    # Detect weak HTTP links
                    if isinstance(value, str) and value.lower().startswith("http://"):
                        results.append({
                            'field': fullPath, 
                            'value': value,
                            'message': f"Found non-HTTPS URL in field '{fullPath}': '{value}'. Prone to man-in-the-middle attack."
                        })
                    
                    # Detect script keys - https://getcomposer.org/doc/articles/scripts.md
                    if key.lower() in scriptKeys:
                        results.append({
                            'field': fullPath, 
                            'value': value,
                            'message': f"Found Composer script keyword '{key}': '{value}'. These scripts can execute arbitrary code and pose a security risk."
                        })

                    # Detect inactive maintainer email address
                    if key.lower() == 'authors' and isinstance(value, list):
                        for author in value:
                            email = author.get('email')
                            if email and isinstance(email, str) and '@' in email:
                                # Get the domain from the email address
                                domain = email.rsplit('@', 1)[1]

                                mxRecords = self.checkMxRecordExistsForDomain(domain)
                                if not mxRecords:
                                    results.append({
                                        'field': fullPath, 
                                        'value': email,
                                        'message': f"Email address '{email}' for author '{author.get('name')}' may be inactive as the domain '{domain}' has no MX records. This could indicate an unmaintained package or potential for account takeover."
                                    })
                    
                    # Recurse into nested dicts/lists
                    if isinstance(value, (dict, list)):
                        results.extend(findWeakLinks(value, fullPath))
            elif isinstance(data, list):
                for index, item in enumerate(data):
                    fullPath = f"{path}[{index}]"
                    results.extend(findWeakLinks(item, fullPath))

            return results
        
        for depName, dependency in self.dependencies.items():
            cachedPath = dependency.get('metadata', {}).get('gitSource', {}).get('cachedPath')

            if not cachedPath:
                self.logger.warning(f"Warning: No cached repository path found for dependency {dependency['name']}. Skipping weak link scanning for this dependency.")
                continue

            composerManifestData = self.loadJsonFile(os.path.join(dependency['metadata']['gitSource']['cachedPath'], "composer.json"))

            results = findWeakLinks(composerManifestData)
            if results:
                self.dependencies[depName].setdefault('weakLinks', []).extend(results)
                for link in results:
                    self.logger.warning(f"Warning in dependency {dependency['name']} - {link['message']}")

    def checkMxRecordExistsForDomain(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return len(answers) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return False

    def retrieveRepositoryStatisticsForAllDependencies(self):
        self.logger.info("Retrieving repository statistics for all dependencies with GitHub repositories.")
        for dep in self.dependencies.keys():
            dependency = self.dependencies[dep]
            repoUrl = dependency.get('metadata', {}).get('gitSource', {}).get('url')

            if not repoUrl:
                self.logger.warning(f"Warning: No repository URL found for dependency {dependency['name']}. Skipping repository statistics retrieval for this dependency.")
                continue

            if "github" in repoUrl.lower():
                gitPath = pathlib.Path(repoUrl)
                gitProjectSlug = f"{gitPath.parent.name}/{gitPath.stem}"

                response = requests.get(
                    f"https://api.github.com/search/issues?q=repo:{gitProjectSlug}+is:issue+is:closed", 
                    headers={
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2026-03-10",
                        "Authorization": f"Bearer {os.getenv('GITHUB_API_BEARER_TOKEN')}"
                    }
                )
                totalClosed = response.json().get('total_count', 0)
                self.logger.debug(totalClosed)

                response = requests.get(
                    f"https://api.github.com/search/issues?q=repo:{gitProjectSlug}+is:issue+is:open", 
                    headers={
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2026-03-10",
                        "Authorization": f"Bearer {os.getenv('GITHUB_API_BEARER_TOKEN')}"
                    }
                )
                totalOpen = response.json().get('total_count', 0)
                self.logger.debug(totalOpen)

                response = requests.get(
                    f"https://api.github.com/repos/{gitProjectSlug}/commits",
                    headers={
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2026-03-10",
                        "Authorization": f"Bearer {os.getenv('GITHUB_API_BEARER_TOKEN')}"
                    }
                )
                commits = response.json()
                self.logger.debug(commits)

                mostRecentCommitDate = None
                if isinstance(commits, list) and len(commits) > 0:
                    mostRecentCommitDate = commits[0].get('commit', {}).get('author', {}).get('date')

                # Get authors from dependency metadata
                authors = self.dependencies[dep].get('metadata', {}).get('authors', [])
                authorCommits = {email: None for email in authors}
                
                # Cycle through all of the commits, and get the date of the commit by each author
                for commit in commits:
                    author = commit.get('commit', {}).get('author', {})
                    authorEmail = author.get('email')
                    commitDateStr = author.get('date')

                    if authorEmail in authorCommits and commitDateStr:
                        commitDate = datetime.datetime.fromisoformat(commitDateStr.replace("Z", "+00:00"))

                        prevDateStr = authorCommits[authorEmail]
                        if prevDateStr is None:
                            authorCommits[authorEmail] = commitDateStr
                        else:
                            prevDate = datetime.datetime.fromisoformat(prevDateStr.replace("Z", "+00:00"))
                            if commitDate > prevDate:
                                authorCommits[authorEmail] = commitDateStr

                self.dependencies[dep]['metadata']['repositoryStatistics'] = {
                    'totalClosedIssues': totalClosed,
                    'totalOpenIssues': totalOpen,
                    'overallRepositoryMostRecentCommitDate': mostRecentCommitDate,
                    'authorMostRecentCommitDate': authorCommits
                }

    def filterVersionsByConstraint(self, allVersions, constraint):
        normalisedConstraint = constraint.lstrip('vV')
        
        try:
            spec = semantic_version.NpmSpec(normalisedConstraint)
        except ValueError:
            self.logger.warning(f"Warning: Unable to parse version constraint '{constraint}'. Using all versions.")
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
                self.logger.warning(f"Warning: Unable to parse version '{version}' for package with constraint '{constraint}'. Skipping this version.")
                continue

        return compatibleVersions

    def findDependencyUsages(self, target):
        usages = []
        self.depthFirstSearchUp(target, [target], usages)
        return usages

    def depthFirstSearchUp(self, current, path, paths):
        parents = self.buildReverseDependencyGraph().get(current, [])

        # If no one depends on this, then its a root package
        if not parents:
            paths.append(list(reversed(path)))
            return
        for parent in parents:
            if parent in path:
                continue
            self.depthFirstSearchUp(parent, path + [parent], paths)

    def buildReverseDependencyGraph(self):
        reverse = {}

        for parent, children in self.dependencyGraph.items():
            for child in children:
                
                reverse.setdefault(child, []).append(parent)
        
        return reverse

    def loadJsonFile(self, jsonPath):
        with open(jsonPath, 'r', encoding='utf-8') as f:
            return json.load(f)

class SCAMissingDependencyFilesError(Exception):
    pass

class SCAMissingDirectoryError(Exception):
    pass