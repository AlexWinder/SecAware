#!/usr/bin/env python3

import argparse
import dotenv
import git
import json
import os
import pathlib
import re
import requests
import semantic_version
import subprocess
import sys
import textwrap
import xml.etree.ElementTree as XML

from app.cli.ArgparseCustomFormatter import ArgparseCustomFormatter
from app.utils.ConsoleColour import ConsoleColour
from app.data.OWASPContext import owaspTop10Context

class SCAMissingDependencyFilesError(Exception):
    pass

class SCAMissingDirectoryError(Exception):
    pass

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
    
class StaticAnalysis:
    psalmConfigPath: str

    def __init__(self):
        self.buildConfigurationFile()
        self.runAnalysis(relativeToScriptAbsolutePath("test-data/vuln.php"))

    def buildConfigurationFile(self):
        psalmConfig = XML.Element('psalm')
        xmlTree = XML.ElementTree(psalmConfig)
        self.psalmConfigPath = relativeToScriptAbsolutePath("test-data/psalm.xml")
        xmlTree.write(self.psalmConfigPath, encoding='utf-8', xml_declaration=True)

    def runAnalysis(self, target):
        subprocess.run([
            "psalm",
            "--config", self.psalmConfigPath,
            "--taint-analysis",
            "--output-format=json",
            "--report=" + relativeToScriptAbsolutePath("debug/psalm-output.json"),
            target
        ])

class GenerativeAIAnalysis:
    findings: dict
    model: str

    def __init__(self):
        self.findings = {}
        self.model = "google/gemma-3-4b"
        self.checkApiAccessible()

    def checkApiAccessible(self):
        response = requests.get('http://host.docker.internal:1234/v1/models')

        for model in response.json().get('data', []):
            if model.get('id') == self.model:
                print(f"Successfully connected to AI API and found model {self.model}")
                return
        
        errorMessage(f"Model {self.model} not found in AI API response. Please ensure the model is correctly loaded in the API and try again.")

    def vulnerabilityScanForFile(self, filePath):
        # We scan several times because AI is non-deterministic
        for i in range(3):
            print(f'Scanning file {filePath}, iteration {i+1}/3...')
            self.initialVulnerabilityScan(filePath)
        
        jsonFileName = str(filePath).lstrip('/').replace('/', '') + ".json"
        
        print(f"Aggregating findings for file {filePath}...")
        self.aggregateInitialFindings(filePath)

        print(f"Assigning correct CWE and OWASP categories for file {filePath}...")
        self.assignCorrectCWEOWASPCategories(filePath)

        dumpJsonToFile(f"debug/{jsonFileName}", self.findings)
    
    def vulnerabilityJsonSchema(self):
        return textwrap.dedent("""\
            When you return results, this should be presented as a JSON object, which uses the following OpenAPI schema:
            
            ```yaml
            type: object
            properties:
                vulnerabilities:
                    type: array
                    items:
                        type: object
                        properties:
                        description:
                            type: string
                            description: A brief description of the vulnerability identified in the code.
                        owasp_categories:
                            type: array
                            nullable: true
                            description: A mapping to one of the OWASP Top 10 categories, if applicable. If the vulnerability does not fit into any OWASP category, this should be null.
                            items:
                                type: string
                                description: The OWASP Top 10 category, e.g. "A05:2025 - Injection".
                        cwe_ids:
                            type: array
                            nullable: true
                            description: A mapping to one or more CWE IDs, if applicable. If the vulnerability does not fit into any CWE ID, this should be null.
                            items:
                                type: string
                                description: The CWE ID.
                        line:
                            type: string
                            description: The particular line that contains the suspected vulnerability, with the vulnerable portion highlighted.
                        justification:
                            type: string
                            description: A concise but clear justification for why the identified line is vulnerable.
                        fix:
                            type: string
                            nullable: true
                            description: Any fix recommended to resolve the identified vulnerability.
                        confidences:
                            type: object
                            properties:
                                description:
                                    type: integer
                                    max: 10
                                    min: 0
                                    description: A confidence score of the defined description. 10 = complete confidence. 0 = no confidence.
                                owasp_categories:
                                    type: integer
                                    max: 10
                                    min: 0
                                    description: A confidence score of the defined OWASP categories. 10 = complete confidence. 0 = no confidence.
                                cwe_ids:
                                    type: integer
                                    max: 10
                                    min: 0
                                    description: A confidence score of the defined CWE IDs. 10 = complete confidence. 0 = no confidence.
                                line:
                                    type: integer
                                    max: 10
                                    min: 0
                                    description: A confidence score of the identified line. 10 = complete confidence. 0 = no confidence.
                                overall:
                                    type: integer
                                    max: 10
                                    min: 0
                                    description: A confidence score of the overall vulnerability finding. 10 = complete confidence. 0 = no confidence.
                        required:
                        - description
                        - line
                        - justification
                        - confidences
            ```
        """)
    
    def explicitJsonOutputInstruction(self):
        return textwrap.dedent("""\
            Output ONLY valid JSON.
            Do NOT include any code fences, markdown, delimiters, formatting or extra text.
            Output MUST be parseable directly as JSON without any additional processing.
        """)

    def initialVulnerabilityScan(self, filePath):
        systemPrompt = textwrap.dedent("""\
            You are a cybersecurity specialist who specialises in identifying vulnerabilities in software code. 
            You are primarily focused on PHP applications. When given a code file, you will analyse it for potential security vulnerabilities.
            
            When analysing code for vulnerabilities, respond **only with the vulnerabilities, explanations, and recommendations/suggested fixes**. 
            Do not include greetings, filler text, disclaimers, or any generic commentary. Focus solely on the code provided.
                                       
            Consider the OWASP Top 10 vulnerabilities as part of your analysis. The OWASP Top 10 vulnerabilities include:
        """) + "\n".join([f"- {item['id']} {item['name']}" for item in owaspTop10Context])

        systemPrompt += self.vulnerabilityJsonSchema()
        systemPrompt += self.explicitJsonOutputInstruction()

        with open(filePath, 'r', encoding='utf-8') as f:
            fileContent = f.read()
        
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": systemPrompt
                },
                {
                    "role": "user",
                    "content": fileContent
                }
            ]
        }

        response = requests.post(
            'http://host.docker.internal:1234/v1/chat/completions', 
            headers={'Content-Type': 'application/json'},
            json=payload
        )

        responseJson = response.json()
        if 'choices' in responseJson:
            aiMessageContent = responseJson['choices'][0]['message']['content']
            
            cleanedResponse = self.cleanUpResponse(aiMessageContent)

            if filePath not in self.findings:
                self.findings[filePath] = {
                    "file": filePath,
                    "vulnerabilities": []
                }
            self.findings[filePath]["vulnerabilities"].append(json.loads(cleanedResponse)['vulnerabilities'])

    def cleanUpResponse(self, response):
        # Tidy up the response by removing any markdown code blocks
        cleanedResponse = re.sub(r"^```.*?\n|\n```$", "", response.strip(), flags=re.DOTALL)
        return cleanedResponse

    def aggregateInitialFindings(self, filePath):
        systemPrompt = textwrap.dedent("""\
            You are a cybersecurity data processor, specialising in vulnerability management.
            Your sole objective is to take a list of existing vulnerability findings and consolidate them into a unique, deduplicated JSON list.
            
            As part of your analysis, you should also ensure that the OWASP and CWE mappings are correctly allocated.

            Do NOT scan for new vulnerabilities.
            If multiple findings refer to the same vulnerability with the same CWE/OWASP mapping, these should be merged into a single finding in the output.
            Use the provided source code ONLY as a reference to verify and consolidate the existing findings.
                                       
            When declaring confidence scores for each vulnerability, adjust accordingly based on the aggregation that was needed to form the final result. For example, if multiple findings are conflicting, then the confidence score may need to be reduced. A confidence score can help a human reviewer understand how certain you are about the accuracy of your findings. For all confidence scores, a 0 indicates no confidence, and a 10 indicates complete confidence.
        """)

        systemPrompt += self.vulnerabilityJsonSchema()
        systemPrompt += self.explicitJsonOutputInstruction()

        with open(filePath, 'r', encoding='utf-8') as f:
            fileContent = f.read()

        userPrompt = textwrap.dedent(f"""\
            JSON findings:
                                     
            ```json
            {self.findings}
            ```
                                     
            For reference, the original code file:
            
            ```
            {fileContent}
            ```
        """)

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": systemPrompt
                },
                {
                    "role": "user",
                    "content": userPrompt
                }
            ]
        }

        response = requests.post(
            'http://host.docker.internal:1234/v1/chat/completions', 
            headers={'Content-Type': 'application/json'},
            json=payload
        )

        responseJson = response.json()
        if 'choices' in responseJson:
            aiMessageContent = responseJson['choices'][0]['message']['content']
            
            cleanedResponse = self.cleanUpResponse(aiMessageContent)

            if filePath not in self.findings:
                self.findings[filePath] = {
                    "file": filePath,
                    "vulnerabilities": []
                }
            self.findings[filePath]["vulnerabilities"] = json.loads(cleanedResponse)['vulnerabilities']

    def assignCorrectCWEOWASPCategories(self, filePath):
        systemPrompt = textwrap.dedent("""\
            You are a cybersecurity specialist, specialising in vulnerability classification and management.
            Your primary focus is to ensure that any identified vulnerabilities are correctly mapped to their appropriate CWE and OWASP categories.
            When presented with a list of vulnerabilities, your task is to review each one and assign the most accurate CWE ID(s) and OWASP Top 10 category, if applicable.
                                       
            It is very important that the CWE and OWASP mappings are as accurate as possible.
            A list of OWASP Top 10 categories and their allowed mapped CWE IDs are as follows:
        """)

        for item in owaspTop10Context:
            systemPrompt += f"- {item['id']} {item['name']} ({', '.join([f'{cwe['id']}' for cwe in item.get('cwe_ids', [])])})\n"
        
        systemPrompt += textwrap.dedent("""\
            This list is authoritative, and so if there is any mismatch between the OWASP category or the CWE IDs, then you should adjust the mappings to ensure they are correct according to the above list.
                                       
            You should not update any other part of the vulnerability finding except for the CWE and OWASP mappings.
                                        
            When returning a response, this should be in the same format as the JSON which was submitted.
        """)

        systemPrompt += self.explicitJsonOutputInstruction()

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": systemPrompt
                },
                {
                    "role": "user",
                    "content": json.dumps(self.findings)
                }
            ]
        }

        response = requests.post(
            'http://host.docker.internal:1234/v1/chat/completions', 
            headers={'Content-Type': 'application/json'},
            json=payload
        )

        responseJson = response.json()
        if 'choices' in responseJson:
            aiMessageContent = responseJson['choices'][0]['message']['content']
            
            cleanedResponse = self.cleanUpResponse(aiMessageContent)

            if filePath not in self.findings:
                self.findings[filePath] = {
                    "file": filePath,
                    "vulnerabilities": []
                }
            
            self.findings[filePath]["vulnerabilities"] = json.loads(cleanedResponse)[filePath]['vulnerabilities']

def errorMessage(message):
    ConsoleColour.toRed(message)
    sys.exit(1)

def relativeToScriptAbsolutePath(relativePath):
    return os.path.join(os.path.dirname(__file__), relativePath)

def dumpJson(data):
    print(json.dumps(data, indent=2))

def dumpJsonToFile(filename, data):
    filename = relativeToScriptAbsolutePath(filename)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

class GitHelper:
    @staticmethod
    def shallowClone(repoUrl, commitHash):
        project = pathlib.Path(repoUrl)
        projectSlug = f"{project.parent.name}/{project.stem}/{commitHash[:7]}"
        repoPath = relativeToScriptAbsolutePath(f"git-project-data/{projectSlug}")

        # Workaround to allow GitPython within Docker environments due to file permissions
        subprocess.run(['git', 'config', '--global', '--replace-all', 'safe.directory', '*'])

        # If the repository already exists at the correct commit hash, then skip cloning
        if os.path.exists(repoPath):
            existingRepo = git.Repo(repoPath)
            if existingRepo.head.commit.hexsha.startswith(commitHash):
                print(f"Repository already exists at {repoPath} with the correct commit hash. Skipping clone.")
                return repoPath
            else:
                print(f"Repository already exists at {repoPath} but with a different commit hash. Removing and recloning.")
                subprocess.run(['rm', '-rf', repoPath])
        else:
            print(f"Cloning repository {repoUrl} at commit {commitHash} into {repoPath}...")
            repo = git.Repo.init(repoPath)
            origin = repo.create_remote('origin', repoUrl) if 'origin' not in repo.remotes else repo.remotes.origin
            # 2 depth needed to allow diffing from the parent
            origin.fetch(commitHash, depth=2)
            repo.git.checkout('FETCH_HEAD')

        return repoPath
    
    @staticmethod
    def diffFiles(repoPath, commitHash):
        repo = git.Repo(repoPath)
        diff = repo.git.diff(f"{commitHash}~1", commitHash, name_only=True)
        changedFiles = diff.splitlines()
        return changedFiles

class SecAware:
    aiRestApiBaseUrl: str
    codeFilesForAnalysis: list
    componentSoftwareCompositionAnalysis: SoftwareCompositionAnalysis
    dependencyManagementFiles: list
    gitChangedFiles: list
    gitRepoLocalPath: str
    gitRepoRemoteUrl: str
    gitCommitHash: str

    def __init__(self, aiRestApiBaseUrl, gitRepoRemoteUrl, gitCommitHash):
        self.aiRestApiBaseUrl = self.formatBaseUrl(aiRestApiBaseUrl)
        self.gitRepoRemoteUrl = gitRepoRemoteUrl
        self.gitCommitHash = gitCommitHash

        self.checkDotEnvFileExists()
        self.loadEnvironmentVariables()
        
        print(ConsoleColour.toYellow("Preparing Git Repository for Analysis"))
        self.gitRepoLocalPath = GitHelper.shallowClone(self.gitRepoRemoteUrl, self.gitCommitHash)
        self.gitChangedFiles = GitHelper.diffFiles(self.gitRepoLocalPath, self.gitCommitHash)
        self.codeFilesForAnalysis = self.identifySuitableFilesForAnalysis(self.gitChangedFiles)
        self.dependencyManagementFiles = self.detectDependencyManagementFiles(self.gitRepoLocalPath)
        print(f"Identified {len(self.codeFilesForAnalysis)} code files for vulnerability analysis.\n")

        print(ConsoleColour.toYellow("Software Composition Analsysis (SCA)"))
        try:
            self.componentSoftwareCompositionAnalysis = SoftwareCompositionAnalysis(directoryPath=self.gitRepoLocalPath)
        except SCAMissingDependencyFilesError:
            print(ConsoleColour.toRed("Skipping SCA due to missing dependency files."))
        except SCAMissingDirectoryError:
            print(ConsoleColour.toRed("Skipping SCA due to missing directory path."))

        dumpJsonToFile("debug/sca.json", self.componentSoftwareCompositionAnalysis.dependencies)

    def checkDotEnvFileExists(self):
        if not os.path.exists(".env"):
            errorMessage(".env file not found. Please create a .env file based on the .env.example file and add the required environment variables.")

    def loadEnvironmentVariables(self):
        dotenv.load_dotenv()
        existingVars = ["GITHUB_TOKEN"]
        for var in existingVars:
            if var not in os.environ:
                errorMessage(f"{var} environment variable not set within .env file")

    def formatBaseUrl(self, url):
        return url.rstrip('/')
    
    def identifySuitableFilesForAnalysis(self, allFiles):
        suitableFiles = [file for file in allFiles if file.endswith('.php')]
        return suitableFiles
    
    def detectDependencyManagementFiles(self, directoryPath):
        dependencyFiles = []
        for root, dirs, files in os.walk(directoryPath):
            for file in files:
                if file in ['composer.json', 'composer.lock']:
                    dependencyFiles.append(os.path.join(root, file))
        return dependencyFiles

if __name__ == '__main__':

    print(ConsoleColour.toGreen("SecAware - A Context-Aware Software Vulnerability Detection Tool") + "\n")

    description = textwrap.dedent("""\
        SecAware is a context-aware software vulnerability detection tool. It combines traditional software composition analysis and static analysis techniques with generative AI capability to provide comprehensive vulnerability detection for software applications.
    """)

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=ArgparseCustomFormatter
    )
    parser.add_argument('--ai-rest-base-url', type=str, default='http://host.docker.internal:1234', help='The base URL for the generative AI REST API.')
    # Default values are a known vulnerability
    # https://github.com/advisories/GHSA-4xf2-7qfv-mgfx
    parser.add_argument('--git-repo-url', type=str, default='https://github.com/in2code-de/ipandlanguageredirect.git', help='The Git repository HTTP URL to scan.')
    parser.add_argument('--git-commit-hash', type=str, default='b814ae1bc545187f924734c1f3ee0999153264ae', help='The specific Git commit hash to use for the scan.')
    
    args = parser.parse_args()

    secAware = SecAware(
        aiRestApiBaseUrl=args.ai_rest_base_url,
        gitRepoRemoteUrl=args.git_repo_url,
        gitCommitHash=args.git_commit_hash
    )
