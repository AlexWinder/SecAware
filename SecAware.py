#!/usr/bin/env python3

import dotenv
import json
import os
import re
import requests
import subprocess
import sys
import textwrap
import xml.etree.ElementTree as XML

from OWASPContext import owaspTop10Context

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
                'vulnerabilities': {}
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
                    self.dependencies[dep]['vulnerabilities'][vuln.get('id')] = {
                        'id': vuln.get('id')
                    }

        dumpJsonToFile("debug/apiRequest.json", payload)
        dumpJsonToFile("debug/apiResponse.json", data)

        # The /querybatch endpoint doesn't return all details, so we now need to make individual requests for each CVE
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

def relativeToScriptAbsolutePath(relativePath):
    return os.path.join(os.path.dirname(__file__), relativePath)

def dumpJson(data):
    print(json.dumps(data, indent=2))

def dumpJsonToFile(filename, data):
    filename = relativeToScriptAbsolutePath(filename)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

if __name__ == '__main__':
    checkDotEnvFileExists()
    loadEnvironmentVariables()

    print("SecAware - Currently Work in Progress")

    # sca = SoftwareCompositionAnalysis()
    # sca.getKnownCVEsForAllPackages()

    # dumpJsonToFile("debug/dependencies.json", sca.dependencies)
    # dumpJsonToFile("debug/dependencyGraph.json", sca.dependencyGraph)
    # dumpJsonToFile("debug/dependencyNesting.json", sca.getNestedDependencies())

    # sa = StaticAnalysis()

    aia = GenerativeAIAnalysis()
    aia.vulnerabilityScanForFile(relativeToScriptAbsolutePath("test-data/vuln2.php"))

