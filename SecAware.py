#!/usr/bin/env python3

import argparse
import dotenv
import json
import os
import pathlib
import requests
import sys
import textwrap
import time

from app.analysis.GenerativeAIAnalysis import GenerativeAIAnalysis, GAIAModelNotAvailableError
from app.analysis.SoftwareCompositionAnalysis import SoftwareCompositionAnalysis, SCAMissingDependencyFilesError, SCAMissingDirectoryError
from app.analysis.StaticAnalysis import StaticAnalysis
from app.cli.ArgparseCustomFormatter import ArgparseCustomFormatter
from app.data.OWASPContext import owaspTop10Context
from app.utils.AIRestAPI import AIRestAPI
from app.utils.ConsoleColour import ConsoleColour
from app.utils.GitHelper import GitHelper

def relativeToScriptAbsolutePath(relativePath):
    return os.path.normpath(
        os.path.join(os.path.dirname(__file__), relativePath)
    )

def dumpJson(data):
    print(json.dumps(data, indent=2))

def dumpJsonToFile(filename, data):
    filename = pathlib.Path(relativeToScriptAbsolutePath(filename))
    filename.parent.mkdir(parents=True, exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

class SecAware:
    aiModel: str
    aiRestApiBaseUrl: str
    codeFilesForAnalysis: list
    combinedVulnerabilityFindings: dict
    componentGenerativeAIAnalysis: GenerativeAIAnalysis
    componentSoftwareCompositionAnalysis: SoftwareCompositionAnalysis
    componentStaticAnalysis: StaticAnalysis
    dependencyManagementFiles: list
    gitChangedFiles: list
    gitRepoLocalPath: str
    gitRepoRemoteUrl: str
    gitCommitHash: str
    reportPath: str
    startTime: str

    def __init__(self, aiModel, aiRestApiBaseUrl, gitRepoRemoteUrl, gitCommitHash):
        self.aiModel = aiModel
        self.aiRestApiBaseUrl = self.formatBaseUrl(aiRestApiBaseUrl)
        self.gitRepoRemoteUrl = gitRepoRemoteUrl
        self.gitCommitHash = gitCommitHash
        self.startTime = time.perf_counter()

        gitPath = pathlib.Path(gitRepoRemoteUrl)
        gitProjectSlug = f"{gitPath.parent.name}/{gitPath.stem}/{gitCommitHash[:7]}"
        self.gitRepoLocalPath = relativeToScriptAbsolutePath(f"git-project-data/{gitProjectSlug}")

        self.reportPath = relativeToScriptAbsolutePath(f"reports/{gitPath.parent.name}-{gitPath.stem}-{gitCommitHash[:7]}")

        self.checkDotEnvFileExists()
        self.loadEnvironmentVariables()
        
        print(ConsoleColour.toYellow("Preparing Git Repository for Analysis"))
        GitHelper.shallowClone(self.gitRepoLocalPath, self.gitRepoRemoteUrl, self.gitCommitHash)
        self.gitChangedFiles = GitHelper.diffFiles(self.gitRepoLocalPath, self.gitCommitHash)

        print(ConsoleColour.toYellow("Detecting Files for Analysis"))
        self.codeFilesForAnalysis = self.identifySuitableFilesForAnalysis(self.gitChangedFiles)
        self.dependencyManagementFiles = self.detectDependencyManagementFiles(self.gitRepoLocalPath)
        print(f"Identified {len(self.codeFilesForAnalysis)} code files for vulnerability analysis.\n")

        print(ConsoleColour.toBlue("Software Composition Analysis (SCA)"))
        try:
            self.componentSoftwareCompositionAnalysis = SoftwareCompositionAnalysis(directoryPath=self.gitRepoLocalPath)
            dumpJsonToFile(f"{self.reportPath}/sca.json", self.componentSoftwareCompositionAnalysis.dependencies)
        except SCAMissingDependencyFilesError:
            print(ConsoleColour.toRed("Skipping SCA due to missing dependency files."))
        except SCAMissingDirectoryError:
            print(ConsoleColour.toRed("Skipping SCA due to missing directory path."))

        print(ConsoleColour.toBlue("Static Analysis"))
        self.componentStaticAnalysis = StaticAnalysis(self.gitRepoLocalPath)
        dumpJsonToFile(f"{self.reportPath}/sa.json", self.componentStaticAnalysis.analysisFindings)

        print(ConsoleColour.toBlue("Generative AI Analysis"))
        try:
            self.componentGenerativeAIAnalysis = GenerativeAIAnalysis(
                baseUrl=self.aiRestApiBaseUrl,
                directoryToScanPath=self.gitRepoLocalPath,
                filesToScan=self.codeFilesForAnalysis,
                model=self.aiModel,
            )
            dumpJsonToFile(f"{self.reportPath}/ai.json", self.componentGenerativeAIAnalysis.findings)
        except GAIAModelNotAvailableError as e:
            print(ConsoleColour.toRed(str(e)))
            print(ConsoleColour.toRed("Skipping Generative AI Analysis due missing model."))

        self.combinedVulnerabilityFindings = self.combineRelevantFindings()
        dumpJsonToFile(f"{self.reportPath}/combined_findings.json", self.combinedVulnerabilityFindings)
        self.produceContextualisedReport()

        self.printConsoleSummary()

    def errorMessage(self, message):
        ConsoleColour.toRed(message)
        sys.exit(1)

    def checkDotEnvFileExists(self):
        if not os.path.exists(".env"):
            self.errorMessage(".env file not found. Please create a .env file based on the .env.example file and add the required environment variables.")

    def loadEnvironmentVariables(self):
        dotenv.load_dotenv()
        existingVars = ["AI_API_BEARER_TOKEN"]
        for var in existingVars:
            if var not in os.environ:
                self.errorMessage(f"{var} environment variable not set within .env file")

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

    def stripBackFilePath(self, stripPath, filePath):
        if filePath.startswith(stripPath):
            return filePath[len(stripPath):].lstrip('/\\')
        return filePath

    def combineRelevantFindings(self):
        aggregatedFindings = {}

        for finding in self.componentStaticAnalysis.analysisFindings:
            filePath = self.stripBackFilePath(self.gitRepoLocalPath, finding.get('file_path', ''))

            if filePath not in aggregatedFindings:
                aggregatedFindings[filePath] = {
                    'staticAnalysis': [],
                    'generativeAIAnalysis': []
                }

            findingEntry = {
                'filePath': filePath,
                'type': finding.get('type'),
                'message': finding.get('message'),
                'lineFrom': finding.get('line_from'),
                'lineTo': finding.get('line_to'),
                'selectedText': finding.get('selected_text'),
            }
            
            trace = []

            for taintTrace in finding.get('taint_trace', []):
                trace.append({
                    'filePath': self.stripBackFilePath(self.gitRepoLocalPath, taintTrace.get('file_path', '')),
                    'label': taintTrace.get('label'),
                    'snippet': taintTrace.get('snippet'),
                    'lineFrom': taintTrace.get('line_from'),
                    'lineTo': taintTrace.get('line_to'),
                })
            
            findingEntry['trace'] = trace
            
            aggregatedFindings[filePath]['staticAnalysis'].append(findingEntry)
        
        for filePath, finding in self.componentGenerativeAIAnalysis.findings.items():
            vulnerabilities = finding.get('vulnerabilities', [])

            # Ignore missing vulnerabilities
            if not vulnerabilities:
                continue

            if filePath not in aggregatedFindings:
                aggregatedFindings[filePath] = {
                    'staticAnalysis': [],
                    'generativeAIAnalysis': []
                }

            for vulnerability in finding.get('vulnerabilities', []):
                # Combine all of the confidence scores into an average
                if 'confidences' in vulnerability:
                    confidenceScores = vulnerability['confidences']
                    averageConfidence = sum(confidenceScores.values()) / len(confidenceScores)

                findingEntry = {
                    'description': vulnerability.get('description'),
                    'line': vulnerability.get('line'),
                    'justification': vulnerability.get('justification'),
                    'fix': vulnerability.get('fix'),
                    'owaspCategories': vulnerability.get('owasp_categories', []),
                    'cweIds': vulnerability.get('cwe_ids', []),
                    'confidence': averageConfidence if 'confidences' in vulnerability else 0
                }

                aggregatedFindings[filePath]['generativeAIAnalysis'].append(findingEntry)

        return aggregatedFindings
    
    def produceContextualisedReport(self):
        systemPrompt = textwrap.dedent("""\
            You are a cybersecurity analyst assistant, specialised in vulnerability assessment.
            Your task is to produce a contextualised vulnerability report for a software project based on initial vulnerability findings from both static analysis and generative AI analysis.
            
            You may find conflicting or duplicated findings between the two sources. Your task is to synthesise the information and provide clear but concise insights on the findings.
                                       
            You will be presented with the contents of the files, along with the findings, and you should use this information to produce an accurate report.
            
            The report should be produced in markdown and should be contain the following headings, with the following contents:
            - SUMMARY = Brief summary of the overall security posture of the project based on the findings.
            - FINDINGS = Findings for each file should be provided with the following details:
                - RISK SCORE = A risk score for the vulnerability
                - LOCATION = The vulnerable code snippet.
                - DESCRIPTION = A brief description of the vulnerability, including the type of vulnerability.
                - CATEGORY = An appropriate category against OWASP Top 10 and/or CWE, where possible.
                - JUSTIFICATION = A justification of why the code is vulnerable, based on the evidence from the findings.
                - REMEDIATION = Suggested fix(es) or remediation(s) for the vulnerability.
            - GLOSSARY = A glossary of any technical terms should be provided, with clear and concise definitions.
                                       
            When allocating to OWASP/CWE categories, ensure to give a URL directly to the relevant category page on OWASP. Ensure that any CWE ID used is accurate and corresponds to the OWASP category. The below list of OWASP and CWE IDs are authoritative. These should be use as the source of truth. If the findings are categorised differently against this list then you should classify it as "Uncategorised":
        """)

        for item in owaspTop10Context:
            systemPrompt += f"- {item['id']} {item['name']} ({item['url']}):\n"

            for cwe in item.get('cwe_ids', []):
                systemPrompt += f"  - {cwe['id']} {cwe['name']}\n"

        userPrompt = ''

        for filePath in self.combinedVulnerabilityFindings:
            findings = self.combinedVulnerabilityFindings[filePath]

            userPrompt += textwrap.dedent(f"""\
                ==========
                File Path: {filePath}

                File Contents:
                ```php
                {pathlib.Path(os.path.join(self.gitRepoLocalPath, filePath)).read_text(encoding='utf-8')}
                ```

                Static Analysis Findings:
                ```json
                {json.dumps(findings.get('staticAnalysis', []))}
                ```

                Generative AI Analysis Findings:
                ```json
                {json.dumps(findings.get('generativeAIAnalysis', []))}
                ```
                ==========                      
            """)

        response = requests.post(
            f"{self.aiRestApiBaseUrl}/v1/chat/completions", 
            headers=AIRestAPI.buildRequestHeaders(),
            json=AIRestAPI.buildConversationPayload(self.aiModel, systemPrompt, userPrompt)
        )

        responseJson = response.json()
        if 'choices' in responseJson:
            aiMessageContent = responseJson['choices'][0]['message']['content']

            print(aiMessageContent)

    def printConsoleSummary(self):
        print("\n")

        print(ConsoleColour.toGreen("Summary of Findings"))
        print('├── Git Repository: ' + ConsoleColour.toBlue(self.gitRepoRemoteUrl))
        print('├── Git Commit: ' + ConsoleColour.toBlue(self.gitCommitHash))
        print('├── Total Suitable Files Changed: ' + ConsoleColour.toBlue(str(len(self.codeFilesForAnalysis))))
        print('├── AI Model: ' + ConsoleColour.toBlue(self.aiModel))
        print('├── AI REST API Base URL: ' + ConsoleColour.toBlue(self.aiRestApiBaseUrl))
        print("└── Analysis Time: " + ConsoleColour.toBlue(f"{time.perf_counter() - self.startTime:.2f} seconds"))
        print("\n")

        print(ConsoleColour.toYellow('Software Composition Analysis (SCA)'))
        if hasattr(self, 'componentSoftwareCompositionAnalysis') and isinstance(self.componentSoftwareCompositionAnalysis, SoftwareCompositionAnalysis):
            print('├── Total Dependencies Detected: ' + ConsoleColour.toBlue(str(len(self.componentSoftwareCompositionAnalysis.dependencies))))
            scaVulnerabilityCount = 0
            for depInfo in self.componentSoftwareCompositionAnalysis.dependencies.values():
                vulnerabilities = depInfo.get('vulnerabilities', {})
                scaVulnerabilityCount += len(vulnerabilities)

            simulated = self.componentSoftwareCompositionAnalysis.isSimulatedLockData
            treeSymbol = "└── "
            if simulated:
                treeSymbol = "├── "
            
            print(f"{treeSymbol}Total Dependency CVEs Detected: " + ConsoleColour.toBlue(str(scaVulnerabilityCount)))

            if simulated:
                print("└── " + ConsoleColour.toRed('Notice! Simulated lock data used. CVE results are likely inaccurate.'))
        else:
            print(ConsoleColour.toRed("└── SCA not performed."))
        print("\n")

        print(ConsoleColour.toYellow('Static Analysis'))
        if hasattr(self, 'componentStaticAnalysis') and isinstance(self.componentStaticAnalysis, StaticAnalysis):
            print('└── Total Static Analysis Findings Detected: ' + ConsoleColour.toBlue(str(len(self.componentStaticAnalysis.analysisFindings))))
        else:
            print(ConsoleColour.toRed("└── Static Analysis not performed."))
        print("\n")

        print(ConsoleColour.toYellow('Generative AI Analysis'))
        if hasattr(self, 'componentGenerativeAIAnalysis') and isinstance(self.componentGenerativeAIAnalysis, GenerativeAIAnalysis):
            aiVulnerabilityCount = 0
            for finding in self.componentGenerativeAIAnalysis.findings.values():
                aiVulnerabilityCount += len(finding.get('vulnerabilities') or [])
            print('└── Total AI Analysis Vulnerabilities Detected: ' + ConsoleColour.toBlue(str(aiVulnerabilityCount)))
        else:
            print(ConsoleColour.toRed("└── Generative AI Analysis not performed."))

if __name__ == '__main__':

    print(ConsoleColour.toGreen("SecAware - A Context-Aware Software Vulnerability Detection Tool") + "\n")

    description = textwrap.dedent("""\
        SecAware is a context-aware software vulnerability detection tool. It combines traditional software composition analysis and static analysis techniques with generative AI capability to provide comprehensive vulnerability detection for software applications.
    """)

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=ArgparseCustomFormatter
    )
    parser.add_argument('--ai-rest-base-url', type=str, default='http://host.docker.internal:1234', help='The base URL for the generative AI REST API. For example, if using LM Studio locally, this might be http://host.docker.internal:1234, if using the Hugging Face proxy this would be https://router.huggingface.co. Any endpoint that is compatible with the OpenAI OpenAPI schema (https://github.com/openai/openai-openapi).')
    parser.add_argument('--ai-model', type=str, default='google/gemma-3-4b', help='The generative AI model to use.')
    # Default values are a known vulnerability
    # https://github.com/advisories/GHSA-4xf2-7qfv-mgfx
    parser.add_argument('--git-repo-url', type=str, default='https://github.com/in2code-de/ipandlanguageredirect.git', help='The Git repository HTTP URL to scan.')
    parser.add_argument('--git-commit-hash', type=str, default='b814ae1bc545187f924734c1f3ee0999153264ae', help='The specific Git commit hash to use for the scan.')

    args = parser.parse_args()

    secAware = SecAware(
        aiModel=args.ai_model,
        aiRestApiBaseUrl=args.ai_rest_base_url,
        gitRepoRemoteUrl=args.git_repo_url,
        gitCommitHash=args.git_commit_hash
    )
