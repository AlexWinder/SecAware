#!/usr/bin/env python3

import argparse
import datetime
import dotenv
import json
import logging
import os
import pathlib
import requests
import sys
import textwrap
import time
import tomllib

from app.analysis.GenerativeAIAnalysis import GenerativeAIAnalysis
from app.analysis.SoftwareCompositionAnalysis import SoftwareCompositionAnalysis, SCAMissingDependencyFilesError, SCAMissingDirectoryError
from app.analysis.StaticAnalysis import StaticAnalysis
from app.cli.ArgparseCustomFormatter import ArgparseCustomFormatter
from app.data.OWASPContext import owaspTop10Context
from app.utils.AIRestAPI import AIRestAPI
from app.utils.ConsoleColour import ConsoleColour
from app.utils.GitHelper import GitHelper

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
    loggers: dict
    reportPath: str
    startTime: str
    warnIfFilesChangedExceedCount: int

    def __init__(
            self, aiModel, aiRestApiBaseUrl, gitRepoRemoteUrl, gitCommitHash, scaAllowedSPDXLicenses=[], scaOverallCommitMinimumActivityDays=None,
            scaMaintainerCommitMinimumActivityDays=None, scaOpenToClosedIssueRadioThreshold=None, scaMinimumVersionAge=None, warnIfFilesChangedExceedCount=None
        ):
        gitPath = pathlib.Path(gitRepoRemoteUrl)
        gitProjectSlug = f"{gitPath.parent.name}/{gitPath.stem}/{gitCommitHash[:7]}"
        self.gitRepoLocalPath = SecAware.relativeToScriptAbsolutePath(f"git-project-data/{gitProjectSlug}")

        self.reportPath = SecAware.relativeToScriptAbsolutePath(f"reports/{gitPath.parent.name}-{gitPath.stem}-{gitCommitHash[:7]}")
        self.configureLogging(logPath=f"{self.reportPath}/secaware.log")
        self.loggers = {
            'secAware': logging.getLogger('SecAware'),
            'generativeAIAnalysis': logging.getLogger('SecAware.GAIA'),
            'softwareCompositionAnalysis': logging.getLogger('SecAware.SCA'),
            'staticAnalysis': logging.getLogger('SecAware.SA'),
        }

        logger = self.loggers['secAware']

        logger.info(ConsoleColour.toYellow("Initialising SecAware"))
        
        self.aiModel = aiModel
        self.aiRestApiBaseUrl = self.formatBaseUrl(aiRestApiBaseUrl)
        self.gitRepoRemoteUrl = gitRepoRemoteUrl
        self.gitCommitHash = gitCommitHash
        self.startTime = time.perf_counter()
        self.warnIfFilesChangedExceedCount = warnIfFilesChangedExceedCount

        logger.debug(f"AI Model: {self.aiModel}")
        logger.debug(f"AI REST API Base URL: {self.aiRestApiBaseUrl}")
        logger.debug(f"Git Repo URL: {self.gitRepoRemoteUrl}")
        logger.debug(f"Git Commit Hash: {self.gitCommitHash}")
        logger.debug(f"Start Time: {self.startTime}")
        logger.debug(f"Warning Threshold for Files Changed: {self.warnIfFilesChangedExceedCount}")

        self.checkDotEnvFileExists()
        self.loadEnvironmentVariables()
        
        logger.info(ConsoleColour.toYellow("Preparing Git Repository for Analysis"))
        GitHelper.shallowClone(self.gitRepoLocalPath, self.gitRepoRemoteUrl, self.gitCommitHash, logger=logger)
        self.gitChangedFiles = GitHelper.diffFiles(self.gitRepoLocalPath, self.gitCommitHash)

        logger.info(ConsoleColour.toYellow("Detecting Files for Analysis"))
        self.codeFilesForAnalysis = self.identifySuitableFilesForAnalysis(self.gitChangedFiles)
        self.dependencyManagementFiles = self.detectDependencyManagementFiles(self.gitRepoLocalPath)
        logger.info(f"Identified {len(self.codeFilesForAnalysis)} code files for vulnerability analysis.")
        logger.debug(self.codeFilesForAnalysis)

        logger.info(ConsoleColour.toBlue("Software Composition Analysis (SCA)"))
        try:
            self.componentSoftwareCompositionAnalysis = SoftwareCompositionAnalysis(
                logger=self.loggers['softwareCompositionAnalysis'],
                cacheDirectoryPath=SecAware.relativeToScriptAbsolutePath("git-cache"),
                gitProjectDirectoryPath=self.gitRepoLocalPath,
                allowedSPDXLicenses=scaAllowedSPDXLicenses,
                overallCommitMinimumActivityDays=scaOverallCommitMinimumActivityDays,
                maintainerCommitMinimumActivityDays=scaMaintainerCommitMinimumActivityDays,
                openToClosedIssueRatioThreshold=scaOpenToClosedIssueRadioThreshold,
                minimumVersionAge=scaMinimumVersionAge,
                gitProjectName= f"{gitPath.parent.name}/{gitPath.stem}",
                gitCommitHash=gitCommitHash
            )
            scaJsonPath = f"{self.reportPath}/analysisFindingsSCA.json"
            logger.info(f"Dumping SCA results to {scaJsonPath}.")
            SecAware.dumpJsonToFile(scaJsonPath, self.componentSoftwareCompositionAnalysis.dependencies)
            logger.debug(self.componentSoftwareCompositionAnalysis.dependencies)

            scaReportPath = f"{self.reportPath}/reportSCA.md"
            logger.info(f"Dumping SCA report to {scaReportPath}.")
            with open(scaReportPath, 'w', encoding='utf-8') as f:
                f.write("\n" + "\n".join(self.componentSoftwareCompositionAnalysis.reportContents))
            logger.debug(self.componentSoftwareCompositionAnalysis.reportContents)
        except SCAMissingDependencyFilesError:
            logger.critical(ConsoleColour.toRed("Skipping SCA due to missing dependency files."))
        except SCAMissingDirectoryError:
            logger.critical(ConsoleColour.toRed("Skipping SCA due to missing directory path."))

        logger.info(ConsoleColour.toBlue("Static Analysis"))
        self.componentStaticAnalysis = StaticAnalysis(self.gitRepoLocalPath, logger=self.loggers['staticAnalysis'])
        saJsonPath = f"{self.reportPath}/analysisFindingsSA.json"
        logger.info(f"Dumping Static Analysis results to {saJsonPath}.")
        SecAware.dumpJsonToFile(saJsonPath, self.componentStaticAnalysis.analysisFindings)
        logger.debug(self.componentStaticAnalysis.analysisFindings)

        logger.info(ConsoleColour.toBlue("Generative AI Analysis"))
        try:
            self.componentGenerativeAIAnalysis = GenerativeAIAnalysis(
                baseUrl=self.aiRestApiBaseUrl,
                directoryToScanPath=self.gitRepoLocalPath,
                filesToScan=self.codeFilesForAnalysis,
                model=self.aiModel,
                logger=self.loggers['generativeAIAnalysis']
            )
            aiJsonPath = f"{self.reportPath}/analysisFindingsGAIA.json"
            logger.info(f"Dumping Generative AI Analysis results to {aiJsonPath}.")
            SecAware.dumpJsonToFile(aiJsonPath, self.componentGenerativeAIAnalysis.findings)
            logger.debug(self.componentGenerativeAIAnalysis.findings)
        except ConnectionError as e:
            logger.critical(ConsoleColour.toRed(str(e)))
            logger.critical(ConsoleColour.toRed("Skipping Generative AI Analysis due to connection error to AI API."))

        self.combinedVulnerabilityFindings = self.combineRelevantFindings()
        combinedFindingsJsonPath = f"{self.reportPath}/analysisFindingsSAPlusGAIACombined.json"
        logger.info(f"Dumping combined vulnerability findings to {combinedFindingsJsonPath}.")
        SecAware.dumpJsonToFile(combinedFindingsJsonPath, self.combinedVulnerabilityFindings)

        logger.info(ConsoleColour.toYellow("Producing Contextualised Vulnerability Report"))
        vulnerabilityReport = self.produceContextualisedReport()
        reportPath = f"{self.reportPath}/reportVulnerabilities.md"
        logger.info(f"Dumping vulnerability report to {reportPath}.")
        with open(reportPath, 'w', encoding='utf-8') as f:
            f.write(vulnerabilityReport)
        logger.debug(vulnerabilityReport)

        executionReport = self.produceExecutionReport()

        # Produce the final report
        with open(f"{self.reportPath}/SecAwareFindingsReport.md", 'w', encoding='utf-8') as f:
            for line in executionReport:
                f.write(line + "\n")

            f.write(vulnerabilityReport + "\n\n")
            
            for line in self.componentSoftwareCompositionAnalysis.reportContents:
                f.write(line + "\n")

        logger.info(ConsoleColour.toGreen("SecAware analysis complete. Final report generated at " + f"{self.reportPath}/SecAwareFindingsReport.md"))

    def errorMessage(self, message):
        self.loggers['secAware'].critical(ConsoleColour.toRed(message))
        sys.exit(1)

    def checkDotEnvFileExists(self):
        if not os.path.exists(".env"):
            self.errorMessage(".env file not found. Please create a .env file based on the .env.example file and add the required environment variables.")

    def loadEnvironmentVariables(self):
        dotenv.load_dotenv()
        existingVars = ["AI_API_BEARER_TOKEN", "GITHUB_API_BEARER_TOKEN"]
        for var in existingVars:
            if var not in os.environ:
                self.errorMessage(f"{var} environment variable not set within .env file")

    def formatBaseUrl(self, url):
        return url.rstrip('/')
    
    def configureLogging(self, logPath):
        if not os.path.exists(os.path.dirname(logPath)):
            os.makedirs(os.path.dirname(logPath), exist_ok=True)

        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s %(name)-14s %(levelname)-8s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=logPath,
            filemode='w'
        )
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(name)-14s: %(levelname)-8s %(message)s')
        console.setFormatter(formatter)
        logging.getLogger().addHandler(console)

        logging.debug("Logging configured. Log file: " + logPath)
    
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
        self.loggers['secAware'].info("Combining findings from Static Analysis and Generative AI Analysis.")
        aggregatedFindings = {}

        if not hasattr(self, 'componentStaticAnalysis') or not isinstance(self.componentStaticAnalysis, StaticAnalysis):
            filePath = f"{self.reportPath}/analysisFindingsSA.json"
            with open(filePath, 'r', encoding='utf-8') as f:
                findingsSA = json.load(f)
        else:
            findingsSA = self.componentStaticAnalysis.analysisFindings

        for finding in findingsSA:
            filePath = self.stripBackFilePath(self.gitRepoLocalPath, finding.get('file_path', ''))

            # We only want to include findings for files that were in the commit diff
            if filePath not in self.gitChangedFiles:
                continue

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

        if not hasattr(self, 'componentGenerativeAIAnalysis') or not isinstance(self.componentGenerativeAIAnalysis, GenerativeAIAnalysis):
            filePath = f"{self.reportPath}/analysisFindingsGAIA.json"
            with open(filePath, 'r', encoding='utf-8') as f:
                findingsGAIA = json.load(f).items()
        else:
            findingsGAIA = self.componentGenerativeAIAnalysis.findings.items()
        
        for filePath, finding in findingsGAIA:
            vulnerabilities = finding.get('vulnerabilities', [])

            # Ignore missing vulnerabilities
            if not vulnerabilities:
                continue

            # We only want to include findings for files that were in the commit diff
            if filePath not in self.gitChangedFiles:
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
        # We need to have at least one vulnerability finding to produce a report
        if not self.combinedVulnerabilityFindings:
            return "# Vulnerability Report\n\nNo vulnerabilities were found in the analysis."
        
        systemPrompt = textwrap.dedent("""\
            You are a cybersecurity analyst assistant, specialised in vulnerability assessment
                                       
            Your task is to produce a clear, concise, and structured vulnerability report based on provided findings from static analysis and generative AI analysis.

            You may encounter duplicate or conflicting findings. You must:
            - Merge duplicate findings referring to the same code snippet and vulnerability.
            - Resolve conflicts by prioritising the most strongly supported finding.
            - Reflect uncertainty through wording and risk score where appropriate.
            
            Additional Rules:
            - Under no circumstances should you fabricate findings. Only report what is provided by the evidence.
            - If there are no vulnerabilities at all, simply state that no vulnerabilities were found.
                                       
            OUTPUT FORMAT (STRICT MARKDOWN):
                                       
            # Vulnerability Report
            Provide a brief high-level assessment of the overall security posture of the project.
            
            ## Findings
            For each unique vulnerability, use the following structure:
            
            ### File Path: [File path]
            - Risk Score: [0-10] ([Low [0-3]/Medium [4-6]/High [7-10]])
            - Location: [Exact vulnerable code snippet]
            - Description: [Clear description of the vulnerability and type]
            - Category: [OWASP Top 10 Category Name(s)] ([OWASP URL])
            - CWE ID(s): [CWE ID(s) if applicable]
            - Justification: [Concise justification for why the code is vulnerable, based strictly on evidence]
            - Remediation: [Suggested fix or remediation for the vulnerability, providing code examples where possible]
                                       
            Notes for findings:
            - Do not duplicate the same vulnerability across findings.
            - Each finding must correspond to a unique issue.
                                       
            ## Glossary
            Provide concise definitions for any technical terms used in the report.
                                       
            CLASSIFICATION RULES:
            - Use the OWASP Top 10 categories and CWE mappings below as the authoritative source.
            - If a finding does not match any category, label it as "Uncategorised".
            - Ensure CWE IDs are accurate and consistent with the OWASP category.
            - Always include the OWASP URL when assigning a category.
            
        """)

        for item in owaspTop10Context:
            systemPrompt += f"- {item['id']} {item['name']} ({item['url']}):\n"

            for cwe in item.get('cwe_ids', []):
                systemPrompt += f"  - {cwe['id']} {cwe['name']}\n"

        userMessages = []

        for filePath in self.combinedVulnerabilityFindings:
            findings = self.combinedVulnerabilityFindings[filePath]

            fileContent = pathlib.Path(
                os.path.join(self.gitRepoLocalPath, filePath)
            ).read_text(encoding='utf-8')

            userMessages.append(textwrap.dedent(f"""\
                FILE: {filePath}

                SOURCE CODE:
                {fileContent}

                STATIC ANALYSIS FINDINGS (JSON):
                {json.dumps(findings.get('staticAnalysis', []))}

                GENERATIVE AI ANALYSIS FINDINGS (JSON):
                {json.dumps(findings.get('generativeAIAnalysis', []))}
            """))

        payload = AIRestAPI.buildConversationPayload(self.aiModel, systemPrompt, userMessages)
        self.loggers['secAware'].debug(payload)

        response = requests.post(
            f"{self.aiRestApiBaseUrl}/v1/chat/completions", 
            headers=AIRestAPI.buildRequestHeaders(),
            json=payload
        )

        responseJson = response.json()
        self.loggers['secAware'].debug(responseJson)
        if response.status_code == 200 and 'choices' in responseJson:
            return responseJson['choices'][0]['message']['content']

    def produceExecutionReport(self):
        self.loggers['secAware'].debug("Execution Report")

        summary = []

        summary.append(f"# SecAware Analysis Report")
        summary.append(f"")

        if len(self.gitChangedFiles) > self.warnIfFilesChangedExceedCount:
            summary.append(f"**Warning: `{len(self.gitChangedFiles)}` files changed in this commit, which exceeds the warning threshold of `{self.warnIfFilesChangedExceedCount}`. Large changes are more likely to contain vulnerabilities, but may also produce more false positives, or be more difficult to analyse effectively.**")
            summary.append(f"")

        summary.append(f"# Summary of Execution")
        summary.append(f"- SecAware Version: {self.loadPyProjectToml()['project']['version']}")
        summary.append(f"- Generation Date: {datetime.datetime.now().isoformat()}")
        summary.append(f"- Git Repository: `{self.gitRepoRemoteUrl}`")
        summary.append(f"- Git Commit: `{self.gitCommitHash}`")
        summary.append(f"- Total PHP Files Changed Within Commit: `{str(len(self.codeFilesForAnalysis))}`")
        summary.append(f"- AI Model: `{self.aiModel}`")
        summary.append(f"- AI REST API Base URL: `{self.aiRestApiBaseUrl}`")
        summary.append(f"- Warning Threshold for Changed Files: `{self.warnIfFilesChangedExceedCount}` files")
        summary.append(f"- Analysis Time: `{time.perf_counter() - self.startTime:.2f}` seconds")
        summary.append(f"")

        summary.append(f"## Software Composition Analysis (SCA)")
        if hasattr(self, 'componentSoftwareCompositionAnalysis') and isinstance(self.componentSoftwareCompositionAnalysis, SoftwareCompositionAnalysis):
            summary.append(f"- Total Dependencies Detected: `{str(len(self.componentSoftwareCompositionAnalysis.dependencies))}`")
            scaVulnerabilityCount = 0
            scaWeakLinkCount = 0
            for depInfo in self.componentSoftwareCompositionAnalysis.dependencies.values():
                vulnerabilities = depInfo.get('vulnerabilities', {})
                weakLinks = depInfo.get('weakLinks', [])
                scaVulnerabilityCount += len(vulnerabilities)
                scaWeakLinkCount += len(weakLinks)

            simulated = self.componentSoftwareCompositionAnalysis.isSimulatedLockData
            summary.append(f"- Total Dependency CVEs Detected: `{str(scaVulnerabilityCount)}`")
            summary.append(f"- Total Dependency Weak Links Detected: `{str(scaWeakLinkCount)}`")

            if simulated:
                summary.append(f"- **Notice! Simulated lock data used. CVE results are likely inaccurate.**")

            summary.append(f"- SCA Analysis Parameters:")
            summary.append(f"   - Allowed SPDX Licenses: `{', '.join(self.componentSoftwareCompositionAnalysis.userDefinedThresholds['allowedSPDXLicenses']) if self.componentSoftwareCompositionAnalysis.userDefinedThresholds['allowedSPDXLicenses'] else 'None'}`")
            summary.append(f"   - Overall Commit Minimum Activity Days: `{self.componentSoftwareCompositionAnalysis.userDefinedThresholds['overallCommitMinimumActivityDays']}`")
            summary.append(f"   - Maintainer Commit Minimum Activity Days: `{self.componentSoftwareCompositionAnalysis.userDefinedThresholds['maintainerCommitMinimumActivityDays']}`")
            summary.append(f"   - Open to Closed Issue Ratio Threshold: `{self.componentSoftwareCompositionAnalysis.userDefinedThresholds['openToClosedIssueRatioThreshold']}`")
            summary.append(f"   - Minimum Version Age (days): `{self.componentSoftwareCompositionAnalysis.userDefinedThresholds['minimumVersionAge']}`")
        else:
            summary.append(f"- SCA not performed.")
        summary.append(f"")

        summary.append(f"## Static Analysis")
        if hasattr(self, 'componentStaticAnalysis') and isinstance(self.componentStaticAnalysis, StaticAnalysis):
            relevantFindings = 0
            for finding in self.componentStaticAnalysis.analysisFindings:
                filePath = self.stripBackFilePath(self.gitRepoLocalPath, finding.get('file_path', ''))

                # We only want to include findings for files that were in the commit diff
                if filePath in self.gitChangedFiles:
                    relevantFindings += 1

            summary.append(f"- Total Static Analysis Findings Detected: `{str(relevantFindings)}`")
        else:
            summary.append(f"- Static Analysis not performed.")
        summary.append(f"")

        summary.append(f"## Generative AI Analysis")
        if hasattr(self, 'componentGenerativeAIAnalysis') and isinstance(self.componentGenerativeAIAnalysis, GenerativeAIAnalysis):
            aiVulnerabilityCount = 0
            for finding in self.componentGenerativeAIAnalysis.findings.values():
                aiVulnerabilityCount += len(finding.get('vulnerabilities') or [])
            summary.append(f"- Total AI Analysis Vulnerabilities Detected: `{str(aiVulnerabilityCount)}`")
        else:
            summary.append(f"- Generative AI Analysis not performed.")
        summary.append(f"")
        
        self.loggers['secAware'].info("\n" + "\n".join(summary))

        return summary

    @staticmethod
    def relativeToScriptAbsolutePath(relativePath):
        return os.path.normpath(
            os.path.join(os.path.dirname(__file__), relativePath)
        )

    @staticmethod
    def dumpJson(data):
        print(json.dumps(data, indent=2))

    @staticmethod
    def dumpJsonToFile(filename, data):
        filename = pathlib.Path(SecAware.relativeToScriptAbsolutePath(filename))
        filename.parent.mkdir(parents=True, exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def loadPyProjectToml():
        with(open(SecAware.relativeToScriptAbsolutePath("pyproject.toml"), 'rb')) as f:
            return tomllib.load(f)

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
    parser.add_argument('--sca-allowed-spdx-licenses', nargs='+', default=[], help='(SCA) Allow-list of SPDX licenses for dependencies. See https://spdx.org/licenses/ for available license identifiers.')
    parser.add_argument('--sca-overall-commit-minimum-activity-days', type=int, default=1, help='(SCA) Minimum number of days required for general commit activity.')
    parser.add_argument('--sca-maintainer-commit-minimum-activity-days', type=int, default=1, help='(SCA) Minimum number of days required for maintainer commit activity.')
    parser.add_argument('--sca-open-to-closed-issue-radio-threshold', type=float, default=0.01, help='(SCA) Threshold for open to closed issue ratio.')
    parser.add_argument('--sca-minimum-version-age', type=int, default=3650, help='(SCA) Minimum number of days old that a version must be.')
    parser.add_argument('--warn-if-files-changed-exceed', type=int, default=1, help='Warning threshold for number of files changed in the commit. Large changes are more likely to contain vulnerabilities, but may also produce more false positives, or be more difficult to analyse effectively.')

    args = parser.parse_args()

    secAware = SecAware(
        aiModel=args.ai_model,
        aiRestApiBaseUrl=args.ai_rest_base_url,
        gitRepoRemoteUrl=args.git_repo_url,
        gitCommitHash=args.git_commit_hash,
        scaAllowedSPDXLicenses=args.sca_allowed_spdx_licenses,
        scaOverallCommitMinimumActivityDays=args.sca_overall_commit_minimum_activity_days,
        scaMaintainerCommitMinimumActivityDays=args.sca_maintainer_commit_minimum_activity_days,
        scaOpenToClosedIssueRadioThreshold=args.sca_open_to_closed_issue_radio_threshold,
        scaMinimumVersionAge=args.sca_minimum_version_age,
        warnIfFilesChangedExceedCount=args.warn_if_files_changed_exceed
    )
