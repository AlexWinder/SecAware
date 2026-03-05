#!/usr/bin/env python3

import argparse
import dotenv
import json
import os
import pathlib
import sys
import textwrap

from app.analysis.GenerativeAIAnalysis import GenerativeAIAnalysis, GAIAModelNotAvailableError
from app.analysis.SoftwareCompositionAnalysis import SoftwareCompositionAnalysis, SCAMissingDependencyFilesError, SCAMissingDirectoryError
from app.analysis.StaticAnalysis import StaticAnalysis
from app.cli.ArgparseCustomFormatter import ArgparseCustomFormatter
from app.data.OWASPContext import owaspTop10Context
from app.utils.ConsoleColour import ConsoleColour
from app.utils.GitHelper import GitHelper

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

class SecAware:
    aiModel: str
    aiRestApiBaseUrl: str
    codeFilesForAnalysis: list
    componentGenerativeAIAnalysis: GenerativeAIAnalysis
    componentSoftwareCompositionAnalysis: SoftwareCompositionAnalysis
    componentStaticAnalysis: StaticAnalysis
    dependencyManagementFiles: list
    gitChangedFiles: list
    gitRepoLocalPath: str
    gitRepoRemoteUrl: str
    gitCommitHash: str

    def __init__(self, aiModel, aiRestApiBaseUrl, gitRepoRemoteUrl, gitCommitHash):
        self.aiModel = aiModel
        self.aiRestApiBaseUrl = self.formatBaseUrl(aiRestApiBaseUrl)
        self.gitRepoRemoteUrl = gitRepoRemoteUrl
        self.gitCommitHash = gitCommitHash

        gitPath = pathlib.Path(gitRepoRemoteUrl)
        gitProjectSlug = f"{gitPath.parent.name}/{gitPath.stem}/{gitCommitHash[:7]}"
        self.gitRepoLocalPath = relativeToScriptAbsolutePath(f"git-project-data/{gitProjectSlug}")

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
            dumpJsonToFile("debug/sca.json", self.componentSoftwareCompositionAnalysis.dependencies)
        except SCAMissingDependencyFilesError:
            print(ConsoleColour.toRed("Skipping SCA due to missing dependency files."))
        except SCAMissingDirectoryError:
            print(ConsoleColour.toRed("Skipping SCA due to missing directory path."))

        print(ConsoleColour.toBlue("Static Analysis"))
        self.componentStaticAnalysis = StaticAnalysis(self.gitRepoLocalPath)
        dumpJsonToFile("debug/sa.json", self.componentStaticAnalysis.analysisFindings)

        print(ConsoleColour.toBlue("Generative AI Analysis"))
        try:
            self.componentGenerativeAIAnalysis = GenerativeAIAnalysis(
                baseUrl=self.aiRestApiBaseUrl,
                directoryToScanPath=self.gitRepoLocalPath,
                filesToScan=self.codeFilesForAnalysis,
                model=self.aiModel,
            )
            dumpJsonToFile("debug/ai.json", self.componentGenerativeAIAnalysis.findings)
        except GAIAModelNotAvailableError as e:
            print(ConsoleColour.toRed(str(e)))
            print(ConsoleColour.toRed("Skipping Generative AI Analysis due missing model."))

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
