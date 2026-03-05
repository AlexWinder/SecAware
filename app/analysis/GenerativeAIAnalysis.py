#!/usr/bin/env python3

import json
import os
import re
import requests
import textwrap

from app.data.OWASPContext import owaspTop10Context
from app.utils.ConsoleColour import ConsoleColour

class GenerativeAIAnalysis:
    baseUrl: str
    directoryToScanPath: str
    filesToScan: list
    findings: dict
    model: str

    def __init__(self, baseUrl, model, directoryToScanPath, filesToScan):
        self.baseUrl = baseUrl
        self.directoryToScanPath = directoryToScanPath
        self.filesToScan = filesToScan
        self.findings = {}
        self.model = model
        self.checkApiAccessible()

        print(f"Starting generative AI vulnerability scan for {len(self.filesToScan)} files...")

        for index, file in enumerate(self.filesToScan):
            print(ConsoleColour.toYellow(f"Analysing file {index + 1}/{len(self.filesToScan)}: {file}"))
            self.vulnerabilityScanForFile(file)

    def checkApiAccessible(self):
        response = requests.get(f"{self.baseUrl}/v1/models")

        for model in response.json().get('data', []):
            if model.get('id') == self.model:
                print(f"Successfully connected to AI API and found model {self.model}")
                return
        
        raise GAIAModelNotAvailableError(f"Model {self.model} not found in AI API response. Please ensure the model is correctly loaded in the API and try again.")

    def vulnerabilityScanForFile(self, relativeFilePath):
        absoluteFilePath = os.path.join(self.directoryToScanPath, relativeFilePath)

        if relativeFilePath not in self.findings:
            self.findings[relativeFilePath] = {
                "file": relativeFilePath,
                "vulnerabilities": []
            }

        # We scan several times because AI is non-deterministic
        scanRange = 3
        for i in range(scanRange):
            print(f'Scanning file {relativeFilePath}, iteration {i+1}/{scanRange}...')
            findings = self.initialVulnerabilityScan(absoluteFilePath)

            self.findings[relativeFilePath]["vulnerabilities"].append(findings)
        
        print(f"Aggregating findings for file {relativeFilePath}...")
        aggregated = self.aggregateInitialFindings(
            fileReference=relativeFilePath, 
            filePath=absoluteFilePath
        )
        self.findings[relativeFilePath]["vulnerabilities"] = aggregated

        print(f"Assigning correct CWE and OWASP categories for file {relativeFilePath}...")
        corrected = self.assignCorrectCWEOWASPCategories(
            fileReference=relativeFilePath
        )
        self.findings[relativeFilePath]["vulnerabilities"] = corrected
    
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
            JSON must be fully valid, with no trailing commas and no unescaped characters.
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
            f"{self.baseUrl}/v1/chat/completions", 
            headers={'Content-Type': 'application/json'},
            json=payload
        )

        responseJson = response.json()
        if 'choices' in responseJson:
            aiMessageContent = responseJson['choices'][0]['message']['content']
            
            cleanedResponse = self.cleanUpResponse(aiMessageContent)

            try:
                return json.loads(cleanedResponse)['vulnerabilities']
            except json.JSONDecodeError as e:
                    print(ConsoleColour.toRed("Failed to decode JSON response from AI API."))
                    print(responseJson)

    def cleanUpResponse(self, response):
        # Tidy up the response by removing any markdown code blocks
        cleanedResponse = re.sub(r"^```.*?\n|\n```$", "", response.strip(), flags=re.DOTALL)
        return cleanedResponse

    def aggregateInitialFindings(self, fileReference, filePath):
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
            {self.findings[fileReference]}
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
            f"{self.baseUrl}/v1/chat/completions",
            headers={'Content-Type': 'application/json'},
            json=payload
        )

        responseJson = response.json()
        if 'choices' in responseJson:
            aiMessageContent = responseJson['choices'][0]['message']['content']
            
            cleanedResponse = self.cleanUpResponse(aiMessageContent)

            try:
                return json.loads(cleanedResponse)['vulnerabilities']
            except json.JSONDecodeError as e:
                print(ConsoleColour.toRed("Failed to decode JSON response from AI API."))
                print(responseJson)
                

    def assignCorrectCWEOWASPCategories(self, fileReference):
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
                    "content": json.dumps(self.findings[fileReference])
                }
            ]
        }

        response = requests.post(
            f"{self.baseUrl}/v1/chat/completions",
            headers={'Content-Type': 'application/json'},
            json=payload
        )

        responseJson = response.json()
        if 'choices' in responseJson:
            aiMessageContent = responseJson['choices'][0]['message']['content']
            
            cleanedResponse = self.cleanUpResponse(aiMessageContent)

            try:
                return json.loads(cleanedResponse)['vulnerabilities']
            except json.JSONDecodeError as e:
                print(ConsoleColour.toRed("Failed to decode JSON response from AI API."))
                print(responseJson)

class GAIAModelNotAvailableError(Exception):
    pass