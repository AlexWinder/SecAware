#!/usr/bin/env python3

import json
import os
import re
import requests
import textwrap

from app.data.OWASPContext import owaspTop10Context
from app.utils.AIRestAPI import AIRestAPI
from app.utils.ConsoleColour import ConsoleColour

class GenerativeAIAnalysis:
    baseUrl: str
    contextWindowUsage: int
    directoryToScanPath: str
    filesToScan: list
    findings: dict
    model: str

    def __init__(self, baseUrl, model, directoryToScanPath, filesToScan, logger):
        self.baseUrl = baseUrl
        self.contextWindowUsage = 0
        self.directoryToScanPath = directoryToScanPath
        self.filesToScan = filesToScan
        self.findings = {}
        self.model = model
        self.logger = logger
        self.checkApiAccessible()

        self.logger.info(f"Performing generative AI vulnerability scan for {len(self.filesToScan)} files.")

        for index, file in enumerate(self.filesToScan):
            self.logger.info(ConsoleColour.toYellow(f"Analysing file {index + 1}/{len(self.filesToScan)}: {file}"))
            self.vulnerabilityScanForFile(file)

    def checkApiAccessible(self):
        response = requests.get(f"{self.baseUrl}/v1/models")

        if response.status_code != 200:
            raise ConnectionError(f"Failed to connect to AI API at {self.baseUrl}. Status code: {response.status_code}, Response: {response.text}")

        return

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
            self.logger.info(f'Scanning {relativeFilePath} (iteration {i+1}/{scanRange}).')

            findings = AIRestAPI.executeWithRetries(
                operationName=f"Initial scan for {relativeFilePath}",
                logger=self.logger,
                function=lambda: self.initialVulnerabilityScan(absoluteFilePath),
            )

            for finding in findings:
                self.findings[relativeFilePath]["vulnerabilities"].append(finding)

        if len(self.findings[relativeFilePath]["vulnerabilities"]) > 0:
            self.logger.info(f"Aggregating findings for file {relativeFilePath}.")
            aggregated = AIRestAPI.executeWithRetries(
                operationName=f"Aggregation for {relativeFilePath}",
                logger=self.logger,
                function=lambda: self.aggregateInitialFindings(
                    fileReference=relativeFilePath,
                    filePath=absoluteFilePath
                )
            )
            self.findings[relativeFilePath]["vulnerabilities"] = aggregated

            self.logger.info(f"Assigning correct CWE and OWASP categories for file {relativeFilePath}.")
            corrected = AIRestAPI.executeWithRetries(
                operationName=f"OWASP/CWE assignment for {relativeFilePath}",
                logger=self.logger,
                function=lambda: self.assignCorrectCWEOWASPCategories(
                    fileReference=relativeFilePath
                )
            )
            self.findings[relativeFilePath]["vulnerabilities"] = corrected
        else:
            self.logger.info(f"No vulnerabilities found for file {relativeFilePath}.")
    
    def initialVulnerabilityScan(self, filePath):
        self.logger.debug(f"Initial vulnerability scan for {filePath}.")

        systemPrompt = textwrap.dedent("""\
            You are a cybersecurity code reviewer focused on PHP applications.
                                       
            Analyse the provided code for vulnerabilities and output the findings strictly following the JSON schema provided in the request's response_format.
            
            Schema guidelines:
            - Use null for any optional values if not applicable.
            - The "line" field must contain the exact code snippet from the source code.
            - Do not output line numbers or offsets.
            - Confidence scores should be based on the evidence of their respective category. Confidence scores allow a human reviewer to understand how certain you are about the accuracy of your findings.
            
            Explicit guidelines:
            - Only report vulnerabilities directly supported by the provided code.
            - When producing results, attempt to provide them within the context of the provided code. The findings should be context-aware where possible, rather than generic or speculative.
            - Do not invent lines, functions, SQL queries, or behaviour not present in the code.
            - If there is insufficient evidence, return an empty vulnerabilities array.
            - When providing a fix, give instruction in plain English and either provide a valid code snippet or a clear but brief and actionable step-by-step instruction.
            - Strongly prefer no findings over a speculative finding.
            - Describe findings in plain English. Findings must be clear and easy to understand for a human reviewer.
            - Map each vulnerability to applicable OWASP Top 10 categories if relevant and possible.
            - Preserve all indentation and characters, without breaking JSON formatting rules.
            
            Consider these OWASP Top 10 categories where applicable:
        """) + "\n".join([f"- {item['id']} {item['name']}" for item in owaspTop10Context])

        with open(filePath, 'r', encoding='utf-8') as f:
            fileContent = f.read()

        payload = AIRestAPI.buildConversationPayloadWithVulnerabilitySchema(self.model, systemPrompt, [fileContent])
        self.logger.debug(payload)
        
        response = requests.post(
            f"{self.baseUrl}/v1/chat/completions", 
            headers=AIRestAPI.buildRequestHeaders(),
            json=payload,
            timeout=60
        )
        self.logger.debug(response.text)

        if response.status_code == 200:
            responseJson = response.json()
            self.logger.debug(responseJson)

            if 'usage' in responseJson and 'total_tokens' in responseJson['usage']:
                self.contextWindowUsage += responseJson['usage']['total_tokens']
                self.logger.debug(f"Context window usage after scanning {filePath}: {self.contextWindowUsage} tokens.")

            if 'choices' in responseJson:
                aiMessageContent = responseJson['choices'][0]['message']['content']
                
                cleanedResponse = self.cleanUpResponse(aiMessageContent)
                return self.getVulnerabilitiesFromJsonResponse(cleanedResponse)

    def cleanUpResponse(self, response):
        # Tidy up the response by removing any markdown code blocks
        cleanedResponse = re.sub(r"^```.*?\n|\n```$", "", response.strip(), flags=re.DOTALL)
        return cleanedResponse

    def aggregateInitialFindings(self, fileReference, filePath):
        self.logger.debug(f"Aggregating initial findings for {fileReference}.")

        systemPrompt = textwrap.dedent("""\
            You are a cybersecurity data processor, specialising in vulnerability management.
                                       
            Your sole objective is to take a list of existing vulnerability findings and consolidate them into a unique, deduplicated JSON list.
            
            Schema guidelines:
            - Use null for any optional values if not applicable.
            - The "line" field should contain the exact code snippet from the source code.
            - Do not output line numbers or offsets.
            - Confidence scores should be based on the evidence of their respective category. Confidence scores allow a human reviewer to understand how certain you are about the accuracy of your findings.
               
            Explicit guidelines:
            - Do not scan for new vulnerabilities.
            - Consider findings duplicates if the `line` is identical and descriptions are semantically similar.
            - When merging multiple findings for the same code snippet:
                - Set each category confidence to the **maximum** of the duplicates.
                - Set `overall` confidence to the **average** of the duplicates.
            - When findings conflict (e.g., different descriptions for the same line), adjust confidence scores downward to reflect uncertainty.
            - Use the provided source code only as a reference to verify and consolidate the existing findings.
            - The provided code allows for context-aware consolidation. Where possible, use the context of the code to resolve ambiguities in the findings, but do not add new findings that are not already present in the input.
            - When making adjustments, ensure that findings are in plain English. Findings must be clear and easy to understand for a human reviewer.
            - Preserve all indentation and characters, without breaking JSON formatting rules.
            - If the OWASP or CWE mapping is inconsistent, adjust accordingly where a majority is selected, or where there is a better fit for the code snippet and vulnerability.
                        
            Consider these OWASP Top 10 categories where applicable, as a reference:
        """) + "\n".join([f"- {item['id']} {item['name']}" for item in owaspTop10Context])

        with open(filePath, 'r', encoding='utf-8') as f:
            fileContent = f.read()

        userPrompt = textwrap.dedent(f"""\
            JSON findings:
                                     
            {self.findings[fileReference]['vulnerabilities']}
                                     
            Original code file for reference:
            
            {fileContent}
        """)

        payload = AIRestAPI.buildConversationPayloadWithVulnerabilitySchema(self.model, systemPrompt, [userPrompt])
        self.logger.debug(payload)

        response = requests.post(
            f"{self.baseUrl}/v1/chat/completions",
            headers=AIRestAPI.buildRequestHeaders(),
            json=payload
        )

        responseJson = response.json()
        self.logger.debug(responseJson)

        if 'usage' in responseJson and 'total_tokens' in responseJson['usage']:
            self.contextWindowUsage += responseJson['usage']['total_tokens']
            self.logger.debug(f"Context window usage after aggregating {filePath}: {self.contextWindowUsage} tokens.")

        if 'choices' in responseJson:
            aiMessageContent = responseJson['choices'][0]['message']['content']
            
            cleanedResponse = self.cleanUpResponse(aiMessageContent)
            return self.getVulnerabilitiesFromJsonResponse(cleanedResponse)

    def assignCorrectCWEOWASPCategories(self, fileReference):
        systemPrompt = textwrap.dedent("""\
            You are a cybersecurity specialist, specialising in vulnerability classification and management.
            
            Your task is to review a list of vulnerability findings and ensure that each finding is correctly mapped to its CWE ID(s) and OWASP Top 10 category, if applicable.
            
            Schema enforcement:
            - Do not modify any field except `owasp_categories` and `cwe_ids`.
            - Output must conform exactly to the `VulnerabilityScanResult` JSON schema.
            - Preserve all other fields exactly as submitted.

            Mapping rules:
            - Use the authoritative OWASP Top 10 categories as their allowed CWE IDs as the reference:
        """)

        for item in owaspTop10Context:
            systemPrompt += f"- {item['id']} {item['name']} ({', '.join([f'{cwe['id']}' for cwe in item.get('cwe_ids', [])])})\n"
        
        systemPrompt += textwrap.dedent("""\

            Instructions:
            - If any OWASP category or CWE ID does not match the authoritative mapping above, correct it.
            - If multiple categories are plausible, include all that are applicable.
            - If no CWE or OWASP category applies, use a best-guess approach.
            - Do not invent new vulnerabilities or change any other fields.
            - Return the output in the same JSON format as submitted, fully parseable by Python `json.loads()`.
        """)

        payload = AIRestAPI.buildConversationPayloadWithVulnerabilitySchema(self.model, systemPrompt, [json.dumps(self.findings[fileReference]['vulnerabilities'])])
        self.logger.debug(payload)

        response = requests.post(
            f"{self.baseUrl}/v1/chat/completions",
            headers=AIRestAPI.buildRequestHeaders(),
            json=payload
        )

        responseJson = response.json()
        self.logger.debug(responseJson)

        if 'usage' in responseJson and 'total_tokens' in responseJson['usage']:
            self.contextWindowUsage += responseJson['usage']['total_tokens']
            self.logger.debug(f"Context window usage after OWASP assignment {fileReference}: {self.contextWindowUsage} tokens.")

        if 'choices' in responseJson:
            aiMessageContent = responseJson['choices'][0]['message']['content']
            
            cleanedResponse = self.cleanUpResponse(aiMessageContent)
            return self.getVulnerabilitiesFromJsonResponse(cleanedResponse)
    
    def getVulnerabilitiesFromJsonResponse(self, jsonResponse):
        try:
            jsonData = json.loads(jsonResponse)

            if isinstance(jsonData, dict) and 'vulnerabilities' in jsonData:
                return jsonData['vulnerabilities']
            
            self.logger.critical(ConsoleColour.toRed("JSON response does not contain 'vulnerabilities' key or is not a valid JSON object."))
            self.logger.debug(jsonResponse)
        except json.JSONDecodeError as e:
            self.logger.critical(ConsoleColour.toRed("Failed to decode JSON response from AI API."))
            self.logger.debug(jsonResponse)
            return []
