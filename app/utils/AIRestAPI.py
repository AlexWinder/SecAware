#!/usr/bin/env python3

import json
import os
import requests
import time

from app.utils.ConsoleColour import ConsoleColour

class AIRestAPI:
    @staticmethod
    def buildRequestHeaders():
        headers = {'Content-Type': 'application/json'}

        token = os.environ.get('AI_API_BEARER_TOKEN')

        if token and token.strip():
            headers['Authorization'] = f"Bearer {token.strip()}"

        return headers

    @staticmethod
    def buildConversationPayload(model, systemPrompt, userMessages):
        messages = [
            {"role": "system", "content": systemPrompt},
            *[{"role": "user", "content": m} for m in userMessages]
        ]

        return {
            "model": model,
            "messages": messages
        }

    @staticmethod
    def buildConversationPayloadWithVulnerabilitySchema(model, systemPrompt, userMessages):
        payload = AIRestAPI.buildConversationPayload(model, systemPrompt, userMessages)

        payload["response_format"] = {
            "type": "json_schema",
            "strict": True,
            "json_schema": {
                "name": "VulnerabilityScanResult",
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "vulnerabilities": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "description": {
                                        "type": "string",
                                        "description": "A brief description of the vulnerability identified in the code."
                                    },
                                    "owasp_categories": {
                                        "type": ["array", "null"], 
                                        "description": "A mapping to one or more of the OWASP Top 10 categories, if applicable. If the vulnerability does not fit into any OWASP category, this should be null.",
                                        "items": {
                                            "type": "string",
                                            "description": 'The OWASP Top 10 category, e.g. "A05:2025 - Injection".'
                                        },
                                    },
                                    "cwe_ids": {
                                        "type": ["array", "null"],
                                        "description": "A mapping to one or more CWE IDs, if applicable. If the vulnerability does not fit into any CWE ID, this should be null.",
                                        "items": {
                                            "type": "string",
                                            "description": "The CWE ID"
                                        }
                                    },
                                    "line": {
                                        "type": "string",
                                        "description": "The exact code snippet from the source that contains the vulnerability."
                                    },
                                    "justification": {
                                        "type": "string",
                                        "description": "A concise but clear justification for why the identified line is vulnerable."
                                    },
                                    "fix": {
                                        "type": ["string", "null"],
                                        "description": "Any fix recommended to resolve the identified vulnerability."
                                    },
                                    "confidences": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "properties": {
                                            "description": {
                                                "type": "integer",
                                                "minimum": 0,
                                                "maximum": 10,
                                                "description": "A confidence score of the defined description. 10 = complete confidence. 0 = no confidence."
                                            },
                                            "owasp_categories": {
                                                "type": "integer",
                                                "minimum": 0,
                                                "maximum": 10,
                                                "description": "A confidence score of the defined OWASP categories. 10 = complete confidence. 0 = no confidence."
                                            },
                                            "cwe_ids": {
                                                "type": "integer",
                                                "minimum": 0,
                                                "maximum": 10,
                                                "description": "A confidence score of the defined CWE IDs. 10 = complete confidence. 0 = no confidence."
                                            },
                                            "line": {
                                                "type": "integer",
                                                "minimum": 0,
                                                "maximum": 10,
                                                "description": "A confidence score of the identified line. 10 = complete confidence. 0 = no confidence."
                                            },
                                            "overall": {
                                                "type": "integer",
                                                "minimum": 0,
                                                "maximum": 10,
                                                "description": "A confidence score of the overall vulnerability finding. 10 = complete confidence. 0 = no confidence."
                                            },
                                        },
                                        "required": [
                                            "description", 
                                            "owasp_categories", 
                                            "cwe_ids",
                                            "line",
                                            "overall"
                                        ],
                                    }
                                },
                                "required": [
                                    "description",
                                    "owasp_categories",
                                    "cwe_ids",
                                    "line", 
                                    "justification",
                                    "fix",
                                    "confidences"
                                ]
                            }
                        }
                    },
                    "required": ["vulnerabilities"]
                }
            }
        }

        return payload
    
    @staticmethod
    def executeWithRetries(operationName, function, logger, maxRetries=50, retryDelay=2):
        for attempt in range(1, maxRetries + 1):
            try:
                result = function()

                if result is None:
                    raise ValueError(f"{operationName} returned None.")
                
                return result

            except (
                requests.RequestException, 
                requests.exceptions.JSONDecodeError,
                ValueError, 
                json.JSONDecodeError
            ) as e:
                logger.warning(
                    ConsoleColour.toRed(
                        f"Attempt {attempt}/{maxRetries} failed for {operationName}: {str(e)}"
                    )
                )

                if attempt < maxRetries:
                    time.sleep(retryDelay * attempt)
                else:
                    logger.error(
                        ConsoleColour.toRed(
                            f"Max retries reached for {operationName}. Skipping this operation."
                        )
                    )
                    return []