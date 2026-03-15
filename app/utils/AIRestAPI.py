#!/usr/bin/env python3

import os

class AIRestAPI:
    @staticmethod
    def buildRequestHeaders():
        headers = {'Content-Type': 'application/json'}

        token = os.environ.get('AI_API_BEARER_TOKEN')

        if token and token.strip():
            headers['Authorization'] = f"Bearer {token.strip()}"

        return headers

    @staticmethod
    def buildConversationPayload(model, systemPrompt, userPrompt):
        return {
            "model": model,
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