# SecAware

SecAware is a context-aware vulnerability scanner that aggregates the findings of several security analysis tools to provide better insight into software risks.

## Pre-Requisites

### LLM Provider

SecAware uses a generative AI component to assist with vulnerability detection and provide contextualised outputs. There are a number of different options, depending on your available resources.

#### Local AI Provider via LM Studio

[LM Studio](https://lmstudio.ai/) can be used where you have adequate available local resources. Generative AI processing is resource intensive, and so you should ensure that your hardware is capable of handling suitable input and output contexts.

LM Studio should be configured with the following:

1. Enabled developer mode. [Please follow the official instructions with details on how to enable this.](https://lmstudio.ai/docs/app/user-interface/modes)
2. Within the developer window, configure the server settings so that "Serve on Local Network" is enabled. This will allow communication from your LM Studio to the Docker container of SecAware.
3. Ensure that you have downloaded the `google/gemma-3-4b` model.

When you intend to use SecAware, you should ensure that the LM Studio server is running with the `google/gemma-3-4b` loaded.

## Quick Start

Create a copy of `.env.example` as `.env`, and ensure that you populate the following values:

| Value          | Description                                                                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GITHUB_TOKEN` | A [personal access token (PAT)](https://github.com/settings/personal-access-tokens/new) for a GitHub account, used to authenticate against GitHub API. |

Please use the provided Docker container. SecAware is designed with specific assumptions regarding operating system functionalities and capabilities. Executing SecAware natively may lead to environment-related crashes or inconsistent analysis results.

```bash
# Build the container
docker build -t secaware .

# Install dependencies and run the system
docker run -it --rm \
    -v "$(pwd):/app" \
    -w /app \
    secaware \
    sh -c "uv pip install --system -e . && ./SecAware.py"
```
