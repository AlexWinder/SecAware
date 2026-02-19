# SecAware

SecAware is a context-aware vulnerability scanner that aggregates the findings of several security analysis tools to provide better insight into software risks.

## Quick Start

Create a copy of `.env.example` as `.env`, and ensure that you populate the following values:

| Value          | Description                                                                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GITHUB_TOKEN` | A [personal access token (PAT)](https://github.com/settings/personal-access-tokens/new) for a GitHub account, used to authenticate against GitHub API. |

A Docker environment is provided to allow simple execution.

```bash
# Build the container
docker build -t secaware .

# Install dependencies and run the system
docker run -it --rm \
    -v "$(pwd):/app" \
    -w /app \
    secaware \
    sh -c "uv pip install --system -e . && bash"
```
