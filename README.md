# SecAware

SecAware is a context-aware vulnerability scanner that aggregates the findings of several security analysis tools to provide better insight into software risks.

## Quick Start

You can get started quickly with Docker:

```bash
docker build -t secaware .

docker run -it --rm \
    -v "$(pwd):/app" \
    -w /app \
    secaware \
    sh -c "uv pip install --system -e . && bash"
```
