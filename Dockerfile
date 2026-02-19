FROM python:3.14-bookworm

RUN pip install --upgrade pip
RUN pip install uv

CMD ["bash"]