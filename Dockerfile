FROM python:3.14-bookworm

RUN apt update

# Install Psalm (https://psalm.dev/) and its dependencies
RUN apt install -y php-cli php-xml
RUN wget https://github.com/vimeo/psalm/releases/latest/download/psalm.phar -O /usr/local/bin/psalm
RUN chmod +x /usr/local/bin/psalm

RUN pip install --upgrade pip
RUN pip install uv

CMD ["bash"]