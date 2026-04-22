FROM python:3.14.4-bookworm

# Upstream for latest versions of PHP
RUN curl -sSLo /tmp/debsuryorg-archive-keyring.deb https://packages.sury.org/debsuryorg-archive-keyring.deb \
    && dpkg -i /tmp/debsuryorg-archive-keyring.deb \
    && rm /tmp/debsuryorg-archive-keyring.deb
RUN echo "deb [signed-by=/usr/share/keyrings/debsuryorg-archive-keyring.gpg] https://packages.sury.org/php/ $(. /etc/os-release && echo $VERSION_CODENAME) main" \
    > /etc/apt/sources.list.d/php.list

RUN apt update

# Install Psalm (https://psalm.dev/) and its dependencies
RUN apt install -y php8.4-cli php8.4-xml php8.4-mbstring
RUN wget https://github.com/vimeo/psalm/releases/download/6.15.1/psalm.phar -O /usr/local/bin/psalm
RUN chmod +x /usr/local/bin/psalm

# Install necessary Python dependencies
RUN pip install --upgrade pip
RUN pip install uv==0.10.6

CMD ["bash"]