FROM python:3.7

RUN useradd -ms /bin/bash web

# copy only the files needed for pip install
COPY requirements.txt /home/web/requirements.txt
RUN pip install --upgrade pip
RUN pip install -r /home/web/requirements.txt --no-cache-dir

USER web

# copy the rest of the app
COPY . /home/web

WORKDIR /home/web

RUN ./gen-cert.sh
