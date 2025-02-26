FROM python:3.7

RUN useradd -ms /bin/bash worker

# copy only the files needed for pip install
RUN pip install --upgrade pip
RUN pip install Cython

COPY requirements-worker.txt /home/worker/requirements-worker.txt
RUN pip install -r /home/worker/requirements-worker.txt --no-cache-dir

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install -yq software-properties-common
RUN apt-get install -yq default-jdk
RUN apt-get install -yq gcc g++ scons autoconf libtool git libboost-all-dev libc6-dev
RUN apt-get install -yq nano
RUN apt-get install -yq cmake

RUN git clone https://github.com/fmtlib/fmt.git
RUN cd fmt && mkdir build && cd build && cmake -DBUILD_SHARED_LIBS=TRUE .. && make && make install

COPY ./deps/BayesElo /home/worker/BayesElo
WORKDIR /home/worker/BayesElo
RUN make
RUN cp /home/worker/BayesElo/bayeselo /usr/bin/bayeselo
RUN rm -rf /home/worker/BayesElo

USER worker

# copy the rest of the app
COPY ./scrimmage /home/worker/scrimmage
COPY ./deps/engine-2025/engine.py /home/worker/engine/engine.py

WORKDIR /home/worker
