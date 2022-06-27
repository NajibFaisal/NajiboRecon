FROM alpine:latest
RUN apk update 
RUN apk add \
    git \
    python3 \
    py3-pip gcc \
    python3-dev \
    postgresql-dev \
    libffi-dev \
    musl-dev \
    libxml2-dev \
    libxslt-dev
RUN rm -rf /var/cache/apk/*
WORKDIR /root
RUN git clone https://github.com/NajibFaisal/najiborecon.git
WORKDIR /root/najiborecon/
RUN pip3 install wheel
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
ENTRYPOINT ["python3", "najiborecon.py"]
