FROM python:3.14

RUN apt update &&\
    apt -y install \
        curl \
        jbig2 \
        libjemalloc2 \
        ocrmypdf \
        pngquant \
        tesseract-ocr-deu \
        unpaper \
        &&\
    apt clean &&\
    rm -rf /var/lib/apt/lists/*

ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2

RUN pip install pyftpdlib pikepdf click cryptography pyOpenSSL watchdog

ADD src/ftp2ocr.py /bin
RUN chmod +x /bin/ftp2ocr.py

USER www-data

ENTRYPOINT ["/bin/ftp2ocr.py"]
