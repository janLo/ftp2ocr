FROM python:3.11 as builder

RUN apt update &&\
    apt -y install \
        curl \
        libleptonica-dev \
        &&\
    apt clean &&\
    rm -rf ./var/lib/apt/lists/*

RUN \
    mkdir jbig2 \
    && curl -L https://github.com/agl/jbig2enc/archive/0.29.tar.gz | \
    tar xz -C jbig2 --strip-components=1 \
    && cd jbig2 \
    && ./autogen.sh && ./configure && make && make install \
    && cd .. \
    && rm -rf jbig2

FROM python:3.11

RUN apt update &&\
    apt -y install \
        ocrmypdf \
        curl \
        libjemalloc2 \
        tesseract-ocr-deu \
        pngquant \
        unpaper \
        &&\
    apt clean &&\
    rm -rf /var/lib/apt/lists/*

ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2

RUN pip install pyftpdlib pikepdf click cryptography pyOpenSSL watchdog

COPY --from=builder /usr/local/lib/ /usr/local/lib/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

ADD src/ftp2ocr.py /bin
RUN chmod +x /bin/ftp2ocr.py

USER www-data

ENTRYPOINT ["/bin/ftp2ocr.py"]
