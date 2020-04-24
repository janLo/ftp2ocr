FROM python:3.8 as builder

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

FROM python:3.8

RUN useradd -u 33  ftpuser

RUN apt update &&\
    apt -y install \
        ocrmypdf \
        curl \
        tesseract-ocr-deu \
        pngquant \
        &&\
    apt clean &&\
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/ /usr/local/lib/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

ADD src/ftp2ocr.py /bin

USER ftp_user

ENTRYPOINT /bin/ftp2ocr.py