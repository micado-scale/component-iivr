FROM python:3-slim

RUN apt-get update && apt-get install openssl libssl-dev netcat build-essential strace -y && rm -rf /var/lib/apt/lists/*

ADD . /opt/iivr
#ADD utils /opt/iivr/utils
#ADD startup /opt/iivr/startup

RUN easy_install pip
RUN pip3 install -r /opt/iivr/utils/requirements.txt

ADD SGX_lib/libcSGX/IIV.signed.so /opt/iivr/IIV_app/IIV.signed.so
#ADD SGX_lib/libcSGX/libiiv.so /lib/libiiv.so
RUN cd /opt/iivr/SGX_lib && python setup.py install

RUN apt-get remove -y --purge build-essential && apt-get autoremove -y

ENV LD_LIBRARY_PATH /opt/iivr/SGX_lib/libcSGX
WORKDIR /opt/iivr/IIV_app
CMD [ "strace", "-fff", "python3", "/opt/iivr/IIV_app/run.py" ]
