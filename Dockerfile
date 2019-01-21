FROM ubuntu:18.04

RUN apt-get update && apt-get install python3 python3-pip python3-setuptools curl libcurl4 libprotobuf10 -y && rm -rf /var/lib/apt/lists/*

ADD . /opt/iivr
#ADD utils /opt/iivr/utils
#ADD startup /opt/iivr/startup

RUN pip3 install -r /opt/iivr/utils/requirements.txt

RUN curl -o sgx_sdk.bin https://download.01.org/intel-sgx/linux-2.4/ubuntu18.04-server/sgx_linux_x64_sdk_2.4.100.48163.bin && chmod +x sgx_sdk.bin && ./sgx_sdk.bin --prefix /opt/intel/
RUN cp -ra /opt/intel/sgxsdk/lib64/* /usr/lib/

ADD SGX_lib/libcSGX/IIV.signed.so /opt/iivr/IIV_app/IIV.signed.so
RUN cd /opt/iivr/SGX_lib && python3 setup.py install

RUN apt-get remove -y --purge build-essential && apt-get autoremove -y

ENV LD_LIBRARY_PATH /opt/iivr/SGX_lib/libcSGX
WORKDIR /opt/iivr/IIV_app
CMD [ "python3", "/opt/iivr/IIV_app/run.py" ]
