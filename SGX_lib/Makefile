LIB_DIR = libcSGX

default: sgxwrapper

sgxwrapper: setup.py sgxwrapper.pyx $(LIB_DIR)/libiiv.so
	python3 setup.py build_ext --inplace #&& rm -f pyexamples.c && rm -Rf build

#$(LIB_DIR)/libexamples.a:
#	make -C $(LIB_DIR) libexamples.a

clean:
	rm *.so
