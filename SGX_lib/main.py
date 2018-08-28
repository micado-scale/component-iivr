import sgxwrapper

sgxwrapper.py_hello(5)
#Initialization of the SGX IIV mechanism
sgxwrapper.py_SGX_init(b"/home/jorge/workspace/SGX_IIV/sgx/enclave_IIV/beto.txt")

#Test one image result
sgxwrapper.py_SGX_IIM(b"medina", b"/home/jorge/workspace/SGX_IIV/sgx/enclave_IIV/untrusted/medina.txt")

#n=float(1120120102012)
#pyexamples.py_sumar(n)
#pyexamples.primes(10)
