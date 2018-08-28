from app import app
import sys
sys.path.insert(0,'../SGX_lib/')
import sgxwrapper


###Checking Initial conditions
#the path of the hash measurements
if len(sys.argv)== 2:
    #Before the application is run we need to pass the list of measurements
    #to the enclave.
    u_hash_list=sys.argv[1]

    if sgxwrapper.py_SGX_init(u_hash_list.encode()) !=0 :
        print("IIV-Error: The Integrity Image Mechanism could no be started")
        exit(1)

elif len(sys.argv)== 1:
    if sgxwrapper.py_SGX_init() != 0:
        print("IIV-Error: The Integrity Image Mechanism could no be started")
        exit(1)
else:
    exit(1)
#print("Initialization succeed!")

#RestAPI Initialization.....
app.run(debug=True)
