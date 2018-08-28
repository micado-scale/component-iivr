cdef extern from "libcSGX/untrusted/iiv.h":
    int SGX_init(char *file_path);
    int SGX_IIM(char *image_name, char *image_path);


def py_SGX_init(file_name:bytes="None".encode()):
    if file_name=="None":
        return SGX_init(NULL)
    else:
        return SGX_init(file_name)

def py_SGX_IIM(image_name:bytes,image_path:bytes):
    result=SGX_IIM(image_name,image_path)
    return result