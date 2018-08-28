from flask import jsonify,request
from app import app
import base64
import sys,os

#import sgxwraper to get access to the enclave
sys.path.insert(0,'../SGX_lib/')
import sgxwrapper

@app.route('/')
@app.route('/index')
def index():
    return "<h1>My Inventory List</h1>"

@app.route('/api/v1.0/image_verify',methods=['POST'])
def image_verify():
    if not request.json or not 'filename' in request.json:
        abort(400)

    #Get the key-pair from POST
    json_dict = request.get_json()
    filename=json_dict['filename']
    file= json_dict['file']

    #processing of file
    f1=file.encode()
    f2=base64.b64decode(f1)

    tempfile=filename
    #print(tempfile)
    with open(tempfile,'wb') as tmp:
        tmp.write(f2)

    #Using the wrapper
    status_out=""
    filename_raw=filename.split('.')[0]
    #print("The file is {}".format(filename_raw))

    #pass the image to the Image Integry Mechanisms and output result
    result=sgxwrapper.py_SGX_IIM(filename_raw.encode(),tempfile.encode())

    ''' If the images is found to be valid, then the image file is sent
    to the requested, otherwise, just the result of the validation
     and the filename are given back'''

    if result==1:
        data = {'filename': filename, 'result': result, 'file': file}
    else:
        data = {'filename': filename,'result':result}

    #remove the image after sending the response to the caller.
    os.remove(tempfile)

    return jsonify(data), 201