import sys
import base64,requests,os

if len(sys.argv)!=3:
    print("Incorrect number of arguments: <url> <Image_name>")
    sys.exit(1)

myurl=sys.argv[1]
route=sys.argv[2]

filename=os.path.basename(route)

try:
    with open(route,'rb') as f:
        filecontent = f.read()
        dataEncoded = base64.b64encode(filecontent)
        dataDecoded = dataEncoded.decode()
    data = {'filename': filename, 'file': dataDecoded}
    try:
        r=requests.post(myurl,json=data)
        if r.status_code==201:
            json_dict=r.json()
            result=json_dict['result']

            '''
            If the results from the verification of the image,
            turns to be OK, then the image is returned as response
            the client therefore must retrieve the image from 
            the JSON request
            '''
            if(result==1):
                print("Recover the image......")
                file=json_dict['file']
                file_name=json_dict['filename']
                f1 = file.encode()
                f2 = base64.b64decode(f1)
                with open(file_name,'wb') as fr:
                    fr.write(f2)
            print("The result of the Image Integrity Verifier is:{}".format(result))

    except requests.exceptions.RequestException as error:
        print(error)
        sys.exit(1)
except IOError:
    print("The file: {} does not exist in the path provided".format(filename))
