import hashlib 

def H1(x):
    x = int(x)
    result = 100
    result1 = 0
    while x:
        result1 += x%10
        x /= 10
    return result

def H2(string):
    result = 0
    for x in string:
        result += x
    return result


# Paras : Array of points, Binary string
def H3(pt,IDi): 
    res = int(IDi,2)

    hash_object = hashlib.sha512(str(pt).encode())
    hex_dig = hash_object.hexdigest()
    
    result = int(IDi,2)
    for e in hex_dig:
        if e <= "9" and e>= "0":
            result += int(e)
    return result

def H4(PT , y):
    # print(bytes(str(x)+str(y), 'utf-8'))
    return bytes(str(PT)+str(y), 'utf-8')


def H7(pt1, pt2, IDi):
    res = str(pt1)+str(pt2)

    # result = hashlib.sha256(res.encode())   
    
    hash_object = hashlib.sha512(res.encode())
    hex_dig = hash_object.hexdigest()
    
    result = int(IDi,2)

    for e in hex_dig:
        if e <= "9" and e>= "0":
            result += int(e)
        
    return result
