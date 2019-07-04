from Crypto.PublicKey import RSA

key = RSA.generate(2048)

f = open('priv_key.pem', 'w')
f.write(key.exportKey(format='PEM'))
f.close()

f = open('pub_key.pem', 'w')
f.write(key.publickey().exportKey(format='PEM'))
f.close()


