from KGC import *
from user import *
from cloud import *
from public.hashfunctions import *


# print(EcGroup(703).parameters())


# ------------------------ Setup Phase -----------------------------
# 'p': 4451685225093714772084598273548427, 
# 'a': 1970543761890640310119143205433388, 
# 'b': 1660538572255285715897238774208265
nameId = 705


# init
kgc = KGC(nameId)

# sending master public keys to Users
sender = User(nameId, kgc.P_pub, "sender")


# -------------------- Key Generation Phase --------------------------

sender.setSecretValue()
Ri,ki = kgc.partialKeyExtract(sender.Ti, sender.IDi)

sender.setPrivateKey(Ri, ki)

# ---------------------- Data Storage Phase ----------------------------

# Encyption by sender
msg = "secretmessage"
CT = sender.encrypt(msg)

print("\nCypher Text(CT) :",CT)

# Verification for correct encryption
sender.decryption1(CT)


print("\n======================= Reciever 1 ==============================")
# setup reciever
reciever1 = User(nameId, kgc.P_pub, "reciever")
reciever1.setSecretValue()
Rj1,kj1 = kgc.partialKeyExtract(reciever1.Ti, reciever1.IDi)
reciever1.setPrivateKey(Rj1, kj1)
print("\n======================= Reciever 1 ==============================\n")

print("\n======================= Reciever 2 ==============================")
# setup reciever
reciever2 = User(nameId, kgc.P_pub, "reciever")
reciever2.setSecretValue()
Rj2,kj2 = kgc.partialKeyExtract(reciever2.Ti, reciever2.IDi)
reciever2.setPrivateKey(Rj2, kj2)
print("\n======================= Reciever 2 ==============================\n")

Rj_list = [Rj1,Rj2]
Tj_list = [reciever1.Ti,reciever2.Ti]
IDj_list = [reciever1.IDi, reciever2.IDi]

# ------------------------ Broadcast Phase -----------------------------

# sender - reencryption key generation 
# sends recievers parameters
rk1, rk2  = sender.rekeygen(Rj_list,Tj_list,IDj_list)

# Storing encrypted message inside cloud
proxy = Proxy(CT)
C31,C41 = proxy.reencryption(rk1,rk2)

# Sharing
decrypted_message1 = reciever1.decryption2(CT,C31,C41)
decrypted_message2 = reciever2.decryption2(CT,C31,C41)


print("Decrypted message for reciever 1 is: ", decrypted_message1)
print("Decrypted message for reciever 2 is: ", decrypted_message2)