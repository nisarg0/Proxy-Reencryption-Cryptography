from petlib.ec import EcGroup
from petlib.bn import Bn

# To genrate IDi
import random
from public.hashfunctions import *

class User:
	# Ti, ti, P, IDi, 
	def __init__(self, nameId, P_pub, type):
		self.nameId = nameId
		self.G = EcGroup(nameId)
		self.P, self.o = self.G.generator(),self.G.order()
		self.P_pub = P_pub
		self.IDi = "0001"

		if type != "sender":		
			while self.IDi == "0001":
				self.IDi = ""
				for i in range(4):
					self.IDi += str(random.randint(0, 1))
			

	# Helper
	def bitwise_xor_bytes(self,a, b):
		result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
		return result_int.to_bytes(max(len(a), len(b)), byteorder="big")


	def setSecretValue(self):
		print("\n\n********* User Seceret Set ***********")

		self.ti = self.G.order().random()
		self.Ti = self.P.pt_mul(self.ti)

		print("Ti :" , self.Ti)
		print("IDi for user is ", self.IDi)

	def setPrivateKey(self,Ri, ki):
		print("\n\n********* User ***********")
		P, P_pub, Ti, ti, IDi = self.P, self.P_pub, self.Ti, self.ti, self.IDi

		lhs = P.pt_mul(ki)

		term1 = Ri
		term2 = P_pub.pt_mul(H7(Ri,Ti,IDi))
		term3_1 = P_pub.pt_mul(ti)
		term3 = P.pt_mul(H3(term3_1,IDi))

		rhs1 = term1.pt_add(term2)
		rhs = rhs1.pt_add(term3)

		si = ki- H3(P_pub.pt_mul(ti), IDi)

		print(lhs,rhs)	
		if lhs == rhs:
			print("Verification Successful")
		else:
			print("Verifcation Unsuccessful")


		print("\nUser Secret Key - si: " + str(si) + ", ti: "+ str(ti))
		print("User Public Key - Ri: " + str(Ri) + ", Ti: "+ str(Ti))

		self.si = si
		self.Ri = Ri
		self.ki = ki

	
		# Sender

	def encrypt(self,m):
		P, P_pub, Ts, ts, IDs, Rs, ss = self.P, self.P_pub, self.Ti, self.ti, self.IDi, self.Ri, self.si

		w = H7(Rs,Ts, IDs)

		z = H2(bytes(m+str(w), 'utf-8'))
		Z = P.pt_mul(z)

		t21 = P_pub.pt_mul(H7(Rs,Ts,IDs))
		t2 = Rs.pt_add(t21)
		t2 = t2.pt_add(Ts)

		Us =  t2.pt_mul(z)

		alpha = H1(ss+ts)
		theta = H1(alpha) #bug
		C = self.bitwise_xor_bytes(H4(Z,theta) , bytes(m+str(w), 'utf-8'))

		self.w = w
		self.z = z
		self.alpha = alpha

		# tupple of C1,C2
		return (Z, C)

	def decryption1(self, CT):
		C1 = CT[0]
		C2 = CT[1]
		ss, ts, P = self.si, self.ti, self.P

		Us1 = C1.pt_mul(ss+ts)

		alpha = H1(ss+ts)
		theta = H1(alpha)

		# mw = m||w
		mw = self.bitwise_xor_bytes(C2, H4(C1,theta))
		rhs = P.pt_mul(H2(mw))

		print("\n", C1, rhs)

		if(C1 == rhs):
			print("Encrypted message is verified")
		else:
			print("Encrypted message is not verified")

	def rekeygen(self, Rj_list, Tj_list, IDj_list):
		alpha, z, w, ss, ts, G, P_pub = self.alpha, self.z, self.w, self.si, self.ti,self.G, self.P_pub

		print("---------- Re-encryption -------------")

		U = []

		print(Rj_list)
		print(Tj_list)
		print(IDj_list)

		for (Rj,Tj,IDj) in zip(Rj_list,Tj_list,IDj_list):
			t2 = P_pub.pt_mul(H7(Rj,Tj,IDj))
			t1 = t2.pt_add(Rj)
			t3 = t1.pt_add(Tj)
			
			Uj = t3.pt_mul(z)
			print("Uj: ",Uj)

			beta = G.order().random()
			uj = H3(Uj,IDj)

			U.append(uj)

		q = 4451685225093714772084598273548427
		# q = EcGroup(nameId).parameters().p
		
		#U is list of Uj
		def polynomial_gen(U,beta,x,q):
			ans = 1
			for ui in U:
				ans *= (x-ui)
			ans += beta % q
			return ans
		

		def modInverse(a, m):
			for x in range(1, m):
				if (((a%m) * (x%m)) % m == 1):
					return x
			return -1
		# mi = modInverse(beta,q)
		x = (ss+ts)*alpha*3

		rk1 = x
		rk2 = beta

		print("Re-encryption key:\n rk1" + str(rk1) + " rk2 : " + str(rk2))

		return rk1, rk2

	def decryption2(self,CT,C31,C41):
		C1,C2,sj,tj,IDj,P = CT[0], CT[1], self.si, self.ti, self.IDi, self.P

		def polynomial(U,x,rk2):
			ans = 1
			for ui in U:
				ans *= (x-ui)
			return rk2

		Uj1 = C1.pt_mul(sj+tj)
		# uj1 = H3(Uji,IDj,w)
		U = [Uj1]
		x = Uj1
		beta1 = polynomial(U,x,C41)
		theta1 = H1(beta1)

		temp = self.bitwise_xor_bytes(C2,H4(C1,theta1)).decode("utf-8")
		m = temp[:len(temp)-3]

		rhs = P.pt_mul(H2(temp.encode("utf-8")))
		print("lhs : ",C1)
		print("rhs : ",rhs)

		if(C1 == rhs):
			print("\nDecrypted Message is verified\n ")
		else:
			print("\nDecrypted Message is not verified\n ")

		return m

	def printf(self):
		print("IDi : ", self.IDi)
		print("ti : ", self.ti)
		print("Ti : ", self.Ti)

