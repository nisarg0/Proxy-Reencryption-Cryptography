from petlib.ec import EcGroup
from petlib.bn import Bn

# To genrate IDi
import random
from public.hashfunctions import *

class Proxy:
    def __init__(self,CT):
        self.CT = CT

    def reencryption(self,rk1, rk2):
        print("\nReencryption done sucessfully in Proxy\n")
        C31 = self.CT[0].pt_mul(rk1)
        C41 = rk2
        return C31,C41

