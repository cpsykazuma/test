from itertools import product
import numpy as np
class AES:
    sbox = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]

    invSbox = [
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    ]
    rcon = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    ]

    round_keys = []
    
    def __init__(self, master_key, num_of_round=10):
        self.master_key = bytearray(master_key.to_bytes(16, byteorder='big'))
        self.master_key = np.array(self.master_key).reshape(4,4)
        round_key = self.master_key
        self.num_of_round = num_of_round
        for round_num in range(num_of_round):
            round_key = self.__key_expansion(round_key, round_num+1)            
            
    def __key_expansion(self, input_key, round_num):
        w0 = input_key[0]
        w1 = input_key[1]
        w2 = input_key[2]
        w3 = input_key[3]
        rcon_pad = np.array([self.rcon[round_num], 0,0,0])
        z1 = self.__sub_4bytes(input_key[3, [1,2,3,0]])^rcon_pad
        w4 = w0^z1
        w5 = w4^w1
        w6 = w5^w2
        w7 = w6^w3
        round_key = np.array([w4, w5, w6, w7])
        self.round_keys.append(round_key)
        return round_key

    def __add_round_key(self, round, data):
        return  self.round_keys[round]^data

    def __sub_4bytes(self, state):
        if (state.size == 4):
            return np.array([self.sbox[elm] for elm in state])
        else:
            l = []
            for row in state:
                for elm in row:
                    l.append(self.sbox[elm])
            return np.array(l) #[self.sbox[elm] for elm in state])

    def __inv_sub_4bytes(self, state):
        if (state.size == 4):
            return np.array([self.invSbox[elm] for elm in state])
        else:
            l = []
            for row in state:
                for elm in row:
                    l.append(self.invSbox[elm])
            return np.array(l) #[self.sbox[elm] for elm in state])

    
    def __shiftrows(self, data):
        tmp = data.T
        tmp = np.array([
            tmp[0,[0,1,2,3]],
            tmp[1,[1,2,3,0]],
            tmp[2,[2,3,0,1]],
            tmp[3,[3,0,1,2]]
            ])
        return tmp.T
    
    def __inv_shiftrows(self, data):
        tmp = data.T
        tmp = np.array([
            tmp[0,[0,1,2,3]],
            tmp[1,[3,0,1,2]],
            tmp[2,[2,3,0,1]],
            tmp[3,[1,2,3,0]]
            ])
        return tmp.T

    def __mixcolumns(self, data):
        w0 = self.__matrixcalc(data[0])
        w1 = self.__matrixcalc(data[1])
        w2 = self.__matrixcalc(data[2])
        w3 = self.__matrixcalc(data[3])
        return np.array([w0,w1,w2,w3])

    def __inv_mixcolumns(self, data):
        w0 = self.__inv_matrixcalc(data[0])
        w1 = self.__inv_matrixcalc(data[1])
        w2 = self.__inv_matrixcalc(data[2])
        w3 = self.__inv_matrixcalc(data[3])
        return np.array([w0,w1,w2,w3])
        
    def __matrixcalc(self, data):
        return np.array([
            self.__gf_mult(data[0], 2)^self.__gf_mult(data[1], 3)^data[2]                   ^data[3],
            data[0]                   ^self.__gf_mult(data[1], 2)^self.__gf_mult(data[2], 3)^data[3],
            data[0]                   ^data[1]                   ^self.__gf_mult(data[2], 2)^self.__gf_mult(data[3], 3),
            self.__gf_mult(data[0], 3)^data[1]                   ^data[2]                   ^self.__gf_mult(data[3], 2)
            ])

    def __inv_matrixcalc(self, data):
        return np.array([
            self.__gf_mult(data[0], 0xe)^self.__gf_mult(data[1], 0xb)^self.__gf_mult(data[2], 0xd)^self.__gf_mult(data[3], 0x9),
            self.__gf_mult(data[0], 0x9)^self.__gf_mult(data[1], 0xe)^self.__gf_mult(data[2], 0xb)^self.__gf_mult(data[3], 0xd),
            self.__gf_mult(data[0], 0xd)^self.__gf_mult(data[1], 0x9)^self.__gf_mult(data[2], 0xe)^self.__gf_mult(data[3], 0xb),
            self.__gf_mult(data[0], 0xb)^self.__gf_mult(data[1], 0xd)^self.__gf_mult(data[2], 0x9)^self.__gf_mult(data[3], 0xe)
            ])

    #xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
    def xtime(self, a):
        if (a & 0x80):
            return (((a << 1) ^ 0x1B) & 0xFF)
        else:
            return (a << 1)
    
    def __gf_mult(self, byte, times):
        if(times == 2):
            return self.xtime(byte)
        elif (times == 3):
            return self.xtime(byte) ^ byte
        elif (times == 4):
            return self.xtime(self.xtime(byte)) 
        elif (times == 8):
            return self.xtime(self.xtime(self.xtime(byte))) 
        elif (times == 9):
            return self.xtime(self.xtime(self.xtime(byte)))^byte
        elif (times == 0xb):
            return self.xtime(self.xtime(self.xtime(byte)))^byte^self.xtime(byte)
        elif (times == 0xd):
            return self.xtime(self.xtime(self.xtime(byte)))^byte^self.xtime(self.xtime(byte))
        elif (times == 0xe):
            return self.xtime(self.xtime(self.xtime(byte)))^self.xtime(self.xtime(byte))^self.xtime(byte)
        
    
    def encrypt(self, plaintext):
        self.plaintext_array = bytearray(plaintext.to_bytes(16, byteorder='big'))
        self.plaintext_array = np.array(self.plaintext_array).reshape(4,4)
        state = self.master_key ^ self.plaintext_array
        for i in range(self.num_of_round-1):
            print("Round[",str(i),"]---")
            state = self.__rounder_enc(state, i)
        i+=1
        print("Round[",str(i),"]---")
        state = self.__sub_4bytes(state).reshape(4,4)
        self.__print("sb,",state.T)
        state = self.__shiftrows(state)
        self.__print("sr,",state.T)
        state = self.__add_round_key(i, state)
        self.__print("ar,",state.T)
        return state
        
    def __rounder_enc(self, state, round_num):
        state = self.__sub_4bytes(state).reshape(4,4)
        self.__print("sb,",state.T)
        state = self.__shiftrows(state)
        self.__print("sr",state.T)
        state = self.__mixcolumns(state)
        self.__print("mc",state.T)
        state = self.__add_round_key(round_num, state)
        self.__print("ar",state.T)
        return state
        
    def decrypt(self, ciphertext):
        self.ciphertext_array = bytearray(ciphertext.to_bytes(16, byteorder='big'))
        self.ciphertext_array = np.array(self.ciphertext_array).reshape(4,4)
        round_num = 9
        state = self.round_keys[round_num]^self.ciphertext_array
        round_num -=1
        for n in range(self.num_of_round-1):
            print("Round[",str(9-round_num),"]---")
            state = self.__rounder_dec(state, round_num)
            round_num -=1
        print("Round[",str(9-round_num),"]---")
        state = self.__inv_shiftrows(state)
        self.__print("isr",state)
        state = self.__inv_sub_4bytes(state).reshape(4,4)
        self.__print("isb",state)
        state = self.master_key^state
        self.__print("iar",state)
        return state
            
    def __rounder_dec(self, state, round_num):
        state = self.__inv_shiftrows(state)
        self.__print("isr",state.T)
        state = self.__inv_sub_4bytes(state).reshape(4,4)
        self.__print("isb",state.T)
        state = self.__add_round_key(round_num, state)
        self.__print("iar",state.T)
        state = self.__inv_mixcolumns(state)
        self.__print("imc",state.T)
        return state
    
    def __print(self, name, state):
        print(name)
        for i in range(4):
            print(hex(state[i][0]),hex(state[i][1]),hex(state[i][2]),hex(state[i][3]))
        print()
        
if __name__ == '__main__':
    plaintext,master_key =  0x000102030405060708090a0b0c0d0e0f, 0xf00
    print("----- Initialization ------")
    r = 3
    cipher = AES(master_key, num_of_round=r)
    print([f"{i},{j}" for i,j in product(range(4),range(4))])
    for i in range(r):
        print("".join([f"{cipher.round_keys[i].tolist()[j][k]:02x}" for j,k in product(range(4),range(4))]))
    print("----- ENCRYPTION ------")
    ciphertext = cipher.encrypt(plaintext)
    print("----- ciphertext ------")
    for i in range(4):
        print(hex(ciphertext[i][0]),hex(ciphertext[i][1]),hex(ciphertext[i][2]),hex(ciphertext[i][3]))
    hoge = [f'{ciphertext[i][j]:02X}' for i,j in product(range(4), range(4))]
    print(f"0x{''.join(hoge)}" )
    
    # print("\n\n----- DECRYPTION ------")
    # ciphertext = 0x050a74f15832aff6197d667782fa484b
    # # ciphertext = 0x69c4e0d86a7b0430d8cdb78070b4c55a
    # ret = cipher.decrypt(ciphertext)
    # print("----- plaintext ------")
    # for i in range(4):
    #     print(hex(ret[i][0]),hex(ret[i][1]),hex(ret[i][2]),hex(ret[i][3]))
