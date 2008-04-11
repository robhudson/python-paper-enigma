"""
Enigma: Partially implements paper enigma from class

http://mckoss.com/Crypto/Enigma.htm

The original motivation to writing this was to be able to generate the Rejewski
characteristics quickly.  I've neglected a few things to focus on this goal,
for example: 
    * the adjacent rotors don't automatically shift after the  the cycle is
    completed.
"""
import string

class Enigma:

    # Rotors based on paper enigma used in class...
    # To encode what the rotors are doing, I'm making a map of position down the
    # left side of the rotor which maps to the position down the right side of
    # the rotor with the matching letter.
    rotors = [
        [20, 22, 24, 6, 0, 3, 5, 15, 21, 25, 1, 4, 2, 10, 12, 19, 7, 23, 18, 11, 17, 8, 13, 16, 14, 9],
        [0, 9, 15, 2, 25, 22, 17, 11, 5, 1, 3, 10, 14, 19, 24, 20, 16, 6, 4, 13, 7, 23, 12, 8, 21, 18],
        [19, 0, 6, 1, 15, 2, 18, 3, 16, 4, 20, 5, 21, 13, 25, 7, 24, 8, 23, 9, 22, 11, 17, 10, 14, 12]
    ]
    # Reflector is a map from one position of R3 to another...
    reflector = [24, 17, 20, 7, 16, 18, 11, 3, 15, 23, 13, 6, 14, 10, 12, 8, 4, 1, 5, 25, 2, 22, 21, 9, 0, 19]

    # For reference (and in case I need it later) here's the rotors in letter form:
    LR1 = {'A': 'E', 'B': 'K', 'C': 'M', 'D': 'F', 'E': 'L', 'F': 'G', 'G': 'D', 'H': 'Q', 'I': 'V', 'J': 'Z', 'K': 'N', 'L': 'T', 'M': 'O', 'N': 'W', 'O': 'Y', 'P': 'H', 'Q': 'X', 'R': 'U', 'S': 'S', 'T': 'P', 'U': 'A', 'V': 'I', 'W': 'B', 'X': 'R', 'Y': 'C', 'Z': 'J'}
    LR2 = {'A': 'A', 'B': 'J', 'C': 'D', 'D': 'K', 'E': 'S', 'F': 'I', 'G': 'R', 'H': 'U', 'I': 'X', 'J': 'B', 'K': 'L', 'L': 'H', 'M': 'W', 'N': 'T', 'O': 'M', 'P': 'C', 'Q': 'Q', 'R': 'G', 'S': 'Z', 'T': 'N', 'U': 'P', 'V': 'Y', 'W': 'F', 'X': 'V', 'Y': 'O', 'Z': 'E'} 
    LR3 = {'A': 'B', 'B': 'D', 'C': 'F', 'D': 'H', 'E': 'J', 'F': 'L', 'G': 'C', 'H': 'P', 'I': 'R', 'J': 'T', 'K': 'X', 'L': 'V', 'M': 'Z', 'N': 'N', 'O': 'Y', 'P': 'E', 'Q': 'I', 'R': 'W', 'S': 'G', 'T': 'A', 'U': 'K', 'V': 'M', 'W': 'U', 'X': 'S', 'Y': 'Q', 'Z': 'O'}

    def __init__(self):
        # Default rotor order
        self.set_rotor_order((1,2,3))
        # Initial rotor positions
        self.rotor_tuple = (0,0,0)
        self.reset()

    def set_rotor_order(self, order_tuple):
        # tuple should be of form (1,2,3) or (3,2,1) etc.
        self.rotor_order = order_tuple
        # these just provide a reference to the rotor
        self.R1 = self.rotors[order_tuple[0]-1]
        self.R2 = self.rotors[order_tuple[1]-1]
        self.R3 = self.rotors[order_tuple[2]-1]

    def set_rotors(self, rotor_tuple):
        self.rotor_tuple = rotor_tuple
        self.reset()

    def reset(self):
        self.p1, self.p2, self.p3 = self.rotor_tuple

    def encode(self, letter):
        """
        Converts letter to another letter as it gets transposed through the
        rotors and reflector.
        """
        if not letter.upper() in string.uppercase:
            return ''

        self.p3 += 1
        # zero based letter plus rotation mod 26 is 3rd rotor right hand side (RHS)
        r3_r_pos = ((ord(letter.upper()) - 65) + self.p3) % 26
        # Take r3 RHS and get r3 LHS
        r3_l_pos = self.R3.index(r3_r_pos)
        # Now find r3_l_pos position in rotor 2
        r2_r_pos = (r3_l_pos - self.p3) % 26
        r2_l_pos = self.R2.index(r2_r_pos)
        # Now find r2_l_pos position in rotor 1
        r1_r_pos = (r2_l_pos - self.p2) % 26
        r1_l_pos = self.R1.index(r1_r_pos)
        # Now perform reflection
        l0 = self.reflector[(r1_l_pos - self.p1) % 26]
        # Now go back to the right...
        r1_l_pos = (l0 + self.p1) % 26
        r1_r_pos = self.R1[r1_l_pos]
        r2_l_pos = (r1_r_pos + self.p2) % 26
        r2_r_pos = self.R2[r2_l_pos]
        r3_l_pos = (r2_r_pos + self.p3) % 26
        r3_r_pos = self.R3[r3_l_pos]
        letter = chr(((r3_r_pos - self.p3) % 26) + 65)
        return letter

    def encrypt(self, plaintext):
        ciphertext = ''
        for letter in plaintext:
            ciphertext += self.encode(letter)
        return ciphertext
        
    def dict2cycle(self, dict):
        """
        E.g. {'a':'b','b':'c','c':'a'} -> [(a,b,c)]
        """
        cycles = []
        
        while len(dict) > 0:
            cycle = [dict.keys()[0]]
            while 1:
                next = dict[cycle[-1]]
                del(dict[cycle[-1]])
                if next == cycle[0]:
                    break
                cycle.append(next)
            if len(cycle) > 0:
                cycles.append(tuple(cycle))

        return cycles

    def generate_rejewski_signatures(self, sigs = {}):
        """
        Rejewski Signatures are a way to crack the Enigma code.
        See: http://en.wikipedia.org/wiki/Marian_Rejewski
        """

        # List of all 26 letters repeated 6 times (eg: 'AAAAAA')
        alph_plaintext = []
        for i in range(65,91):
            alph_plaintext.append(chr(i) * 6)

        num_loops = 0
        rotors = (0,0,0)

        while True:
            num_loops += 1
            self.set_rotors(rotors)

            alph_ciphertext = []
            for code in alph_plaintext:
                ct = self.encrypt(code)
                alph_ciphertext.append(ct)
                self.reset()

            # Make cycles from resulting encodings
            a1a4, a2a5, a3a6 = ({}, {}, {})
            for code in alph_ciphertext:
                a1a4[code[0]] = code[3]
                a2a5[code[1]] = code[4]
                a3a6[code[2]] = code[5]
            cycle1 = self.dict2cycle(a1a4)
            cycle2 = self.dict2cycle(a2a5)
            cycle3 = self.dict2cycle(a3a6)

            # Get cycle signature
            csig1, csig2, csig3 = ([], [], [])

            tmp = []
            for c in cycle1:
                tmp.append(len(c))
            tmp.sort()
            for i,v in enumerate(tmp):
                if i%2==0:
                    csig1.append(v)

            tmp = []
            for c in cycle2:
                tmp.append(len(c))
            tmp.sort()
            for i,v in enumerate(tmp):
                if i%2==0:
                    csig2.append(v)

            tmp = []
            for c in cycle3:
                tmp.append(len(c))
            tmp.sort()
            for i,v in enumerate(tmp):
                if i%2==0:
                    csig3.append(v)

            try:
                sigs["%s%s%s" % (csig1, csig2, csig3)].append("%s%s" % (self.rotor_order, rotors))
            except KeyError:
                sigs["%s%s%s" % (csig1, csig2, csig3)] = ["%s%s" % (self.rotor_order, rotors)]

            # Perform odometer rotations on rotors
            r1, r2, r3 = rotors
            # Break if we've gone through all rotations in 2 right most rotors
            if r1 == 25 and r2 == 25 and r3 == 25:
                break
            r3 += 1
            if r3 > 25:
                r3 = 0
                r2 += 1
            if r2 > 25:
                r2 = 0
                r1 += 1
            rotors = (r1, r2, r3)

        return (num_loops, sigs)

    def generate_all_rejewski(self):
        """
        Out of curiousity I wanted to see all signatures generated and see if
        there were collisions -- more than one setting that produced the same
        signature.
        """

        all_rotor_orderings = [(1,2,3),(1,3,2),(2,1,3),(2,3,1),(3,1,2),(3,2,1)]
        sig2rotor = {}
        total_rotors = 0
        num_loops = 0

        for orderings in all_rotor_orderings:
            self.set_rotor_order(orderings)
            loops, sig2rotor = self.generate_rejewski_signatures(sig2rotor)
            num_loops += loops

        # We're done, now look for items in sig2rotor with more than 1 item
        
        total_sigs = len(sig2rotor.keys())
        collisions = 0
        for k, v in sig2rotor.iteritems():
            if len(v) > 1:
                collisions += 1
        print "Total number of settings calculated: %d" % num_loops
        print "Total unique signatures calculated: %d" % total_sigs
        # Total number of rotor orders and settings producing more than one signature
        print "%d collisions (rotors orders and settings producing the same signature)" % (collisions)

        return sig2rotor

    def generate_zygalski(self):
        """
        Zygalski sheets are another way to crack Enigma machines.
        See: http://en.wikipedia.org/wiki/Zygalski_sheets

        Note: This implementation was never verified for correctness.
        """
        
        # List of coordinates that have a female
        coords1 = []
        coords2 = []
        coords3 = []

        # Encrypt all 26 letters
        alph_plaintext = []
        for i in range(65,91):
            alph_plaintext.append(chr(i) * 6)

        rotors = (1,0,0)
        while True:
            self.set_rotors(rotors)

            alph_ciphertext = []
            for code in alph_plaintext:
                ct = self.encrypt(code)
                alph_ciphertext.append(ct)
                self.reset()
                
                # Look for females
                if ct[0] == ct[3]:
                    coords1.append((rotors[1], rotors[2]))
                if ct[1] == ct[4]:
                    coords2.append((rotors[1], rotors[2]))
                if ct[2] == ct[5]:
                    coords3.append((rotors[1], rotors[2]))

            # Increment rotors but keep left most fixed
            r1, r2, r3 = rotors
            r3 += 1
            if r3 > 25:
                r3 = 0
                r2 += 1
            if r2 > 25:
                break
            rotors = (r1, r2, r3)

        # Now display Zygalski sheet
        for i in range(3):
            if i == 0: 
                coords = coords1; 
                #print "Females a1a4"
            if i == 1: 
                coords = coords2; 
                #print "Females a2a5"
            if i == 2: 
                coords = coords3; 
                #print "Females a3a6"
            print " - | %s" % (' '.join(string.uppercase))
            for i in range(26):
                line = ' %s |' % (chr(i + 65))
                for j in range(26):
                    if (i, j) in coords:
                        line += ' O'
                    else:
                        line += ' .'
                print line

if __name__ == '__main__':

    import sys

    e = Enigma()

    if '-rj' in sys.argv:
        e.generate_rejewski()
    elif '-zg' in sys.argv:
        e.generate_zygalski()

