=====================================README=====================================
# Python Paper Enigma

Partially implements paper Enigma found here:
[http://mckoss.com/Crypto/Enigma.htm](http://mckoss.com/Crypto/Enigma.htm)

The original motivation to writing this was to be able to generate the Rejewski
characteristics quickly.  I've neglected a few things to focus on this goal,
for example: 

* the adjacent rotors don't automatically shift after the cycle is completed.

Example usage:

    >>> from enigma import Enigma
    >>> e = Enigma()
    >>> e.encrypt('ATTACK AT DAWN')
    'BZHGNOCRRTCM'

