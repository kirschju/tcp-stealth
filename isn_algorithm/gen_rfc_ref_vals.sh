gcc -o gen_isn gen_isn.c -lcrypto
./gen_isn 6 2001:db8::2a:2a 4242 0x11223344 "Magic secret string" q
./gen_isn 6 2001:db8::2a:2a 4242 0x11223344 "Magic secret string" 28 "Protected payload goes here." q
./gen_isn 4 192.18.42.42 4242 0x11223344 "Magic secret string" q
./gen_isn 4 192.18.42.42 4242 0x11223344 "Magic secret string" 28 "Protected payload goes here." q
