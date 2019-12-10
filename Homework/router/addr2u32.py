s = input()
s = list(map(lambda x: hex(int(x))[2:].zfill(2), s.split('.')))
print(f'0x{s[3]}{s[2]}{s[1]}{s[0]}')
