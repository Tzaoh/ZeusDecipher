import r2pipe
import sys
import json


def main(args):
    r2 = r2pipe.open(args[1])
    
    # Desteamos ajustes de la interfaz
    r2.cmd('e asm.describe = false')
    r2.cmd('e asm.pseudo = false')
    
    r2.cmd('aaa')
    
    # Sacamos todas las referencias a la función de descifrado de cadenas
    refs = r2.cmdj('axfj 0x00410d39')
    
    # Recorremos las referencias
    strs = []
    for ref in refs:
        
        # Si la referencia es una "call"
        if ref['type'] == 'C':
        
            # Cogemos las tres últimas instrucciones
            last_instr = r2.cmdj('pdj -3 @ {}'.format(ref['from']))
            
            for inst in last_instr:
                
                # Si alguna de estas instrucciones es un push
                if inst['type'] == 'push':
                    strs.append(dec_string(r2, inst['val']))
                
                # O si un mov a ecx con un de 'ptr'
                elif 'mov ecx' in inst['opcode'] and 'ptr' in inst.keys():
                    strs.append(dec_string(r2, inst['ptr']))
                
    print("\n".join(strs))

def dec_string(r2, offset):
    str = ''
    
    # Byte con el que xorear
    chr_xor = r2.cmd('px 1 @ {}~:1[1]'.format(0x4034f0 + offset * 8))
    chr_xor = int(chr_xor, 16)
    
    # Direccion donde leer la string cifrada
    addr = r2.cmd('pxW 4 @ {}~[1]'.format(0x4034f4 + offset * 8))
    c_str = r2.cmdj('pcj 255 @ {}'.format(addr))
    c_str = c_str[0:c_str.index(0)]
    
    i = 0
    for c in c_str:
        str += chr(c ^ chr_xor ^ i)
        i += 1
    
    return str
    
if __name__ == "__main__":
    main(sys.argv)        
    