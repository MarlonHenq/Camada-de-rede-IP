from iputils import *
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.id = 0
        self.tabela_encaminhamento = {} #usando dicionário
        # Se prox é -1, ainda não foi identificado um próximo salto. Isso é alterado em _next_hop
        self.prox = -1

    #PASSO 4 e 5
    def __raw_recv(self, datagrama):
        _, _, _, _, _, ttl, proto, src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            self.prox = -1
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            # desempacotar os valores do datagrama:
            # mesmas variaveis utilizadas na função de construir datagrama!
            verNheader, dscpNecn, length, _, flagNfrag, _, protocolo, _, orig, dest = struct.unpack('!BBHHHBBHII', datagrama[:20]) 
            #checksum = 0
            prev_exec = [ verNheader, dscpNecn, length, self.id, flagNfrag, ttl, protocolo, 0, orig, dest]
            # Se ainda podemos saltar, continua construindo
            if ttl > 1:
                datagrama = self.buildDatagram(payload, None, prev_exec)
            else:
                # Quando ttl expira, utilizamos o protocolo ICMP que tem valor 1.
                # em buildDatagram usamos 6, que é o valor para o protocolo TCP
                protocolo = 1
                self.prox = -1
                next_hop = self._next_hop(src_addr)
                
                dest = next_hop
                # Se o próximo endereço tem distância 0, é a própria pessoa
                if self.prox == 0:
                    dest = src_addr
                
                # orig = endereço de origem
                # dest = endereço de destino
                orig, = struct.unpack('!I', str2addr(self.meu_endereco))
                dest, = struct.unpack('!I', str2addr(dest))
                
                # resetamos o ttl a 64, para a volta do sinal
                # checksum = 0
                prev_exec = [ verNheader, dscpNecn, length, self.id, flagNfrag, 64, protocolo, 0, orig, dest]
                
                # Passo 5 - gerar ICMP time exceed
                # tipo de mensagem Time Exceed
                type = 0x0b
                # código 0 para 'TTL expirado'
                code = 0
                # checksum inicial
                checksum = 0
                # não ha bits não-utilizados
                unused = 0
                # ihl - internet header length, isolamos os últimos 4 bites de verNheader
                ihl = verNheader & 0x0f
                # tam - tamanho dos dados que serão incluidos no ICMP time exceed
                # ihl é o número de palavras no cabeçalho IP. Convertemos em bytes
                # multiplicando por 4. Depois somamos 8, para conter os primeiros 8
                # bytes do payload, algo necessário em mensagems de 'Time Exceed'
                tam = 8 + (4 * ihl)
                
                #calculo do checksum, há 0 bits não-utilizados
                icmp_header = struct.pack('!BBHI', type, code, checksum, unused) + (datagrama[:tam])
                
                checksum = calc_checksum(icmp_header)

                icmp_header = struct.pack('!BBHI', type, code, checksum, unused) + (datagrama[:tam])
                
                # prev_exec[2] = length
                prev_exec[2] = len(icmp_header) + 20
                
                datagrama = self.buildDatagram(icmp_header, None, prev_exec)
                self.enlace.enviar(datagrama, next_hop)
                return
                
            self.enlace.enviar(datagrama, next_hop)

    #PASSO 1 e 3
    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        
        destino, = struct.unpack('!I', str2addr(dest_addr))
        print(f'destino em inteiro {destino}')
        print(f'opções armazenadas em self.table: {self.tabela_encaminhamento}')
        # na tabela_encaminhamento
        # chaves - cidr
        # valores - next_hop
        for key in self.tabela_encaminhamento.keys():
            cidr, bits_prefix = key.split('/') #pegamos o valor do cidr
            prefix = int(bits_prefix) #cast para int do prefixo cidr
            bits_prefix = 32 - prefix
            cidr, = struct.unpack('!I', str2addr(cidr))
            # retiramos os bits indicados no prefixo, e voltamos para o tamanho correto
            cidr = cidr >> bits_prefix << bits_prefix
            dest = destino >> bits_prefix << bits_prefix
            
            if (dest == cidr):
                # proximidade definida como o comprimento do prefixo cidr
                self.prox = prefix
                return self.tabela_encaminhamento[key]

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        # ^ utilizamos dicionário.
        
        #Se tabela já está definida, limpamos e continuamos a inicialização,
        #evitando a mistura de dados antigos e novos
        if len(self.tabela_encaminhamento) != 0: self.tabela_encaminhamento.clear()
        
        #tabela contém pares de (cidr, next_hop). Ordenaremos pelo tamanho dos prefixos
        tabela.sort(key = self.get_prefix_length, reverse = True)
        
        #usando a estrutura dicionário, definimos a chave
        #endereco[0], que é o cidr, e a ligamos com o valor
        #endereco[1], que é o next_hop
        for endereco in tabela:
            self.tabela_encaminhamento[endereco[0]] = endereco[1]
            
    # função auxiliar para o ordenamento da tabela    
    def get_prefix_length(self, bits):
        #bits[0] é o cidr
        #bits[1] é o next_hop
        #definimos uma função que ordena a tabela para que os prefixos
        #cidr com tamanho maior venham primeiro
        return int(bits[0].split('/')[1])
    
    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback
        
    #PASSO 2
    def buildDatagram(self, segmento, dest_addr, prev_exec = None):
        # Se não tivermos informações prévias, inicializamos necessárias todas as variaveis manualmente
        if prev_exec == None:
            # versão do protocolo ip (v4)
            # tamanho do cabeçalho ihl (5 palavras de 32 bits)
            verNheader = 0x45
            # campos dscp e ecn
            dscpNecn = 0x00
            # comprimento do datagrama
            length = 20 + len(segmento)
            # id único do datagrama
            address = self.id
            # flags e offset de fragmentação
            flagNfrag = 0x00
            # time to live, numero de saltos antes de ser descartado
            ttl = 64
            # protocolo 6 é TCP
            protocolo = 6
            # checksum será calculado depois
            checksum = 0
            # orig = endereço de origem
            # dest = endereço de destino
            orig, = struct.unpack('!I', str2addr(self.meu_endereco))
            dest, = struct.unpack('!I', str2addr(dest_addr))
            # aumenta o indice p/ próx execução
            self.id += length
        else:
            verNheader, dscpNecn, length, address, flagNfrag, ttl, protocolo, checksum, orig, dest = prev_exec
            ttl -= 1

        # criação do cabeçalho IP com checksum 0
        header = struct.pack('!BBHHHBBHII', verNheader, dscpNecn, length, address, flagNfrag, ttl, protocolo, checksum, orig, dest)

        # cálculo do checksum
        checksum = calc_checksum(header)

        # criação do cabeçalho IP com checksum correto
        header = struct.pack('!BBHHHBBHII', verNheader, dscpNecn, length, address, flagNfrag, ttl, protocolo, checksum, orig, dest) 
        
        # Coloca o segmento depois do cabeçalho, pra mandar pra camada de enlace
        datagrama = header + segmento

        return datagrama

    #PASSO 2
    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        
        #segmento: o segmento TCP que será encapsulado em um datagrama IP
        # buildDatagram - constroi o cabeçalho IP
        datagrama = self.buildDatagram(segmento, dest_addr)
        self.enlace.enviar(datagrama, next_hop)
        
    

        