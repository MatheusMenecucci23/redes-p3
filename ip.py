from iputils import *
import ipaddress
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
        self.tabela_encaminhamento = []


    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)

            # Decrementar o TTL antes de encaminhar o datagrama
            ttl -= 1

            if ttl <= 0:
                # Descartar o datagrama se o TTL chegar a zero
                
                return

            # Corrigir o checksum do cabeçalho IP após decrementar o TTL
            header = struct.pack('!BBHHHBBH4s4s', (4 << 4) | 5, dscp << 2 | ecn, 
                                 len(datagrama), identification, 
                                 (flags << 13) | frag_offset, ttl, proto, 0, 
                                 str2addr(src_addr), str2addr(dst_addr))
            
            checksum = calc_checksum(header)
            header = struct.pack('!BBHHHBBH4s4s', (4 << 4) | 5, dscp << 2 | ecn, 
                                 len(datagrama), identification, 
                                 (flags << 13) | frag_offset, ttl, proto, checksum, 
                                 str2addr(src_addr), str2addr(dst_addr))

            # Encaminhar o datagrama para o próximo roteador
            self.enlace.enviar(header + payload, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        dest_ip = ipaddress.IPv4Address(dest_addr)

        longest_prefix_length = -1
        next_hop = None

        for cidr, next_hop_addr in self.tabela_encaminhamento:
            network, prefix_length = cidr.split('/')
            prefix_length = int(prefix_length)  # Convertendo para inteiro
            network_ip = ipaddress.IPv4Network(cidr, strict=False)

            if dest_ip in network_ip and prefix_length > longest_prefix_length:
                longest_prefix_length = prefix_length
                next_hop = next_hop_addr

        return next_hop

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
        self.tabela_encaminhamento = tabela

        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        # Montando o cabeçalho IP
        src_addr = self.meu_endereco
        dst_addr = dest_addr
        version_ihl = (4 << 4) | 5  # Versão IPv4 (4) e IHL (5 palavras de 32 bits)
        dscp_ecn = 0
        total_length = 20 + len(segmento)  # Tamanho do cabeçalho IP + tamanho do payload (segmento)
        identification = 0
        flags_offset = 0
        ttl = 64  # Time-to-Live padrão (pode ser alterado conforme necessário)
        proto = IPPROTO_TCP  # Protocolo TCP (pode ser alterado conforme necessário)
        header_checksum = 0  # Calculado posteriormente
        src_addr_bytes = str2addr(src_addr)
        dst_addr_bytes = str2addr(dst_addr)

        # Montando o cabeçalho IP em formato de bytes
        header = struct.pack('!BBHHHBBH4s4s', version_ihl, dscp_ecn, total_length,
                             identification, flags_offset, ttl, proto, header_checksum,
                             src_addr_bytes, dst_addr_bytes)

        # Calculando o checksum do cabeçalho IP
        if not self.ignore_checksum:
            header_checksum = calc_checksum(header)
            header = struct.pack('!BBHHHBBH4s4s', version_ihl, dscp_ecn, total_length,
                                 identification, flags_offset, ttl, proto, header_checksum,
                                 src_addr_bytes, dst_addr_bytes)

        # Montando o datagrama completo com o cabeçalho IP e o payload (segmento)
        datagrama = header + segmento

        # Enviando o datagrama através da camada de enlace
        self.enlace.enviar(datagrama, next_hop)
