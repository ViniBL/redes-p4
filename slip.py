class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        self.buffer = bytearray()
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        # TODO: Preencha aqui com o código para enviar o datagrama pela linha
        # serial, fazendo corretamente a delimitação de quadros e o escape de
        # sequências especiais, de acordo com o protocolo CamadaEnlace (RFC 1055).
        datagrama = bytearray(datagrama)

        if 0xdb in datagrama:
            rep_lst = [0xdb, 0xdd]
            rep_idxs = [i if item == 0xdb else None for i, item in enumerate(datagrama)]
            for i in rep_idxs:
                if i is not None:
                    datagrama.pop(i)
                    datagrama.insert(i, rep_lst[1])
                    datagrama.insert(i, rep_lst[0])

        if 0xc0 in datagrama:
            rep_lst = [0xdb, 0xdc]
            rep_idxs = [i if item == 0xc0 else None for i, item in enumerate(datagrama)]
            for i in rep_idxs:
                if i is not None:
                    datagrama.pop(i)
                    datagrama.insert(i, rep_lst[1])
                    datagrama.insert(i, rep_lst[0])

        # envelopa
        datagrama.insert(0, 0xc0)
        datagrama.append(0xc0)
        datagrama = bytes(datagrama)
        self.linha_serial.enviar(datagrama)

    def __raw_recv(self, dados):
        # TODO: Preencha aqui com o código para receber dados da linha serial.
        # Trate corretamente as sequências de escape. Quando ler um quadro
        # completo, repasse o datagrama contido nesse quadro para a camada
        # superior chamando self.callback. Cuidado pois o argumento dados pode
        # vir quebrado de várias formas diferentes - por exemplo, podem vir
        # apenas pedaços de um quadro, ou um pedaço de quadro seguido de um
        # pedaço de outro, ou vários quadros de uma vez só.
        def _callback(data):
            data = data.replace(b'\xdb\xdd', b'\xdb')
            data = data.replace(b'\xdb\xdc', b'\xc0')
            self.callback(data)
            self.buffer = bytearray()

        if dados == b'0':
            return

        dados = bytearray(dados)

        if dados == bytearray(0xc0):
            if self.buffer != b'': # 0xc0 eh final
                self._callback(dados)

            else: # 0xc0 eh começo
                return

        else:
            if 0xc0 in dados:
                start_flag = False
                for b in dados:
                    self.buffer.append(b)

                    if b == 0xc0 and start_flag:
                        start_flag = False

                    elif b == 0xc0 and not start_flag:
                        self._callback(self.buffer)
                        start_flag = True
