# Interface Windows

[Esboço no Figma](https://www.figma.com/design/BQNC74KJoWRbj8JC0fIpOl?node-id=5-136).
As telas Proxy e Settings usam camadas editáveis, auto layout, variáveis de cor
e um botão da biblioteca Simple Design System. Os valores de tráfego do esboço
são exemplos; o cliente mostra contadores da sessão atual.

A tela principal reúne estado do proxy local, servidor, token e ação de conexão.
Portas, reserva, timeout e CA ficam em Opções. Fechar a janela mantém o proxy na
bandeja; Sair encerra as conexões. “Proxy ativo” significa que o listener local
está aberto. A conexão remota é verificada quando uma aplicação usa o proxy.

O renderer usa Dear ImGui e DirectX 11. A fonte Inter acompanha o executável,
sob licença SIL OFL. Cores: fundo `#141716`, campos `#1e2220`, borda `#343b37`,
texto `#eef1ef`, texto secundário `#a1aaa4` e ação `#b8ecd0`. As transições usam
interpolação exponencial de 180 ms. Não há animações contínuas quando o proxy
está parado. O renderer pausa enquanto a janela fica oculta ou minimizada.

ImGui não oferece a mesma integração de acessibilidade dos controles Win32.
Há navegação por teclado, mas suporte a leitores de tela permanece uma limitação.
