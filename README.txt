MOZ BUSINESS — VERSÃO LIGADA AO SUPABASE

Esta versão mantém o Flask e a autenticação do aplicativo, mas usa o PostgreSQL do Supabase quando DATABASE_URL está definida. Sem DATABASE_URL, funciona localmente com SQLite para testes.

PACOTES
- Básico: 500 MT — aparece nas pesquisas.
- Premium: 700 MT — pesquisa + perfil completo, fotos, serviços, contactos e redes sociais.
- Anúncio: 1.500 MT — publicidade para TikTok e Facebook; vídeo até 30 segundos; sujeito a aprovação.

PAGAMENTOS
- Apenas M-Pesa e e-Mola.
- M-Pesa oficial: 858804425
- e-Mola oficial: 865742391
- Cada pagamento guarda o plan_code e o valor escolhidos.
- Quando o webhook confirma PAID, o pacote comprado é ativado na empresa.

SUPABASE
O SQL de criação das tabelas já foi executado no projeto Supabase. Para produção, configure DATABASE_URL no Render. Consulte SUPABASE_CONFIGURACAO.txt.

SEGURANÇA
- Nunca publique DATABASE_URL, service_role ou segredos Pagar no código.
- Troque o acesso inicial de administrador antes de colocar o serviço em produção.
- A configuração de RLS deve ser feita antes de expor tabelas diretamente ao navegador. O Flask usa a conexão do servidor.

LIMITAÇÕES ATUAIS
- O pagamento real Pagar ainda depende de credenciais/KYC e configuração do webhook.
- O limite de 30 segundos ainda é validado pelo campo enviado pelo formulário; deve ser reforçado com inspeção real do ficheiro de vídeo antes do lançamento.
- Uploads locais em Render não são armazenamento permanente; para produção, usar armazenamento de objetos.
