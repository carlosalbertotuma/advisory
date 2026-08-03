# Advisory de Segurança — [NOME DA VULNERABILIDADE]

> **Identificador:** [CVE-AAAA-NNNNN / ID interno]  
> **Data de publicação:** [DD/MM/AAAA]  
> **Última atualização:** [DD/MM/AAAA]  
> **Severidade:** [Crítica / Alta / Média / Baixa]  
> **CVSS:** [0.0] — `[VETOR CVSS]`  
> **CWE:** [CWE-NNN — Nome da fraqueza]  
> **Status:** [Corrigida / Mitigação disponível / Sem correção / Em investigação]

---

## 1. Resumo executivo

Foi identificada uma vulnerabilidade em **[produto, sistema ou componente]**, nas versões **[versões afetadas]**, que permite que **[tipo de atacante ou condição necessária]** realize **[ação principal]**.

A exploração bem-sucedida pode resultar em **[impacto principal: execução de código, acesso não autorizado, exposição de dados, elevação de privilégio, indisponibilidade etc.]**.

A organização responsável foi notificada em **[data]** e **[resumo da resposta do fornecedor]**.

---

## 2. Produtos afetados

| Produto / Componente | Versões afetadas | Versão corrigida | Status |
|---|---:|---:|---|
| [Produto 1] | [Versões] | [Versão] | [Afetado/Corrigido] |
| [Produto 2] | [Versões] | [Versão] | [Afetado/Corrigido] |

### Produtos não afetados

- [Produto ou versão não afetada]
- [Produto ou versão não afetada]

---

## 3. Descrição da vulnerabilidade

A vulnerabilidade ocorre devido a **[causa técnica da falha]**.

O componente **[nome do componente, endpoint, função ou módulo]** não realiza corretamente **[validação, autenticação, autorização, sanitização, controle de acesso, tratamento de sessão etc.]**, permitindo que um atacante **[resultado técnico da exploração]**.

### Condições necessárias

- [Autenticação necessária ou não]
- [Tipo de usuário ou privilégio necessário]
- [Acesso local, remoto ou à rede interna]
- [Interação do usuário, quando aplicável]
- [Configuração específica necessária]

---

## 4. Impacto

A exploração pode permitir:

- [Impacto 1]
- [Impacto 2]
- [Impacto 3]
- [Impacto 4]

### Impacto sobre a confidencialidade

[Descreva se dados podem ser visualizados, extraídos ou expostos.]

### Impacto sobre a integridade

[Descreva se dados, configurações ou operações podem ser alterados.]

### Impacto sobre a disponibilidade

[Descreva se o serviço pode ser interrompido, degradado ou indisponibilizado.]

---

## 5. Classificação

### CVSS

- **Pontuação:** [0.0]
- **Severidade:** [Crítica / Alta / Média / Baixa]
- **Vetor:** `[CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]`

### CWE

- **[CWE-NNN — Nome da fraqueza]**

### CAPEC, quando aplicável

- **[CAPEC-NNN — Nome do padrão de ataque]**

---

## 6. Cenário de exploração

Um possível cenário de exploração ocorre da seguinte forma:

1. O atacante identifica uma instância vulnerável de **[produto]**.
2. O atacante envia **[requisição, arquivo, entrada ou payload]** ao componente vulnerável.
3. A aplicação processa o conteúdo sem **[controle de segurança ausente]**.
4. O atacante consegue **[resultado da exploração]**.
5. Como consequência, pode ocorrer **[impacto final]**.

---

## 7. Evidências técnicas

### Componente afetado

```text
[Nome do endpoint, arquivo, classe, função, parâmetro ou módulo]
```

### Requisição de exemplo

```http
[MÉTODO] /[CAMINHO] HTTP/1.1
Host: [HOST]
Content-Type: [TIPO]

[CORPO DA REQUISIÇÃO OU PARÂMETROS]
```

### Resposta observada

```http
HTTP/1.1 [CÓDIGO]
Content-Type: [TIPO]

[RESPOSTA RELEVANTE]
```

### Resultado

[Descreva objetivamente o comportamento observado e por que ele comprova a vulnerabilidade.]

> **Nota:** Remova tokens, cookies, credenciais, dados pessoais, endereços internos e outros segredos antes da publicação.

---

## 8. Prova de conceito

A prova de conceito abaixo demonstra apenas o comportamento vulnerável e deve ser utilizada exclusivamente em ambientes autorizados.

```bash
# Comando ou exemplo mínimo para reproduzir a vulnerabilidade
[POC CONTROLADA]
```

### Resultado esperado

```text
[RESULTADO QUE CONFIRMA A VULNERABILIDADE]
```

### Limitações da PoC

- Não causa indisponibilidade intencional.
- Não remove ou modifica dados de terceiros.
- Não cria persistência ou backdoor.
- Não contém credenciais reais.
- Não automatiza exploração em massa.


$x = $_POST["fid"];
$y = $_POST["pass"];

$sql = "select * from facutlytable where FID='" . $x . "' and Pass='" . $y . "'";

Because the input is not sanitized, attackers can inject SQL like:

Bypass de autenticação

Campo FID

' OR '1'='1' -- -

<img width="1155" height="470" alt="image" src="https://github.com/user-attachments/assets/bea6f85c-0cb6-42a8-b742-27919ed73b42" />

<img width="1292" height="296" alt="image" src="https://github.com/user-attachments/assets/ce13bbf7-4765-4a17-8dac-edfe67ff78fa" />

---

## 9. Passos para reprodução

1. Instale ou acesse a versão **[versão afetada]**.
2. Configure **[pré-requisito]**.
3. Acesse **[endpoint ou funcionalidade]**.
4. Envie **[entrada ou requisição]**.
5. Observe **[resultado vulnerável]**.
6. Compare com o comportamento esperado: **[comportamento seguro]**.

---

## 10. Mitigação

Até que a correção definitiva seja aplicada, recomenda-se:

- Restringir o acesso ao componente afetado.
- Desabilitar temporariamente **[função vulnerável]**, quando possível.
- Aplicar regras de firewall, WAF, proxy reverso ou ACL.
- Revisar permissões e privilégios associados.
- Monitorar requisições ou eventos relacionados a **[indicador]**.
- Invalidar credenciais, tokens ou sessões potencialmente expostos.
- Manter logs e evidências para investigação.

> As mitigações reduzem o risco, mas podem não eliminar completamente a vulnerabilidade.

---

## 11. Correção

A correção foi disponibilizada na versão **[versão corrigida]**.

Recomenda-se:

1. Atualizar imediatamente para **[versão corrigida]** ou superior.
2. Reiniciar os serviços afetados, quando necessário.
3. Invalidar sessões e credenciais antigas.
4. Revisar logs anteriores à atualização.
5. Confirmar que o comportamento vulnerável não pode mais ser reproduzido.

### Alteração implementada

[Descreva, em alto nível, a correção aplicada pelo fornecedor.]

---

## 12. Detecção e indicadores

Possíveis indicadores de exploração:

- Requisições para **[endpoint]** contendo **[padrão]**.
- Erros incomuns relacionados a **[componente]**.
- Criação ou modificação inesperada de **[arquivo, usuário ou configuração]**.
- Execução de processos anormais pelo usuário **[usuário do serviço]**.
- Conexões de saída não esperadas.
- Aumento anormal de erros HTTP **[códigos]**.

### Exemplo de busca em logs

```text
[EXPRESSÃO, REGEX, QUERY SIEM OU FILTRO]
```

---

## 13. Timeline de divulgação

| Data | Evento |
|---|---|
| [DD/MM/AAAA] | Vulnerabilidade identificada |
| [DD/MM/AAAA] | Primeira notificação enviada ao fornecedor |
| [DD/MM/AAAA] | Confirmação de recebimento |
| [DD/MM/AAAA] | Vulnerabilidade validada |
| [DD/MM/AAAA] | CVE solicitada ou reservada |
| [DD/MM/AAAA] | Correção disponibilizada |
| [DD/MM/AAAA] | Advisory publicado |
| [DD/MM/AAAA] | Última atualização |

---

## 14. Comunicação com o fornecedor

- **Fornecedor:** [Nome]
- **Canal utilizado:** [E-mail, formulário, programa de bug bounty, CERT etc.]
- **Data da primeira notificação:** [DD/MM/AAAA]
- **Status da resposta:** [Respondido / Sem resposta / Em análise]
- **Posicionamento do fornecedor:** [Resumo objetivo]

---

## 15. Créditos

A vulnerabilidade foi identificada e reportada por:

- **Pesquisador:** [Nome ou pseudônimo]
- **Organização:** [Nome da organização]
- **Contato:** [E-mail profissional]
- **Perfil:** [GitHub, LinkedIn, site ou identificador]

Agradecimentos:

- [Fornecedor]
- [CERT/CSIRT]
- [Colaboradores]

---

## 16. Referências

- [Link do advisory do fornecedor]
- [Link do registro CVE]
- [Link do NVD]
- [Link da documentação do produto]
- [Link do CWE]
- [Link do patch ou commit]
- [Outras referências técnicas]

---

## 17. Histórico de revisões

| Versão | Data | Alteração |
|---|---|---|
| 1.0 | [DD/MM/AAAA] | Publicação inicial |
| 1.1 | [DD/MM/AAAA] | Atualização de versões afetadas |
| 1.2 | [DD/MM/AAAA] | Inclusão de correção ou novos indicadores |

---

## 18. Aviso legal

Este advisory é publicado com finalidade educacional, defensiva e de melhoria da segurança.

As informações apresentadas foram obtidas em ambiente autorizado e divulgadas de forma responsável ou coordenada. O autor não incentiva o uso destas informações para acesso não autorizado, interrupção de serviços, violação de privacidade ou qualquer atividade ilegal.

A utilização das informações deste documento é de responsabilidade exclusiva do leitor.

---

## 19. Contato

Para correções, atualizações ou informações adicionais:

- **E-mail:** [E-MAIL]
- **Site:** [SITE]
- **Chave PGP:** [LINK OU FINGERPRINT]
