document.addEventListener("DOMContentLoaded", function () {
    const valorInput = document.getElementById("valor");
    const bancoInput = document.getElementById("banco-destino");
    const agenciaInput = document.getElementById("agencia-destino");
    const contaInput = document.getElementById("conta-destino");

    // Formata valor com R$ e vírgula
    valorInput.addEventListener("input", function () {
        let valor = valorInput.value.replace(/\D/g, '');
        if (valor.length > 0) {
            let numero = Number(valor) / 100;
            valorInput.value = numero.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
        } else {
            valorInput.value = "";
        }
    });

    // Formata Banco (3 dígitos)
    bancoInput.addEventListener("input", function () {
        bancoInput.value = bancoInput.value.replace(/\D/g, '').slice(0, 3);
    });

    // Formata Agência (4 dígitos)
    agenciaInput.addEventListener("input", function () {
        agenciaInput.value = agenciaInput.value.replace(/\D/g, '').slice(0, 4);
    });

    // Formata Conta Corrente (até 6 números + hífen + 1 dígito)
    contaInput.addEventListener("input", function () {
        let conta = contaInput.value.replace(/\D/g, '').slice(0, 7);
        if (conta.length > 1) {
            conta = conta.replace(/^(\d{1,6})(\d{1})$/, "$1-$2");
        }
        contaInput.value = conta;
    });

    // Função para adicionar movimentação no localStorage
    function adicionarMovimentacao(data, descricao, valor) {
        const movimentacoes = JSON.parse(localStorage.getItem("movimentacoes")) || [];
        movimentacoes.push({ data, descricao, valor });
        localStorage.setItem("movimentacoes", JSON.stringify(movimentacoes));
    }

    // Botão Transferir (com fala de sucesso e redirecionamento direto)
    document.getElementById("btn-transferir").addEventListener("click", function () {
        const valor = valorInput.value.trim();
        const banco = bancoInput.value.trim();
        const agencia = agenciaInput.value.trim();
        const conta = contaInput.value.trim();

        if (!valor || !banco || !agencia || !conta) {
            let utteranceErro = new SpeechSynthesisUtterance("Por favor, preencha todos os campos.");
            utteranceErro.rate = 0.9;
            speechSynthesis.speak(utteranceErro);
            return;
        }

        let saldoAtual = parseFloat(localStorage.getItem("saldo")) || 0;

        let valorNumerico = Number(valor.replace(/[R$\s\.]/g, '').replace(',', '.'));

        if (valorNumerico > saldoAtual) {
            let utteranceSaldo = new SpeechSynthesisUtterance("Saldo insuficiente para esta transferência.");
            utteranceSaldo.rate = 0.9;
            speechSynthesis.speak(utteranceSaldo);
            return;
        }

        saldoAtual -= valorNumerico;
        localStorage.setItem("saldo", saldoAtual.toFixed(2));

        const hoje = new Date();
        const dataFormatada = hoje.toLocaleDateString('pt-BR');
        adicionarMovimentacao(dataFormatada, "Transferência", valor);

        let utteranceSucesso = new SpeechSynthesisUtterance("Transferência realizada com sucesso.");
        utteranceSucesso.rate = 0.9;

        utteranceSucesso.onend = function() {
            window.location.href = "redirecionar.html";
        };

        speechSynthesis.speak(utteranceSucesso);
    });

    // Leitor de tela
    document.getElementById('btn-ler-formulario').addEventListener('click', function () {
        const textoParaLer = [
            "Este é o formulário de transferência. Por favor, insira o banco, agência, conta e o valor da transferência. Se preferir, utilize as opções de acessibilidade como o modo de alto contraste e o suporte para Libras do VLibras disponibilizado pelo governo brasileiro (Universidade Federal da Paraíba - UFPB).",
            "Clique em Transferir para completar a ação."
        ];
        let utterance = new SpeechSynthesisUtterance(textoParaLer.join(' '));
        utterance.rate = 0.9;
        speechSynthesis.speak(utterance);
    });

    // Contraste
    document.getElementById('btn-contraste').addEventListener('click', function () {
        document.body.classList.toggle('contraste-ativo');
        let texto = document.body.classList.contains('contraste-ativo') ? "Modo de Alto Contraste Ativado." : "Modo de Alto Contraste Desativado.";
        let utterance = new SpeechSynthesisUtterance(texto);
        utterance.rate = 0.9;
        speechSynthesis.speak(utterance);
    });
});
