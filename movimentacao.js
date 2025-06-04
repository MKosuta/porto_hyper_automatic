document.addEventListener("DOMContentLoaded", function () {
    const saldoSpan = document.getElementById("saldo-atual");
    const btnResetarSaldo = document.getElementById("btn-resetar-saldo");
    const btnVoltarLogin = document.getElementById("btn-voltar-login");

    // Função para formatar valor em R$ 1.234,56
    function formatarValor(valor) {
        return valor.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
    }

    // Pega saldo do localStorage ou inicializa com 0
    function pegarSaldo() {
        let saldo = localStorage.getItem("saldo");
        if (saldo === null) {
            saldo = 0;
            localStorage.setItem("saldo", saldo);
        } else {
            saldo = parseFloat(saldo);
        }
        return saldo;
    }

    // Salva saldo no localStorage
    function salvarSaldo(novoSaldo) {
        localStorage.setItem("saldo", novoSaldo);
    }

    // Atualiza o saldo na tela
    function atualizarSaldoTela() {
        const saldo = pegarSaldo();
        saldoSpan.textContent = formatarValor(saldo);
    }

    // Função para adicionar movimentação no histórico
    function adicionarMovimentacao(tipo, valor) {
        const movimentacoes = JSON.parse(localStorage.getItem("movimentacoes")) || [];
        const data = new Date().toLocaleString('pt-BR');
        movimentacoes.push({ data, tipo, valor });
        localStorage.setItem("movimentacoes", JSON.stringify(movimentacoes));
    }

    // Função para depositar
    function depositar(valor) {
        if (valor <= 0) {
            alert("Valor inválido para depósito.");
            return;
        }
        let saldo = pegarSaldo();
        saldo += valor;
        salvarSaldo(saldo);
        adicionarMovimentacao("Depósito", valor);
        atualizarSaldoTela();
        alert(`Depósito de ${formatarValor(valor)} realizado com sucesso!`);
    }

    // Função para sacar
    function sacar(valor) {
        let saldo = pegarSaldo();
        if (valor <= 0) {
            alert("Valor inválido para saque.");
            return;
        }
        if (valor > saldo) {
            alert("Saldo insuficiente para saque.");
            return;
        }
        saldo -= valor;
        salvarSaldo(saldo);
        adicionarMovimentacao("Saque", valor);
        atualizarSaldoTela();
        alert(`Saque de ${formatarValor(valor)} realizado com sucesso!`);
    }

    // Função para transferir
    function transferir(valor) {
        let saldo = pegarSaldo();
        if (valor <= 0) {
            alert("Valor inválido para transferência.");
            return;
        }
        if (valor > saldo) {
            alert("Saldo insuficiente para transferência.");
            return;
        }
        saldo -= valor;
        salvarSaldo(saldo);
        adicionarMovimentacao("Transferência", valor);
        atualizarSaldoTela();
        alert(`Transferência de ${formatarValor(valor)} realizada com sucesso!`);
    }

    // Resetar saldo
    btnResetarSaldo.addEventListener("click", function () {
        if (confirm("Tem certeza que deseja resetar o saldo para zero?")) {
            salvarSaldo(0);
            atualizarSaldoTela();
            localStorage.removeItem("movimentacoes");
            alert("Saldo e histórico resetados.");
        }
    });

    // Botão voltar login
    btnVoltarLogin.addEventListener("click", function () {
        window.location.href = "login.html";
    });

    // Acessibilidade (igual você já tinha)
    document.getElementById('btn-falar').addEventListener('click', function () {
        const texto = `Seu saldo atual é ${saldoSpan.textContent}`;
        const utterance = new SpeechSynthesisUtterance(texto);
        utterance.rate = 0.9;
        speechSynthesis.speak(utterance);
    });

    document.getElementById('btn-contraste').addEventListener('click', function () {
        document.body.classList.toggle('contraste-ativo');
        const texto = document.body.classList.contains('contraste-ativo') ? "Modo Alto Contraste Ativado." : "Modo Alto Contraste Desativado.";
        const utterance = new SpeechSynthesisUtterance(texto);
        utterance.rate = 0.9;
        speechSynthesis.speak(utterance);
    });

    document.getElementById('btn-libras').addEventListener('click', function () {
        const utterance = new SpeechSynthesisUtterance("Suporte Libras ainda não implementado.");
        utterance.rate = 0.9;
        speechSynthesis.speak(utterance);
    });

    // Atualiza saldo na tela quando abrir a página
    atualizarSaldoTela();

    // -- EXEMPLO para depositar/ sacar/ transferir --
    // Você pode criar formulários ou botões na sua página que chamem essas funções
    // Por exemplo:

    // Depositando R$ 100 (exemplo):
    // depositar(100);

    // Sacando R$ 50 (exemplo):
    // sacar(50);

    // Transferindo R$ 200 (exemplo):
    // transferir(200);

});
