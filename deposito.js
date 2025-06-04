document.addEventListener("DOMContentLoaded", function () {
    const btnFalar = document.getElementById("btn-falar");
    const btnContraste = document.getElementById("btn-contraste");
    const btnVoltarMenu = document.getElementById("btn-voltar-menu");
    const valorDepositoInput = document.getElementById("valor-deposito");

    // Inicializa saldo no localStorage se não existir
    if (localStorage.getItem("saldo") === null) {
        localStorage.setItem("saldo", "1250.75");
    }

    // 📢 Leitura do conteúdo da página
    if (btnFalar) {
        btnFalar.addEventListener("click", () => {
            let texto = "Bem-vindo à página de Depósito. Por favor, insira o valor que deseja depositar. As opções de acessibilidade disponíveis são: modo de alto contraste e o suporte para Libras do VLibras disponibilizado pelo governo brasileiro (Universidade Federal da Paraíba - UFPB).";
            const fala = new SpeechSynthesisUtterance(texto);
            fala.lang = 'pt-BR';
            window.speechSynthesis.speak(fala);
        });
    }

    // 🌙 Modo de Alto Contraste
    if (btnContraste) {
        btnContraste.addEventListener("click", () => {
            document.body.classList.toggle("contraste-ativo");
        });
    }

    // Formatação automática do valor do depósito
    if (valorDepositoInput) {
        valorDepositoInput.addEventListener("input", (e) => {
            let valor = e.target.value.replace(/\D/g, "");
            if (valor.length > 0) {
                valor = (Number(valor) / 100).toLocaleString('pt-BR', {
                    style: 'currency',
                    currency: 'BRL'
                });
            }
            e.target.value = valor;
        });

        valorDepositoInput.addEventListener("keydown", (e) => {
            if ((e.key === "Backspace" || e.key === "Delete") && valorDepositoInput.selectionStart <= 3) {
                e.preventDefault();
            }
        });
    }

    // Função para atualizar saldo somando o depósito
    function atualizarSaldo(valorString) {
        const valorNumerico = parseFloat(valorString.replace(/[R$\s]/g, '').replace(/\./g, '').replace(',', '.'));
        let saldoAtual = parseFloat(localStorage.getItem("saldo")) || 0;
        saldoAtual += valorNumerico;
        localStorage.setItem("saldo", saldoAtual.toFixed(2));
    }

    // Envio do formulário de depósito
    const formularioDeposito = document.getElementById("deposit-form");
    if (formularioDeposito) {
        formularioDeposito.addEventListener("submit", function (e) {
            e.preventDefault();

            const valorDeposito = valorDepositoInput.value.trim();
            const valorNumerico = parseFloat(valorDeposito.replace(/[R$\s]/g, '').replace(/\./g, '').replace(',', '.'));

            if (!valorDeposito || isNaN(valorNumerico) || valorNumerico <= 0) {
                alert("Por favor, insira um valor válido para depósito maior que zero.");
                return;
            }

            const hoje = new Date();
            const dataFormatada = hoje.toLocaleDateString('pt-BR');

            atualizarSaldo(valorDeposito);

            alert("Depósito realizado com sucesso!");

            const sucessoFala = new SpeechSynthesisUtterance("Depósito realizado com sucesso.");
            sucessoFala.lang = 'pt-BR';
            window.speechSynthesis.speak(sucessoFala);

            sucessoFala.onend = function () {
                window.location.href = "redirecionar.html";
            };
        });
    }

    if (btnVoltarMenu) {
        btnVoltarMenu.addEventListener("click", () => {
            window.location.href = "menu.html";
        });
    }
});
