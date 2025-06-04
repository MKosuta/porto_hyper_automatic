document.addEventListener("DOMContentLoaded", function () {
    const btnFalar = document.getElementById("btn-falar");
    const btnContraste = document.getElementById("btn-contraste");
    const btnVoltarMenu = document.getElementById("btn-voltar-menu");

    const valorSaqueInput = document.getElementById("valor-saque");
    const saqueContagem = document.getElementById("saque-contagem");

    // 📢 Leitura do conteúdo da página
    if (btnFalar) {
        btnFalar.addEventListener("click", () => {
            let texto = "Bem-vindo à página de Saque. Por favor, insira o valor que deseja sacar no campo abaixo. O valor deverá ser informado com o símbolo R$. As opções de acessibilidade disponíveis são: modo de alto contraste e o suporte para Libras do VLibras disponibilizado pelo governo brasileiro (Universidade Federal da Paraíba - UFPB).";
            texto += " Se precisar de assistência, utilize o modo de alto contraste.";

            const fala = new SpeechSynthesisUtterance(texto);
            fala.lang = 'pt-BR';
            fala.volume = 1;
            fala.rate = 1;
            fala.pitch = 1;

            window.speechSynthesis.speak(fala);
        });
    }

    // 🌙 Modo de Alto Contraste
    if (btnContraste) {
        btnContraste.addEventListener("click", () => {
            const corpo = document.body;

            let modoContraste;

            if (corpo.classList.contains("contraste-ativo")) {
                corpo.classList.remove("contraste-ativo");
                modoContraste = "O modo de alto contraste foi desativado.";
            } else {
                corpo.classList.add("contraste-ativo");
                modoContraste = "O modo de alto contraste foi ativado.";
            }

            const fala = new SpeechSynthesisUtterance(modoContraste);
            fala.lang = 'pt-BR';
            fala.volume = 1;
            fala.rate = 1;
            fala.pitch = 1;

            window.speechSynthesis.speak(fala);
        });
    }

    // Formatação e validação do valor do saque
    if (valorSaqueInput) {
        valorSaqueInput.addEventListener("input", function () {
            let valor = valorSaqueInput.value.replace(/\D/g, ''); // Remove qualquer caractere não numérico
            if (valor.length > 0) {
                valor = "R$ " + valor.replace(/(\d)(\d{2})$/, '$1,$2'); // Formata com vírgula
            }
            valorSaqueInput.value = valor;

            if (saqueContagem) {
                saqueContagem.textContent = `${valor.length}/10`;
            }
        });
    }

    // Função para adicionar movimentação
    function adicionarMovimentacao(data, descricao, valor) {
        const movimentacoes = JSON.parse(localStorage.getItem("movimentacoes")) || [];
        movimentacoes.push({ data, descricao, valor });
        localStorage.setItem("movimentacoes", JSON.stringify(movimentacoes));
    }

    // Envio do formulário saque
    const formularioSaque = document.getElementById("saque-form");
    if (formularioSaque) {
        formularioSaque.addEventListener("submit", function (e) {
            e.preventDefault();

            const valorRaw = valorSaqueInput.value.replace(/\D/g, '');
            const valorNumero = Number(valorRaw) / 100;

            if (valorNumero > 0) {
                let saldoAtual = parseFloat(localStorage.getItem("saldo")) || 0;

                if (valorNumero > saldoAtual) {
                    alert("Saldo insuficiente para este saque.");
                    return;
                }

                saldoAtual -= valorNumero;
                localStorage.setItem("saldo", saldoAtual.toFixed(2));

                const hoje = new Date();
                const dataFormatada = hoje.toLocaleDateString('pt-BR');
                const valorFormatado = valorNumero.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });

                adicionarMovimentacao(dataFormatada, "Saque", valorFormatado);

                // Voz confirmando o saque
                const falaSaque = new SpeechSynthesisUtterance("Saque realizado com sucesso.");
                falaSaque.lang = 'pt-BR';
                falaSaque.volume = 1;
                falaSaque.rate = 1;
                falaSaque.pitch = 1;

                falaSaque.onend = () => {
                    // Redirecionamento direto após falar o sucesso
                    window.location.href = "redirecionar.html";
                };

                window.speechSynthesis.speak(falaSaque);

            } else {
                alert("Por favor, insira um valor válido para saque.");
            }
        });
    }

    // Voltar ao menu
    if (btnVoltarMenu) {
        btnVoltarMenu.addEventListener("click", function () {
            window.location.href = "menu.html";
        });
    }
});
