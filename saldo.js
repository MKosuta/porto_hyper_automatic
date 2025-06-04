document.addEventListener("DOMContentLoaded", function () {
    const btnFalar = document.getElementById("btn-falar");
    const btnContraste = document.getElementById("btn-contraste");
    const btnLibras = document.getElementById("btn-libras"); // corrigido para minúsculo
    const btnVoltarLogin = document.getElementById("btn-voltar-login");
    const saldoAtualSpan = document.getElementById("saldo-atual");
    const btnResetarSaldo = document.getElementById("btn-resetar-saldo");

    // Inicializa saldo no localStorage se não existir
    if (localStorage.getItem("saldo") === null) {
        localStorage.setItem("saldo", "1250.75");
    }

    // Função para atualizar exibição do saldo
    function atualizarSaldo() {
        const saldo = parseFloat(localStorage.getItem("saldo")).toFixed(2);
        saldoAtualSpan.textContent = `R$ ${saldo}`;
    }

    atualizarSaldo();

    // Altera o texto do botão de leitura para "Ler Formulário"
    btnFalar.textContent = "🔊 Ler Formulário";

    // 🔊 Leitura do formulário (acessibilidade)
    btnFalar.addEventListener("click", () => {
        const saldo = parseFloat(localStorage.getItem("saldo")).toFixed(2);
        const texto = `Seu saldo atual é de R$ ${saldo}. Você pode voltar ao login ou ativar opções de acessibilidade como alto contraste ou suporte para LIBRAS do VLibras disponibilizado pelo governo brasileiro (Universidade Federal da Paraíba - UFPB).`;
        const fala = new SpeechSynthesisUtterance(texto);
        fala.lang = 'pt-BR';
        fala.volume = 1;
        fala.rate = 1;
        fala.pitch = 1;
        window.speechSynthesis.speak(fala);
    });

    // 🌙 Modo Alto Contraste
    btnContraste.addEventListener("click", () => {
        const corpo = document.body;
        let mensagem;
        if (corpo.classList.contains("contraste-ativo")) {
            corpo.classList.remove("contraste-ativo");
            mensagem = "O modo de alto contraste foi desativado.";
        } else {
            corpo.classList.add("contraste-ativo");
            mensagem = "O modo de alto contraste foi ativado.";
        }
        const fala = new SpeechSynthesisUtterance(mensagem);
        fala.lang = 'pt-BR';
        fala.volume = 1;
        fala.rate = 1;
        fala.pitch = 1;
        window.speechSynthesis.speak(fala);
    });

    // 🤟 Suporte LIBRAS (simulado)
    btnLibras.addEventListener("click", () => {
        const mensagem = "O suporte para LIBRAS foi ativado. (Em desenvolvimento)";
        const fala = new SpeechSynthesisUtterance(mensagem);
        fala.lang = 'pt-BR';
        fala.volume = 1;
        fala.rate = 1;
        fala.pitch = 1;
        window.speechSynthesis.speak(fala);
    });

    // 🔙 Voltar ao login
    btnVoltarLogin.addEventListener("click", () => {
        window.location.href = "redirecionar.html";
    });

    // Botão para resetar saldo
    btnResetarSaldo.addEventListener("click", () => {
        if (confirm("Deseja resetar o saldo para R$ 1250,75?")) {
            localStorage.setItem("saldo", "1250.75");
            atualizarSaldo();
            alert("Saldo resetado com sucesso!");
        }
    });

    // Aqui você pode adicionar funções para alterar o saldo (exemplo saque, depósito) e sempre chamar atualizarSaldo() e atualizar o valor no localStorage
});
