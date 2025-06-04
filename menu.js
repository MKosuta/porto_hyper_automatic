document.addEventListener("DOMContentLoaded", function () {

    const btnFalar = document.getElementById("btn-falar");
    const btnContraste = document.getElementById("btn-contraste");

    const btnSaldo = document.getElementById("btn-saldo");
    const btnSaque = document.getElementById("btn-saque");
    const btnDeposito = document.getElementById("btn-deposito");
    const btnExtrato = document.getElementById("btn-extrato");
    const btnTransferencia = document.getElementById("btn-transferencia");
    const btnPoupanca = document.getElementById("btn-poupanca");

    const btnVoltarLogin = document.getElementById("btn-voltar-login");

    if (!localStorage.getItem("saldo")) {
        localStorage.setItem("saldo", "1250.75");
    }

    btnSaldo.addEventListener("click", () => {
        window.location.href = "saldo.html";
    });

    btnFalar.addEventListener("click", () => {
        let texto = "Bem-vindo ao Menu. Você pode acessar as opções: Saldo, Saque, Depósito, Extrato, Transferência e Poupança. ";
        texto += "Também estão disponíveis recursos de acessibilidade como modo de alto contraste e suporte para Libras do VLibras disponibilizado pelo governo brasileiro (Universidade Federal da Paraíba - UFPB).";

        const fala = new SpeechSynthesisUtterance(texto);
        fala.lang = 'pt-BR';
        fala.volume = 1;
        fala.rate = 1;
        fala.pitch = 1;

        window.speechSynthesis.speak(fala);
    });

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

    btnSaque.addEventListener("click", () => {
        window.location.href = "saque.html";
    });

    btnDeposito.addEventListener("click", () => {
        window.location.href = "deposito.html";
    });

    btnExtrato.addEventListener("click", () => {
        window.location.href = "extrato.html";
    });

    btnTransferencia.addEventListener("click", () => {
        window.location.href = "transferencia.html";
    });

    btnPoupanca.addEventListener("click", () => {
        window.location.href = "poupanca.html";
    });

    btnVoltarLogin.addEventListener("click", () => {
        localStorage.removeItem("logado");
        window.location.href = "login.html";
    });
});
