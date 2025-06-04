// Máscara para valor (R$)
const campoValor = document.getElementById("valor");

campoValor.addEventListener("input", (e) => {
    let valor = e.target.value.replace(/\D/g, ""); // remove não números
    const valorFormatado = (Number(valor) / 100).toLocaleString('pt-BR', {
        style: 'currency',
        currency: 'BRL'
    });
    e.target.value = valorFormatado;
});

campoValor.addEventListener("keydown", (e) => {
    if (
        (e.key === "Backspace" || e.key === "Delete") &&
        campoValor.selectionStart <= 3
    ) {
        e.preventDefault();
    }
});

// Acessibilidade com voz
document.getElementById("btn-ler-formulario").addEventListener("click", () => {
    const mensagem = `Esta é a página de poupança. As opções de acessibilidade são: 
    Modo alto contraste e Suporte para Libras do VLibras disponibilizado pelo governo brasileiro (Universidade Federal da Paraíba - UFPB)..`;
    
    const fala = new SpeechSynthesisUtterance(mensagem);
    fala.lang = "pt-BR";
    fala.rate = 0.8; // Ritmo mais natural
    speechSynthesis.speak(fala);
});

// Função para adicionar movimentação no localStorage
function adicionarMovimentacao(data, descricao, valor) {
    const movimentacoes = JSON.parse(localStorage.getItem("movimentacoes")) || [];
    movimentacoes.push({ data, descricao, valor });
    localStorage.setItem("movimentacoes", JSON.stringify(movimentacoes));
}

// Controle de saldo (sem exibição)
const SALDO_PADRAO = 1250.75;

function obterSaldo() {
    const saldoSalvo = localStorage.getItem("saldo");
    if (saldoSalvo === null) {
        localStorage.setItem("saldo", SALDO_PADRAO.toFixed(2));
        return SALDO_PADRAO;
    }
    return parseFloat(saldoSalvo);
}

function salvarSaldo(novoSaldo) {
    localStorage.setItem("saldo", novoSaldo.toFixed(2));
}

function atualizarSaldoAoTransferir(valorTransferido) {
    let saldoAtual = obterSaldo();
    saldoAtual -= valorTransferido;
    if (saldoAtual < 0) saldoAtual = 0;
    salvarSaldo(saldoAtual);
}

// Função para Transferir
document.getElementById("btn-transferir").addEventListener("click", () => {
    const valor = campoValor.value.replace(/[^\d,]/g, "").replace(",", ".").trim();
    const valorNum = parseFloat(valor);

    if (valor && !isNaN(valorNum) && valorNum > 0) {
        const saldoAtual = obterSaldo();

        if (valorNum > saldoAtual) {
            const falaSaldo = new SpeechSynthesisUtterance("Saldo insuficiente para essa transferência.");
            falaSaldo.lang = "pt-BR";
            falaSaldo.rate = 0.9;
            speechSynthesis.speak(falaSaldo);
            return;
        }

        atualizarSaldoAoTransferir(valorNum);

        const hoje = new Date();
        const dataFormatada = hoje.toLocaleDateString('pt-BR');
        const valorFormatado = valorNum.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });

        adicionarMovimentacao(dataFormatada, "Transferência para Poupança", valorFormatado);

        const falaSucesso = new SpeechSynthesisUtterance("Transferência para a poupança realizada com sucesso.");
        falaSucesso.lang = "pt-BR";
        falaSucesso.rate = 0.9;
        speechSynthesis.speak(falaSucesso);

        falaSucesso.onend = () => {
            window.location.href = "redirecionar.html";
        };
        
    } else {
        const fala = new SpeechSynthesisUtterance("Por favor, insira um valor válido para a transferência.");
        fala.lang = "pt-BR";
        fala.rate = 0.9;
        speechSynthesis.speak(fala);
    }
});

// Modo alto contraste
let contrasteAtivo = false;

document.getElementById("btn-contraste").addEventListener("click", () => {
    contrasteAtivo = !contrasteAtivo;

    if (contrasteAtivo) {
        document.body.classList.add("contraste-ativo");
        const fala = new SpeechSynthesisUtterance("Modo alto contraste ativado.");
        fala.lang = "pt-BR";
        fala.rate = 0.9;
        speechSynthesis.speak(fala);
    } else {
        document.body.classList.remove("contraste-ativo");
        const fala = new SpeechSynthesisUtterance("Modo alto contraste desativado.");
        fala.lang = "pt-BR";
        fala.rate = 0.9;
        speechSynthesis.speak(fala);
    }
});

// Voltar ao Menu
document.getElementById("btn-voltar-menu").addEventListener("click", () => {
    window.location.href = "menu.html";
});
