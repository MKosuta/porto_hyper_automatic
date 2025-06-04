// Botão: Ler formulário
document.getElementById('btn-falar').addEventListener('click', function () {
    const textoParaLer = [
        "Este é o extrato. Bem-vindo à plataforma.",
        "Aqui estão as opções de acessibilidade:",
        "Primeira opção: Modo de alto contraste.",
        "Segunda opção: o suporte para Libras do VLibras disponibilizado pelo governo brasileiro (Universidade Federal da Paraíba - UFPB)."
    ];

    let utterance = new SpeechSynthesisUtterance(textoParaLer.join(' '));
    utterance.rate = 0.9;
    speechSynthesis.speak(utterance);
});

// Botão: Contraste
document.getElementById('btn-contraste').addEventListener('click', function () {
    document.body.classList.toggle('contraste-ativo');
    let mensagem = document.body.classList.contains('contraste-ativo') ?
        "Modo de Alto Contraste Ativado." : "Modo de Alto Contraste Desativado.";
    let utterance = new SpeechSynthesisUtterance(mensagem);
    utterance.rate = 0.9;
    speechSynthesis.speak(utterance);
});

// Atualizar extrato
function atualizarExtrato() {
    const tbody = document.querySelector("table tbody");
    const movimentacoes = JSON.parse(localStorage.getItem("movimentacoes")) || [];
    tbody.innerHTML = "";

    movimentacoes.forEach(mov => {
        const tr = document.createElement("tr");

        const tdData = document.createElement("td");
        tdData.textContent = mov.data;
        tr.appendChild(tdData);

        const tdDesc = document.createElement("td");
        tdDesc.textContent = mov.descricao;
        tr.appendChild(tdDesc);

        const tdValor = document.createElement("td");
        tdValor.textContent = mov.valor;
        tr.appendChild(tdValor);

        tbody.appendChild(tr);
    });
}

// Chama atualização ao carregar a página
window.addEventListener("load", atualizarExtrato);

// Atualiza automaticamente se localStorage mudar em outra aba
window.addEventListener("storage", (event) => {
    if (event.key === "movimentacoes") {
        atualizarExtrato();
    }
});

// Adiciona movimentação e redireciona com voz
function adicionarMovimentacao(data, descricao, valor) {
    const movimentacoes = JSON.parse(localStorage.getItem("movimentacoes")) || [];
    movimentacoes.push({ data, descricao, valor });
    localStorage.setItem("movimentacoes", JSON.stringify(movimentacoes));

    atualizarExtrato();

    // Fala a mensagem
    const mensagem = `${descricao} registrada com sucesso. Você será redirecionado.`;
    const fala = new SpeechSynthesisUtterance(mensagem);
    fala.lang = 'pt-BR';
    fala.rate = 0.9;
    speechSynthesis.speak(fala);

    // Redireciona após pequena pausa
    setTimeout(() => {
        window.location.href = "redirecionar.html";
    }, 3000); // 3 segundos de delay para fala ser concluída
}
