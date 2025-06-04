document.addEventListener("DOMContentLoaded", function () {
    
    // Elementos do DOM
    const btnFalar = document.getElementById("btn-falar");
    const btnContraste = document.getElementById("btn-contraste");
    const btnBiometria = document.getElementById("btn-biometria");
    const btnReconhecimentoFacial = document.getElementById("btn-reconhecimento-facial");
    const btnCadastrarRosto = document.getElementById("btn-cadastrar-rosto");
    const cpfInput = document.getElementById("cpf");
    const senhaInput = document.getElementById("password");
    const cpfContagem = document.getElementById("cpf-contagem");
    const senhaContagem = document.getElementById("senha-contagem");
    const video = document.getElementById("video");
    const formulario = document.getElementById("login-form");

    // ====== FUNÇÕES DE ACESSIBILIDADE ======
    
    // Fala - Ler conteúdo
    btnFalar.addEventListener("click", () => {
        const texto = "Bem-vindo ao sistema. Por favor, insira seu CPF e senha contendo quatro dígitos para acessar sua conta. Se precisar, ative o modo de alto contraste, o suporte para Libras do VLibras disponibilizado pelo governo brasileiro (Universidade Federal da Paraíba - UFPB), ou utilize a biometria e reconhecimento facial. Caso não tenha cadastrado seu rosto ou sua biometria, cadastre logo abaixo";
        falarTexto(texto);
    });

    // Contraste
    btnContraste.addEventListener("click", () => {
        document.body.classList.toggle("contraste-ativo");
        const mensagem = document.body.classList.contains("contraste-ativo") 
            ? "Modo alto contraste ativado" 
            : "Modo alto contraste desativado";
        falarTexto(mensagem);
    });

    // ====== VALIDAÇÃO DE CAMPOS ======
    
    // Formatação do CPF (xxx.xxx.xxx-xx)
    cpfInput.addEventListener("input", function () {
        let valor = this.value.replace(/\D/g, '');
        
        // Limita a 11 dígitos
        if (valor.length > 11) {
            valor = valor.substring(0, 11);
        }
        
        // Aplica máscara
        let valorFormatado = '';
        for (let i = 0; i < valor.length; i++) {
            if (i === 3 || i === 6) {
                valorFormatado += '.';
            } else if (i === 9) {
                valorFormatado += '-';
            }
            valorFormatado += valor[i];
        }
        
        this.value = valorFormatado;
        cpfContagem.textContent = valor.length + '/11';
    });

    // Validação da senha (4 dígitos numéricos)
    senhaInput.addEventListener("input", function () {
        let valor = this.value.replace(/\D/g, '');
        
        if (valor.length > 4) {
            valor = valor.substring(0, 4);
        }
        
        this.value = valor;
        senhaContagem.textContent = valor.length + '/4';
    });

    // Impede caracteres não numéricos
    function apenasNumeros(event) {
        const charCode = (event.which) ? event.which : event.keyCode;
        if (charCode > 31 && (charCode < 48 || charCode > 57)) {
            event.preventDefault();
            return false;
        }
        return true;
    }

    cpfInput.addEventListener("keypress", apenasNumeros);
    senhaInput.addEventListener("keypress", apenasNumeros);

    // ====== AUTENTICAÇÃO ======
    
    // Login tradicional
    formulario.addEventListener("submit", function (e) {
        e.preventDefault();
        
        const cpfValido = cpfInput.value.length === 14 && /^\d{3}\.\d{3}\.\d{3}-\d{2}$/.test(cpfInput.value);
        const senhaValida = senhaInput.value.length === 4 && /^\d{4}$/.test(senhaInput.value);
        
        if (!cpfValido) {
            alert("CPF inválido. Deve conter 11 dígitos no formato 000.000.000-00");
            return;
        }
        
        if (!senhaValida) {
            alert("Senha inválida. Deve conter exatamente 4 dígitos numéricos.");
            return;
        }
        
        // Simula login bem-sucedido
        localStorage.setItem("logado", "true");
        window.location.href = "menu.html";
    });

    // Biometria
    btnBiometria.addEventListener("click", async () => {
        btnBiometria.disabled = true; // desabilita para evitar múltiplos cliques
        try {
            if (!window.PublicKeyCredential) {
                alert("Seu navegador não suporta autenticação biométrica.");
                return;
            }
            
            const credential = await navigator.credentials.get({
                publicKey: {
                    challenge: new Uint8Array([0x8C, 0x7B, 0x44, 0x29, 0xF2, 0xDD, 0x98, 0x34]).buffer,
                    timeout: 60000,
                    userVerification: "required",
                }
            });
            
            if (credential) {
                localStorage.setItem("logado", "true");
                window.location.href = "menu.html";
            }
        } catch (err) {
            alert("Erro na autenticação biométrica: " + err.message);
        } finally {
            btnBiometria.disabled = false; // reabilita
        }
    });

    // Reconhecimento Facial
    btnReconhecimentoFacial.addEventListener("click", async () => {
        btnReconhecimentoFacial.disabled = true; // desabilita o botão
        const descriptorArmazenado = localStorage.getItem("descriptorRosto");
        
        if (!descriptorArmazenado) {
            alert("Nenhum rosto cadastrado. Por favor, cadastre seu rosto primeiro.");
            btnReconhecimentoFacial.disabled = false;
            return;
        }
        
        let stream;
        try {
            video.style.display = "block";
            stream = await navigator.mediaDevices.getUserMedia({ video: true });
            video.srcObject = stream;
            
            await carregarModelosFaceAPI();
            
            const detection = await faceapi.detectSingleFace(video, new faceapi.TinyFaceDetectorOptions())
                .withFaceLandmarks()
                .withFaceDescriptor();
            
            if (!detection) {
                throw new Error("Rosto não detectado");
            }
            
            const descriptorAtual = Array.from(detection.descriptor);
            const descriptorSalvo = JSON.parse(descriptorArmazenado);
            
            const distancia = faceapi.euclideanDistance(descriptorAtual, descriptorSalvo);
            
            if (distancia < 0.6) { // Threshold arbitrário
                localStorage.setItem("logado", "true");
                window.location.href = "menu.html";
            } else {
                alert("Reconhecimento facial falhou. Tente novamente.");
            }
        } catch (error) {
            alert("Erro no reconhecimento facial: " + error.message);
        } finally {
            if (stream) {
                stream.getTracks().forEach(track => track.stop());
            }
            video.style.display = "none";
            btnReconhecimentoFacial.disabled = false; // reabilita o botão
        }
    });

    // Cadastro de Rosto
    btnCadastrarRosto.addEventListener("click", async () => {
        btnCadastrarRosto.disabled = true; // desabilita o botão
        let stream;
        try {
            video.style.display = "block";
            stream = await navigator.mediaDevices.getUserMedia({ video: true });
            video.srcObject = stream;
            
            await carregarModelosFaceAPI();
            
            setTimeout(async () => {
                try {
                    const detection = await faceapi.detectSingleFace(video, new faceapi.TinyFaceDetectorOptions())
                        .withFaceLandmarks()
                        .withFaceDescriptor();
                    
                    if (!detection) {
                        throw new Error("Rosto não detectado");
                    }
                    
                    localStorage.setItem("descriptorRosto", JSON.stringify(Array.from(detection.descriptor)));
                    alert("Rosto cadastrado com sucesso!");
                } catch (error) {
                    alert("Erro ao detectar rosto: " + error.message);
                } finally {
                    if (stream) {
                        stream.getTracks().forEach(track => track.stop());
                    }
                    video.style.display = "none";
                    btnCadastrarRosto.disabled = false; // reabilita o botão
                }
            }, 3000);
        } catch (error) {
            alert("Erro ao cadastrar rosto: " + error.message);
            if (stream) {
                stream.getTracks().forEach(track => track.stop());
            }
            video.style.display = "none";
            btnCadastrarRosto.disabled = false;
        }
    });

    // ====== FUNÇÕES AUXILIARES ======
    
    function falarTexto(texto) {
        const utterance = new SpeechSynthesisUtterance(texto);
        utterance.lang = 'pt-BR';
        window.speechSynthesis.speak(utterance);
    }
    
    async function carregarModelosFaceAPI() {
        await faceapi.nets.tinyFaceDetector.loadFromUri('/models');
        await faceapi.nets.faceLandmark68Net.loadFromUri('/models');
        await faceapi.nets.faceRecognitionNet.loadFromUri('/models');
    }
});
