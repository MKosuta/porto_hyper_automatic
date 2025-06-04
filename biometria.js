document.addEventListener("DOMContentLoaded", function () {
    const btnCadastrarBiometria = document.getElementById("btn-cadastrar-biometria");
    const btnBiometria = document.getElementById("btn-biometria");

    // Verificar se o dispositivo suporta biometria (WebAuthn)
    async function checkBiometricSupport() {
        if (!window.PublicKeyCredential) {
            console.log("WebAuthn não é suportado");
            return false;
        }
        try {
            const isAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            return isAvailable;
        } catch (error) {
            console.error("Erro ao verificar suporte:", error);
            return false;
        }
    }

    // Gerar um desafio criptográfico aleatório
    function generateChallenge() {
        const challenge = new Uint8Array(32);
        window.crypto.getRandomValues(challenge);
        return challenge;
    }

    // 🔹 Desabilitar botões se não houver suporte
    checkBiometricSupport().then(supported => {
        if (!supported) {
            btnCadastrarBiometria.disabled = true;
            btnBiometria.disabled = true;
            btnCadastrarBiometria.title = "Biometria não disponível neste dispositivo.";
            btnBiometria.title = "Biometria não disponível neste dispositivo.";
        }
    });

    // ✅ Registro da biometria
    btnCadastrarBiometria.addEventListener("click", async () => {
        try {
            const supported = await checkBiometricSupport();
            if (!supported) {
                alert("Biometria não disponível.");
                return;
            }

            const publicKey = {
                challenge: generateChallenge(),
                rp: {
                    name: "Hyper Automatic Bank"
                },
                user: {
                    id: new Uint8Array(16), // ID aleatório
                    name: "usuario",
                    displayName: "Usuario"
                },
                pubKeyCredParams: [
                    { type: "public-key", alg: -7 },    // ES256
                    { type: "public-key", alg: -257 }   // RS256
                ],
                authenticatorSelection: {
                    authenticatorAttachment: "platform",
                    userVerification: "required"
                },
                timeout: 60000,
                attestation: "none"
            };

            const credential = await navigator.credentials.create({ publicKey });

            if (credential) {
                const data = {
                    rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                    id: credential.id,
                    type: credential.type
                };

                localStorage.setItem("biometria", JSON.stringify(data));
                alert("Biometria cadastrada com sucesso!");
                console.log("Credencial registrada:", credential);
            }
        } catch (error) {
            console.error("Erro no registro biométrico:", error);
            alert("Erro no registro biométrico: " + error.message);
        }
    });

    // 🔒 Login com biometria
    btnBiometria.addEventListener("click", async () => {
        try {
            const supported = await checkBiometricSupport();
            if (!supported) {
                alert("Biometria não disponível.");
                return;
            }

            const storedCredential = localStorage.getItem("biometria");
            if (!storedCredential) {
                alert("Nenhuma biometria cadastrada.");
                return;
            }

            const parsedCredential = JSON.parse(storedCredential);

            const publicKey = {
                challenge: generateChallenge(),
                allowCredentials: [
                    {
                        id: Uint8Array.from(atob(parsedCredential.rawId), c => c.charCodeAt(0)),
                        type: "public-key",
                        transports: ["internal"]
                    }
                ],
                userVerification: "required",
                timeout: 60000
            };

            const assertion = await navigator.credentials.get({ publicKey });

            if (assertion) {
                console.log("Autenticação biométrica bem-sucedida:", assertion);
                localStorage.setItem("usuarioLogado", "true");
                alert("Autenticação biométrica realizada com sucesso!");
                window.location.href = "menu.html";
            }
        } catch (error) {
            console.error("Erro na autenticação:", error);
            let msg = "Erro na autenticação: ";
            switch (error.name) {
                case "NotAllowedError":
                    msg += "Operação cancelada ou nenhuma credencial encontrada.";
                    break;
                case "SecurityError":
                    msg += "Biometria requer HTTPS ou localhost.";
                    break;
                default:
                    msg += error.message;
            }
            alert(msg);
        }
    });
});
