document.addEventListener("DOMContentLoaded", function () {
    const btnReconhecimentoFacial = document.getElementById("btn-reconhecimento-facial");
    const btnCadastrarRosto = document.getElementById("btn-cadastrar-rosto");
    const video = document.getElementById("video");

    let modelosCarregados = false;

    function rostoCadastrado() {
        return !!localStorage.getItem("faceDescriptor");
    }

    function atualizarBotaoReconhecimento() {
        if (rostoCadastrado()) {
            btnReconhecimentoFacial.disabled = false;
            btnReconhecimentoFacial.title = "";
        } else {
            btnReconhecimentoFacial.disabled = true;
            btnReconhecimentoFacial.title = "Cadastre seu rosto antes de usar o reconhecimento facial.";
        }
    }

    atualizarBotaoReconhecimento();

    async function carregarModelosFaceAPI() {
        if (!modelosCarregados) {
            const MODEL_URL = "models";
            console.log("Carregando modelos...");
            await Promise.all([
                faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
                faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
                faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL)
            ]);
            modelosCarregados = true;
            console.log("Modelos carregados.");
        }
    }

    async function iniciarCamera() {
        console.log("Iniciando câmera...");
        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
        video.srcObject = stream;
        video.style.display = "block";
        return new Promise(resolve => {
            video.onloadedmetadata = () => {
                resolve();
                console.log("Câmera pronta.");
            };
        });
    }

    function pararCamera() {
        if (video.srcObject) {
            video.srcObject.getTracks().forEach(track => track.stop());
        }
        video.style.display = "none";
        video.pause();
        console.log("Câmera parada.");
    }

    btnCadastrarRosto.addEventListener("click", async () => {
        try {
            await carregarModelosFaceAPI();
            await iniciarCamera();

            alert("Posicione seu rosto na câmera. O cadastro ocorrerá automaticamente em 3 segundos.");

            await new Promise(r => setTimeout(r, 3000));

            const detection = await faceapi
                .detectSingleFace(video, new faceapi.TinyFaceDetectorOptions())
                .withFaceLandmarks()
                .withFaceDescriptor();

            if (detection) {
                const descriptorArray = Array.from(detection.descriptor);
                localStorage.setItem("faceDescriptor", JSON.stringify(descriptorArray));
                alert("Rosto cadastrado com sucesso!");
                atualizarBotaoReconhecimento();
            } else {
                alert("Nenhum rosto detectado. Tente novamente.");
            }

        } catch (error) {
            if (error.name === 'NotAllowedError') {
                alert("Acesso à câmera negado. Por favor, permita o uso da câmera para usar essa função.");
            } else {
                alert("Erro ao cadastrar rosto: " + error.message);
            }
            console.error(error);
        } finally {
            pararCamera();
        }
    });

    btnReconhecimentoFacial.addEventListener("click", async () => {
        if (!rostoCadastrado()) {
            alert("Nenhum rosto cadastrado. Por favor, cadastre seu rosto primeiro.");
            return;
        }

        try {
            await carregarModelosFaceAPI();
            await iniciarCamera();

            alert("Posicione seu rosto na câmera para autenticação.");

            await new Promise(r => setTimeout(r, 3000));

            const detection = await faceapi
                .detectSingleFace(video, new faceapi.TinyFaceDetectorOptions())
                .withFaceLandmarks()
                .withFaceDescriptor();

            if (!detection) {
                alert("Nenhum rosto detectado. Tente novamente.");
                return;
            }

            const storedDescriptor = new Float32Array(JSON.parse(localStorage.getItem("faceDescriptor")));
            const distance = faceapi.euclideanDistance(detection.descriptor, storedDescriptor);

            console.log("Distância do reconhecimento:", distance);

            if (distance < 0.6) {
                alert("Rosto reconhecido! Login autorizado.");
                localStorage.setItem("usuarioLogado", "true");
                window.location.href = "menu.html";
            } else {
                alert("Rosto não reconhecido. Tente novamente.");
            }

        } catch (error) {
            if (error.name === 'NotAllowedError') {
                alert("Acesso à câmera negado. Por favor, permita o uso da câmera para usar essa função.");
            } else {
                alert("Erro no reconhecimento facial: " + error.message);
            }
            console.error(error);
        } finally {
            pararCamera();
        }
    });
});
