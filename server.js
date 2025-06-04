const express = require('express');
const app = express();
const webauthn = require('./utils/webauthn');

app.use(express.json()); // para interpretar JSON no corpo da requisição

// Registro de credencial - início
app.post('/webauthn/register/start', (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username é obrigatório' });
  }

  // Busca usuário ou cria novo
  let user = webauthn.getUser(username) || webauthn.generateUser(username);

  // Gera opções para registro
  const options = webauthn.generateRegistrationOptions(user);

  // Salva o desafio atual no usuário para verificação futura
  user.currentChallenge = options.challenge;

  res.json(options);
});

// Registro de credencial - finalização
app.post('/webauthn/register/finish', async (req, res) => {
  const { username, attestation } = req.body;
  if (!username || !attestation) {
    return res.status(400).json({ error: 'Dados incompletos para verificação' });
  }

  const user = webauthn.getUser(username);
  if (!user) return res.status(400).json({ error: 'Usuário não encontrado' });

  try {
    // Verifica a resposta do cliente
    const verification = await webauthn.verifyRegistrationResponse(attestation, user);
    if (verification.verified) {
      // Aqui você pode salvar as credenciais do usuário no banco/dados
      user.credentials = user.credentials || [];
      user.credentials.push(verification.registrationInfo);
    }
    res.json({ verified: verification.verified });
  } catch (err) {
    console.error('Erro na verificação de registro:', err);
    res.status(500).json({ error: 'Falha na verificação de registro' });
  }
});

// Autenticação - início
app.post('/webauthn/login/start', (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username é obrigatório' });
  }

  const user = webauthn.getUser(username);

  if (!user || !user.credentials || user.credentials.length === 0) {
    return res.status(400).json({ error: 'Credenciais não registradas' });
  }

  // Gera opções para autenticação
  const options = webauthn.generateAuthenticationOptions(user);

  // Salva o desafio atual no usuário para verificação futura
  user.currentChallenge = options.challenge;

  res.json(options);
});

// Autenticação - finalização
app.post('/webauthn/login/finish', async (req, res) => {
  const { username, assertion } = req.body;
  if (!username || !assertion) {
    return res.status(400).json({ error: 'Dados incompletos para autenticação' });
  }

  const user = webauthn.getUser(username);
  if (!user) return res.status(400).json({ error: 'Usuário não encontrado' });

  try {
    // Verifica a resposta da autenticação
    const verification = await webauthn.verifyAuthenticationResponse(assertion, user);

    if (verification.verified) {
      // Pode marcar sessão, token, etc.
      return res.json({ verified: true, message: 'Autenticação bem-sucedida' });
    } else {
      return res.status(401).json({ verified: false, error: 'Falha na autenticação' });
    }
  } catch (err) {
    console.error('Erro na verificação de autenticação:', err);
    res.status(500).json({ error: 'Erro na autenticação' });
  }
});

module.exports = app;  // caso queira importar em outro arquivo
