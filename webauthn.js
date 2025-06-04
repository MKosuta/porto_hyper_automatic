const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const { v4: uuidv4 } = require('uuid');

const rpName = 'Meu Projeto';
const rpID = 'localhost';
const origin = `http://${rpID}:3000`; // HTTP no localhost para dev

// Banco de dados em memória (substitua por DB real)
const users = {};

module.exports = {
  getUser: (username) => users[username],

  generateUser: (username) => {
    const id = uuidv4();
    users[username] = {
      id,
      username,
      credentials: [],
      currentChallenge: null,
    };
    return users[username];
  },

  generateRegistrationOptions: (user) => generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id,
    userName: user.username,
    attestationType: 'none',
    authenticatorSelection: {
      userVerification: 'required',
      residentKey: 'preferred',
    },
    timeout: 60000,
  }),

  verifyRegistrationResponse: async (response, user) => {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      // Salva credentialID como Buffer para facilitar comparações futuras
      const credential = verification.registrationInfo.credential;
      credential.credentialID = Buffer.from(credential.credentialID);
      user.credentials.push(credential);
    }

    return verification;
  },

  generateAuthenticationOptions: (user) => {
    return generateAuthenticationOptions({
      rpID,
      timeout: 60000,
      allowCredentials: user.credentials.map(cred => ({
        id: cred.credentialID,      // já Buffer
        type: 'public-key',
        transports: cred.transports || ['internal'],
      })),
      userVerification: 'required',
    });
  },

  verifyAuthenticationResponse: async (response, user) => {
    // Convertendo rawId recebido para Buffer para comparação
    const rawIdBuffer = Buffer.from(response.rawId, 'base64url');

    // Busca credencial pelo credentialID igual ao rawId do assertion
    const authenticator = user.credentials.find(cred => cred.credentialID.equals(rawIdBuffer));

    if (!authenticator) {
      throw new Error('Credencial não encontrada para autenticação');
    }

    return await verifyAuthenticationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator,
    });
  }
};
