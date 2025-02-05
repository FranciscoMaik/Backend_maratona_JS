const express = require("express");
const bcrypt = require("bcrypt");
const { Account } = require("../models");
const { accountSignUp, accountSignIn } = require("../validators/account");
const { getMessage } = require("../helpers/messages");
const {
  generateJwt,
  generateRereshJwt,
  getTokenFromHeaders,
  verifyRefreshJwt,
} = require("../helpers/jwt");

const router = express.Router();

const saltRounds = 10;

// Função de Login
router.post("/sign-in", accountSignIn, async (req, res) => {
  const { email, password } = req.body;
  const account = await Account.findOne({ where: { email } });

  // Validar a senha
  const match = account ? bcrypt.compareSync(password, account.password) : null;
  if (!match) {
    return res.jsonBadRequest(null, postMessage("account.signin.invalid"));
  }

  const token = generateJwt({ id: account.id });
  const refreshToken = generateRereshJwt({
    id: account.id,
    version: account.jwtVersion,
  });

  return res.jsonOK(account, getMessage("account.signin.sucess"), {
    token,
    refreshToken,
  });
});

// Função de criação de Login
router.post("/sign-up", accountSignUp, async (req, res) => {
  const { email, password } = req.body;

  const account = await Account.findOne({ where: { email } });
  if (account)
    return res.jsonBadRequest(null, getMessage("account.signup.email_exists"));

  const hash = bcrypt.hashSync(password, saltRounds);
  console.log(hash);
  const newAccount = await Account.create({
    email,
    password: hash,
  });

  const token = generateJwt({ id: newAccount.id });
  const refreshToken = generateRereshJwt({
    id: newAccount.id,
    version: newAccount.jwtVersion,
  });

  return res.jsonOK(newAccount, getMessage("account.signup.sucess"), {
    token,
    refreshToken,
  });
});

router.post("/refresh", async (req, res) => {
  const token = getTokenFromHeaders(req.headers);
  if (!token) {
    return res.jsonUnauthorized(null, "Invalid token");
  }

  try {
    const decoded = verifyRefreshJwt(token);

    const account = await Account.findByPk(decoded.id);

    if (!account) {
      return res.jsonUnauthorized(null, "Invalid Token");
    }
    if (decoded.version !== account.jwtVersion) {
      return res.jsonUnauthorized(null, "Invalid Token");
    }

    const meta = {
      token: generateJwt({ id: account.id }),
    };

    return res.jsonOK(null, null, meta);
  } catch (error) {
    return res.jsonUnauthorized(null, "Invalid Token");
  }
});

module.exports = router;
