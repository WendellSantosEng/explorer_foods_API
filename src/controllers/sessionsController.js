const knex = require('../database/knex');
const AppError = require('../utils/appError');
const AuthConfig = require('../configs/Auth');

const { compare } = require('bcrypt');
const { sign } = require('jsonwebtoken');

class SessionsController {
  async create(request, response) {
    const { email, password } = request.body;

    const user = await knex("users").where({ email }).first();

    if (!user) {
      console.warn(`Tentativa de login com e-mail inválido: ${email}`);
      throw new AppError("As credenciais fornecidas estão incorretas.", 401);
    }

    const passwordMatched = await compare(password, user.password);

    if (!passwordMatched) {
      console.warn(`Senha incorreta para o e-mail: ${email}`);
      throw new AppError("As credenciais fornecidas estão incorretas.", 401);
    }

    const { expiresIn, secret } = AuthConfig.jwt;
    const token = sign({}, secret, {
      subject: String(user.id),
      expiresIn,
    });

    // Retorna apenas dados essenciais do usuário
    const userResponse = {
      id: user.id,
      name: user.name,
      email: user.email
    };

    return response.status(201).json({ user: userResponse, token });
  }
}

module.exports = SessionsController;
