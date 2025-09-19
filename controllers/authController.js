import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const prisma = new PrismaClient();

export const register = async (req, res) => {
  try {
    const { nombre, correo, password } = req.body;

    // Verificar si ya existe
    const userExists = await prisma.usuario.findUnique({ where: { correo } });
    if (userExists) {
      return res.status(400).json({ error: "El correo ya está registrado" });
    }

    // Encriptar password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear usuario
    await prisma.usuario.create({
      data: { nombre, correo, password: hashedPassword }
    });

    res.json({ message: "Usuario registrado correctamente" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const login = async (req, res) => {
  try {
    const { correo, password } = req.body;

    const usuario = await prisma.usuario.findUnique({ where: { correo } });
    if (!usuario) return res.status(400).json({ error: "Usuario no encontrado" });

    const validPassword = await bcrypt.compare(password, usuario.password);
    if (!validPassword)
      return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: usuario.id, correo: usuario.correo },
      process.env.JWT_SECRET || "secreto123",
      { expiresIn: "1h" }
    );

    res.json({ message: "Login exitoso", token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};