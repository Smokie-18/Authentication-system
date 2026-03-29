import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";



export async function register(req, res) {
    try {
        const { username, email, password } = req.body;

        const existingUser = await userModel.findOne({
            $or: [{ username }, { email }]
        });

        if (existingUser) {
            return res.status(409).json({
                message: "Username or Email already exists"
            });
        }

        const hashedPassword = crypto
            .createHash("sha256")
            .update(password)
            .digest("hex");

        const user = await userModel.create({
            username,
            email,
            password: hashedPassword
        });

        // refresh token
        const refreshToken = jwt.sign(
            { id: user._id },
            config.JWT_SECRET,
            { expiresIn: "7d" }
        );

        const refreshTokenHash = crypto
            .createHash("sha256")
            .update(refreshToken)
            .digest("hex");

        const session = await sessionModel.create({
            user: user._id,
            refreshTokenHash,
            ip: req.ip,
            userAgent: req.headers["user-agent"]
        });

        // access token
        const accessToken = jwt.sign(
            {
                id: user._id,
                sessionId: session._id
            },
            config.JWT_SECRET,
            { expiresIn: "15m" }
        );

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(201).json({
            message: "User registered successfully",
            user: {
                username: user.username,
                email: user.email
            },
            accessToken
        });

    } catch (err) {
        return res.status(500).json({
            message: "Server Error",
            error: err.message
        });
    }
}


export async function getMe(req, res) {
    try {
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) {
            return res.status(401).json({
                message: "Token not found"
            });
        }

        const decoded = jwt.verify(token, config.JWT_SECRET);

        const user = await userModel.findById(decoded.id);

        return res.status(200).json({
            message: "User fetched successfully",
            user: {
                username: user.username,
                email: user.email
            }
        });

    } catch (err) {
        if (err.name === "TokenExpiredError") {
            return res.status(401).json({
                message: "Access token expired"
            });
        }

        return res.status(401).json({
            message: "Invalid token"
        });
    }
}


export async function refreshTokenHandler(req, res) {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({
                message: "Refresh token not found"
            });
        }

        const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

        const refreshTokenHash = crypto
            .createHash("sha256")
            .update(refreshToken)
            .digest("hex");

        const session = await sessionModel.findOne({
            refreshTokenHash,
            revoked: false
        });

        if (!session) {
            return res.status(401).json({
                message: "Invalid refresh token"
            });
        }


        const accessToken = jwt.sign(
            {
                id: decoded.id,
                sessionId: session._id
            },
            config.JWT_SECRET,
            { expiresIn: "15m" }
        );

        // new refresh token (rotation)
        const newRefreshToken = jwt.sign(
            { id: decoded.id },
            config.JWT_SECRET,
            { expiresIn: "7d" }
        );

        const newRefreshTokenHash = crypto
            .createHash("sha256")
            .update(newRefreshToken)
            .digest("hex");

        session.refreshTokenHash = newRefreshTokenHash;
        await session.save();

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({
            message: "Access token refreshed",
            accessToken
        });

    } catch (err) {
        return res.status(401).json({
            message: "Invalid or expired refresh token"
        });
    }
}


export async function logout(req, res) {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(400).json({
                message: "Refresh token not found"
            });
        }

        const refreshTokenHash = crypto
            .createHash("sha256")
            .update(refreshToken)
            .digest("hex");

        const session = await sessionModel.findOne({
            refreshTokenHash,
            revoked: false
        });

        if (!session) {
            return res.status(400).json({
                message: "Invalid refresh token"
            });
        }

        session.revoked = true;
        await session.save();

        res.clearCookie("refreshToken");

        return res.status(200).json({
            message: "Logged out successfully"
        });

    } catch (err) {
        return res.status(500).json({
            message: "Server error"
        });
    }
}