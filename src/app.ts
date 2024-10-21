import express, { Request, Response, NextFunction } from 'express';
import { body, validationResult } from 'express-validator';
import { User } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import AppError from './utils/appError';
import asyncErrorHandler from './utils/asyncErrorHandler';
import globalErrorHandler from './utils/globalErrorHandler';
import logger from './utils/logger'; // Import the logger
import prisma from './prisma';

const app = express();

app.enable('trust proxy');


// 1) GLOBAL MIDDLEWARES
// Implement CORS
app.use(cors());

app.options('*', cors());

// Middleware: Security headers, cookie parser, and rate limiter
app.use(helmet());
app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));

// Logging each incoming request
app.use((req: Request, _res: Response, next: NextFunction) => {
    logger.info(`[${req.method}] ${req.originalUrl} - ${req.ip}`);
    next();
});

// Rate Limiting: 100 requests per 10 minutes
const limiter = rateLimit({
    max: 100,
    windowMs: 10 * 60 * 1000,
    message: 'Too many requests from this IP, please try again later.',
    handler: (req: Request, res: Response) => {
        logger.warn(`Rate limit exceeded by IP: ${req.ip}`);
        res.status(429).json({ message: 'Too many requests, try again later.' });
    }
});

app.use('/', limiter);

/**
 * Helper function to sign a JWT token for the user.
 * @param {string} id - The user's unique ID.
 * @returns {string} - A JWT token.
 */
const signToken = (id: string): string => {
    logger.info(`Generating JWT for user with ID: ${id}`);
    return jwt.sign({ id }, process.env.JWT_SECRET as string, {
        expiresIn: process.env.JWT_EXPIRES_IN || '90d',
    });
};

/**
 * Helper function to send the JWT token in an HTTP-only cookie and the user's details in the response.
 * @param {Partial<User>} user - The user object (without the password).
 * @param {number} statusCode - The HTTP status code to return.
 * @param {Request} req - The Express request object.
 * @param {Response} res - The Express response object.
 */
const createSendToken = (user: Partial<User>, statusCode: number, req: Request, res: Response): void => {
    const token = signToken(user.id!);

    res.cookie('jwt', token, {
        expires: new Date(
            Date.now() + Number(process.env.JWT_COOKIE_EXPIRES_IN || 90) * 24 * 60 * 60 * 1000
        ),
        httpOnly: true,
        secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
        sameSite: 'lax',
    });

    logger.info(`User ${user.email} signed up and received a token.`);

    user.password = undefined;

    res.status(statusCode).json({
        status: 'success',
        token,
        data: {
            user,
        },
    });
};

/**
 * Middleware to protect routes and ensure only authenticated users can access them.
 * @param {Request} req - The Express request object.
 * @param {Response} res - The Express response object.
 * @param {NextFunction} next - The next middleware function in the stack.
 */
const protect = asyncErrorHandler(async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    let token: string | undefined = req?.cookies?.jwt;

    if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        logger.warn('Unauthorized access attempt without a token.');
        return next(new AppError('You are not logged in! Please log in to get access.', 401));
    }

    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { id: string };
    } catch (error) {
        logger.error('Invalid token used.');
        return next(new AppError('Invalid token. Please log in again.', 401));
    }

    const currentUser = await prisma.user.findUnique({
        where: { id: decoded.id },
    });

    if (!currentUser) {
        logger.warn(`Token used by non-existent user with ID: ${decoded.id}`);
        return next(new AppError('The user belonging to this token no longer exists.', 401));
    }

    logger.info(`User with ID: ${decoded.id} authenticated successfully.`);
    req.user = currentUser;
    next();
});

/**
 * Array of validation rules for password.
 */
const passwordValidationRules = [
    body('password')
        .isLength({ min: 8, max: 64 })
        .withMessage('Password must be between 8 and 64 characters'),
    body('password')
        .matches(/\d/)
        .withMessage('Password must contain at least one digit'),
    body('password')
        .matches(/[a-z]/)
        .withMessage('Password must contain at least one lowercase letter'),
    body('password')
        .matches(/[A-Z]/)
        .withMessage('Password must contain at least one uppercase letter'),
];

/**
 * POST /signup
 * Endpoint to register a new user.
 * @route POST /signup
 * @access Public
 */
app.post(
    '/signup',
    [
        body('fullName').notEmpty().withMessage('Full name is required'),
        body('email').isEmail().withMessage('Please provide a valid email'),
        body('userType')
            .isIn(['student', 'teacher', 'parent', 'private tutor'])
            .withMessage('User type must be one of: student, teacher, parent, private tutor'),
        ...passwordValidationRules,
    ],
    asyncErrorHandler(async (req: Request, res: Response, next: NextFunction) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            logger.warn('Validation failed during user signup.');
            return next(new AppError('Validation failed. Please correct the errors.', 400));
        }

        const { fullName, email, password, userType } = req.body;

        const hashedPassword = await bcrypt.hash(password, 12);
        logger.info(`User ${email} is signing up with hashed password.`);

        try {
            const newUser = await prisma.user.create({
                data: {
                    fullName,
                    email,
                    password: hashedPassword,
                    userType,
                },
            });

            logger.info(`New user created: ${email}`);

            createSendToken(newUser, 201, req, res);
        } catch (error: any) {
            if (error.code === 'P2002') {
                logger.warn(`Signup failed for email ${email} - Email already exists.`);
                return next(new AppError('Email already exists. Please use another email.', 400, error.code));
            }

            logger.error('Internal server error during user signup.');
            return next(new AppError('Internal server error', 500));
        }
    })
);

/**
 * GET /me
 * Endpoint to get the authenticated user's information.
 * @route GET /me
 * @access Protected
 */
app.get('/me', protect, (req: Request, res: Response) => {
    logger.info(`User ${req.user?.email} accessed their profile.`);
    res.status(200).json({
        status: 'success',
        data: {
            user: req.user,
        },
    });
});

/**
 * GET /protected-route
 * Example of a protected route that requires authentication.
 * @route GET /protected-route
 * @access Protected
 */
app.get('/protected-route', protect, (req: Request, res: Response) => {
    logger.info(`User ${req.user?.email} accessed a protected route.`);
    res.status(200).json({
        status: 'success',
        message: 'You have access to this protected route.',
        data: {
            user: req.user,
        },
    });
});


/**
 * GET /user/:id
 * Route to get a user by their ID
 * @route GET /user/:id
 * @param {string} id - The ID of the user to retrieve
 * @access Public or Protected (depending on your setup)
 */
app.get(
    '/user/:id',
    asyncErrorHandler(async (req: Request, res: Response, next: NextFunction) => {
        const { id } = req.params;

        // Fetch the user by ID using Prisma
        const user = await prisma.user.findUnique({
            where: {
                id: String(id), // Convert ID to string if it's stored as a string
            },
        });

        // If user is not found, throw a custom AppError
        if (!user) {
            return next(new AppError(`User not found with ID: ${id}`, 404));
        }

        // If user is found, send the user data in response
        res.status(200).json({
            status: 'success',
            data: {
                user,
            },
        });
    })
);

// Log outgoing responses
app.use((req: Request, res: Response, next: NextFunction) => {
    res.on('finish', () => {
        logger.info(`[${req.method}] ${req.originalUrl} - Response: ${res.statusCode}`);
    });
    next();
});

// Use the global error handler
app.use(globalErrorHandler);

export default app;
