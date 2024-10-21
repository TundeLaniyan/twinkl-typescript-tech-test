import { NextFunction, Request, Response } from 'express';
import AppError from './appError';

/**
 * Sends detailed error response during development.
 * Includes stack trace and metadata for debugging.
 * 
 * @param {AppError} err - The error object containing the details of the error.
 * @param {Request} req - The Express request object.
 * @param {Response} res - The Express response object.
 * @returns {Response} The response object with error details.
 */
const sendErrorDev = (err: AppError, req: Request, res: Response): Response => {
    console.error('Error during development:', {
        status: err.status,
        error: err,
        message: err.message,
        stack: err.stack,
        metadata: {
            timestamp: new Date().toISOString(),
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
        },
    });

    return res.status(err.statusCode).json({
        status: err.status,
        error: err,
        message: err.message,
        stack: err.stack,
        metadata: {
            timestamp: new Date().toISOString(),
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
        },
    });
};

/**
 * Sends error response during production.
 * Does not expose sensitive error details such as stack traces.
 * 
 * @param {AppError} err - The error object containing the details of the error.
 * @param {Request} req - The Express request object.
 * @param {Response} res - The Express response object.
 * @returns {Response} The response object with sanitized error details.
 */
const sendErrorProd = (err: AppError, req: Request, res: Response): Response => {
    // Log the error for internal purposes (production logs should be detailed)
    console.error('Error in production:', {
        message: err.message,
        status: err.status,
        metadata: {
            timestamp: new Date().toISOString(),
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
        },
    });

    // Send a simplified response to the client without exposing stack traces
    return res.status(err.statusCode).json({
        status: err.status,
        message: err.isOperational ? err.message : 'Something went wrong!',
        metadata: {
            timestamp: new Date().toISOString(),
        },
    });
};

/**
 * Handles Prisma-specific errors.
 * 
 * @param {AppError} err - The error object containing Prisma error details.
 * @returns {AppError} The updated error object with the appropriate status code and message.
 */
const handlePrismaError = (err: AppError): AppError => {
    switch (err.code) {
        case 'P2002':
            err.statusCode = 400;
            err.message = 'The provided data violates a unique constraint in the database. Please check your input and try again.';
            break;
        case 'P2025':
            err.statusCode = 404;
            err.message = 'The requested record could not be found. Please verify your request.';
            break;
        default:
            err.statusCode = 500;
            err.message = 'An unexpected database error occurred.';
            break;
    }

    console.error('Prisma Error:', err.message);
    return err;
};

/**
 * Handles JWT-specific errors (authentication/authorization).
 * 
 * @param {AppError} err - The error object containing JWT error details.
 * @returns {AppError} The updated error object with the appropriate status code and message.
 */
const handleJWTError = (err: AppError): AppError => {
    if (err.name === 'JsonWebTokenError') {
        err.statusCode = 401;
        err.message = 'Invalid token. Please log in again.';
    } else if (err.name === 'TokenExpiredError') {
        err.statusCode = 401;
        err.message = 'Your token has expired. Please log in again.';
    }
    return err;
};

/**
 * Global error handling middleware for Express applications.
 * Differentiates between development and production environments.
 * Handles specific error types such as Prisma and JWT errors.
 * 
 * @param {AppError} err - The error object containing error details.
 * @param {Request} req - The Express request object.
 * @param {Response} res - The Express response object.
 * @param {NextFunction} _next - The next middleware function (not used here).
 */
export default (err: AppError, req: Request, res: Response, _next: NextFunction) => {

    // Set default error properties if they are not provided
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    let error = { ...err, message: err.message };

    // Handle Prisma errors
    if (error?.name === 'PrismaClientKnownRequestError') {
        error = handlePrismaError(error);
    }

    // Handle JWT errors (authentication/authorization issues)
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
        error = handleJWTError(error);
    }

    // Send appropriate error response depending on the environment
    if (process.env.NODE_ENV === 'development') {
        sendErrorDev(error, req, res);
    } else {
        sendErrorProd(error, req, res);
    }
};
