class AppError extends Error {
    statusCode: number;
    status: string;
    isOperational: boolean;
    code?: string;
    name: string;

    /**
     * Custom AppError class to handle operational errors.
     * 
     * @param {string} message - The error message.
     * @param {number} statusCode - The HTTP status code.
     * @param {string} [code] - Optional error code for specific errors (e.g., Prisma or other services).
     */
    constructor(message: string, statusCode: number, code?: string) {
        super(message);
        this.name = this.constructor.name;
        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;
        this.code = code;

        // Capture stack trace, excluding the constructor call from it
        Error.captureStackTrace(this, this.constructor);
    }
}

export default AppError;
