import { createLogger, format, transports } from 'winston';

const logger = createLogger({
    level: 'info', // Set the default log level
    format: format.combine(
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        format.printf(({ level, message, timestamp }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new transports.Console(), // Log to console
        new transports.File({ filename: 'logs/app.log', level: 'info' }), // Log info level messages to a file
        new transports.File({ filename: 'logs/error.log', level: 'error' }) // Log error level messages to a file
    ],
});

export default logger;
